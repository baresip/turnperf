/**
 * @file allocation.c TURN Allocations
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <sys/time.h>
#include <re.h>
#include "turnperf.h"


enum {
	TURN_LAYER = 0,
	DTLS_LAYER = -100,
};

enum {
	PING_INTERVAL = 5000,
	REDIRC_MAX = 16,
};


struct allocation {
	struct le le;
	struct allocator *allocator;  /* pointer to container */
	struct udp_sock *us;
	struct turnc *turnc;
	struct timeval sent;
	int proto;
	bool secure;
	struct sa srv;
	const char *user;
	const char *pass;
	struct sa relay;
	struct sa peer;
	struct tcp_conn *tc;
	struct tls_conn *tlsc;
	struct tls *tls;
	struct dtls_sock *dtls_sock;
	struct mbuf *mb;              /* TCP re-assembly buffer */
	struct sender *sender;
	struct receiver recv;
	struct udp_sock *us_tx;
	struct sa laddr_tx;
	struct tmr tmr_ping;
	double atime;                 /* ms */
	unsigned ix;
	bool ok;
	bool turn_ind;
	unsigned redirc;
	int err;
	allocation_h *alloch;
	void *arg;
};


static int start(struct allocation *alloc);


/*
 * In data communications only the Metric definition of a kilobyte
 * (1000 bytes per kilobyte) is correct
 */
static int print_bitrate(struct re_printf *pf, double *val)
{
	if (*val >= 1000000)
		return re_hprintf(pf, "%.2f Mbit/s", *val/1000/1000);
	else if (*val >= 1000)
		return re_hprintf(pf, "%.2f Kbit/s", *val/1000);
	else
		return re_hprintf(pf, "%.2f bit/s", *val);
}


static void tmr_ping_handler(void *arg)
{
	struct allocation *alloc = arg;
	struct mbuf *mb;

	tmr_start(&alloc->tmr_ping, PING_INTERVAL, tmr_ping_handler, alloc);

	mb = mbuf_alloc(256);
	if (!mb)
		return;

	mb->pos = 48;
	mbuf_write_str(mb, "PING");
	mb->pos = 48;

	turnc_send(alloc->turnc, &alloc->peer, mb);

	mem_deref(mb);
}


static void perm_handler(void *arg)
{
	struct allocation *alloc = arg;

	re_printf("%s to %J added.\n",
		  alloc->turn_ind ? "Permission" : "Channel",
		  &alloc->peer);

	alloc->alloch(0, 0, "OK", &alloc->srv, &alloc->relay, alloc->arg);
}


static int set_peer(struct allocation *alloc, const struct sa *peer)
{
	alloc->peer = *peer;

	tmr_start(&alloc->tmr_ping, PING_INTERVAL, tmr_ping_handler, alloc);

	if (alloc->turn_ind)
		return turnc_add_perm(alloc->turnc, peer, perm_handler, alloc);
	else
		return turnc_add_chan(alloc->turnc, peer, perm_handler, alloc);
}


static bool is_connection_oriented(const struct allocation *alloc)
{
	return alloc->proto == IPPROTO_TCP ||
		(alloc->proto == IPPROTO_UDP && alloc->secure);
}


/* NOTE: this code must be fast, and not do any calculations */
static void turnc_handler(int err, uint16_t scode, const char *reason,
			  const struct sa *relay_addr,
			  const struct sa *mapped_addr,
			  const struct stun_msg *msg,
			  void *arg)
{
	struct allocation *alloc = arg;
	struct allocator *allocator = alloc->allocator;
	struct timeval now;
	struct sa peer;

	if (err) {
		(void)re_fprintf(stderr, "[%u] turn error: %m\n",
				 alloc->ix, err);
		alloc->err = err;
		goto term;
	}

	if (scode) {

		if (scode == 300 && is_connection_oriented(alloc) &&
		    alloc->redirc++ < REDIRC_MAX) {

			const struct stun_attr *alt;

			alt = stun_msg_attr(msg, STUN_ATTR_ALT_SERVER);
			if (!alt)
				goto term;

			re_printf("[%u] redirecting to new server %J\n",
				  alloc->ix, &alt->v.alt_server);

			alloc->srv = alt->v.alt_server;

			alloc->turnc = mem_deref(alloc->turnc);
			alloc->tlsc  = mem_deref(alloc->tlsc);
			alloc->tc    = mem_deref(alloc->tc);
			alloc->dtls_sock = mem_deref(alloc->dtls_sock);
			alloc->us    = mem_deref(alloc->us);

			err = start(alloc);
			if (err)
				goto term;

			return;
		}

		(void)re_fprintf(stderr, "[%u] turn error: %u %s\n",
				 alloc->ix, scode, reason);
		alloc->err = EPROTO;
		goto term;
	}

	if (sa_af(relay_addr) != sa_af(mapped_addr)) {
		re_fprintf(stderr, "allocation: address-family mismatch"
			   " (mapped=%J, relay=%J)\n",
			   mapped_addr, relay_addr);
		err = EAFNOSUPPORT;
		goto term;
	}

	alloc->ok = true;
	alloc->relay = *relay_addr;

	(void)gettimeofday(&now, NULL);

	alloc->atime  = (double)(now.tv_sec - alloc->sent.tv_sec) * 1000;
	alloc->atime += (double)(now.tv_usec - alloc->sent.tv_usec) / 1000;

	/* save information from the TURN server */
	if (!allocator->server_info) {

		struct stun_attr *attr;

		allocator->server_auth =
			(NULL != stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY));

		attr = stun_msg_attr(msg, STUN_ATTR_SOFTWARE);
		if (attr) {
			str_ncpy(allocator->server_software, attr->v.software,
				 sizeof(allocator->server_software));
		}

		allocator->mapped_addr = *mapped_addr;

		allocator->server_info = true;

		attr = stun_msg_attr(msg, STUN_ATTR_LIFETIME);
		if (attr) {
			allocator->lifetime = attr->v.lifetime;
		}
	}

	peer = *mapped_addr;
	sa_set_port(&peer, sa_port(&alloc->laddr_tx));

	err = set_peer(alloc, &peer);
	if (err)
		goto term;

	return;

 term:
	alloc->alloch(err, scode, reason, NULL, NULL, alloc->arg);
}


/* Incoming data from TURN-server */
static void data_handler(struct allocation *alloc, const struct sa *src,
			 struct mbuf *mb)
{
	int err;

	if (!alloc->ok) {
		re_fprintf(stderr, "allocation not ready"
			   " -- ignore %zu bytes from %J\n",
			   mbuf_get_left(mb), src);
		return;
	}

	if (!sa_cmp(src, &alloc->peer, SA_ALL)) {

		re_printf("updating peer address:  %J  -->  %J\n",
			  &alloc->peer, src);

		alloc->peer = *src;

		if (!alloc->turn_ind)
			turnc_add_chan(alloc->turnc, src, NULL, NULL);

		tmr_start(&alloc->tmr_ping, PING_INTERVAL,
			  tmr_ping_handler, alloc);
	}

	err = receiver_recv(&alloc->recv, src, mb);
	if (err) {
		re_fprintf(stderr, "corrupt packet coming from %J (%m)\n",
			   src, err);
	}
}


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct allocation *alloc = arg;

	data_handler(alloc, src, mb);
}


static void tcp_recv_handler(struct mbuf *mb_pkt, void *arg)
{
	struct allocation *alloc = arg;
	int err = 0;

	/* re-assembly of fragments */
	if (alloc->mb) {
		size_t pos;

		pos = alloc->mb->pos;

		alloc->mb->pos = alloc->mb->end;

		err = mbuf_write_mem(alloc->mb,
				     mbuf_buf(mb_pkt), mbuf_get_left(mb_pkt));
		if (err)
			goto out;

		alloc->mb->pos = pos;
	}
	else {
		alloc->mb = mem_ref(mb_pkt);
	}

	for (;;) {

		size_t len, pos, end;
		struct sa src;
		uint16_t typ;

		if (mbuf_get_left(alloc->mb) < 4)
			break;

		typ = ntohs(mbuf_read_u16(alloc->mb));
		len = ntohs(mbuf_read_u16(alloc->mb));

		if (typ < 0x4000)
			len += STUN_HEADER_SIZE;
		else if (typ < 0x8000)
			len += 4;
		else {
			err = EBADMSG;
			goto out;
		}

		alloc->mb->pos -= 4;

		if (mbuf_get_left(alloc->mb) < len)
			break;

		pos = alloc->mb->pos;
		end = alloc->mb->end;

		alloc->mb->end = pos + len;

		/* forward packet to TURN client */
		err = turnc_recv(alloc->turnc, &src, alloc->mb);
		if (err)
			goto out;

		if (mbuf_get_left(alloc->mb)) {
			data_handler(alloc, &src, alloc->mb);
		}

		/* 4 byte alignment */
		while (len & 0x03)
			++len;

		alloc->mb->pos = pos + len;
		alloc->mb->end = end;

		if (alloc->mb->pos >= alloc->mb->end) {
			alloc->mb = mem_deref(alloc->mb);
			break;
		}
	}

 out:
	if (err) {
		alloc->alloch(err, 0, NULL, NULL, NULL, alloc->arg);
	}
}


static void tcp_estab_handler(void *arg)
{
	struct allocation *alloc = arg;
	int err;

	alloc->mb = mem_deref(alloc->mb);

	err = turnc_alloc(&alloc->turnc, NULL, IPPROTO_TCP, alloc->tc, 0,
			  &alloc->srv, alloc->user, alloc->pass,
			  TURN_DEFAULT_LIFETIME, turnc_handler, alloc);
	if (err)
		alloc->alloch(err, 0, NULL, NULL, NULL, alloc->arg);
}


static void tcp_close_handler(int err, void *arg)
{
	struct allocation *alloc = arg;

	alloc->alloch(err ? err : ECONNRESET, 0, NULL, NULL, NULL, alloc->arg);
}


static void dtls_estab_handler(void *arg)
{
	struct allocation *alloc = arg;
	int err;

	re_printf("allocation: DTLS established\n");

	err = turnc_alloc(&alloc->turnc, NULL, STUN_TRANSP_DTLS,
			  alloc->tlsc, TURN_LAYER,
			  &alloc->srv, alloc->user, alloc->pass,
			  TURN_DEFAULT_LIFETIME, turnc_handler, alloc);
	if (err) {
		re_fprintf(stderr, "allocation: failed to"
			   " create TURN client"
			   " (%m)\n", err);
		goto out;
	}

 out:
	if (err)
		alloc->alloch(err, 0, NULL, NULL, NULL, alloc->arg);
}


static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct allocation *alloc = arg;
	struct sa src;
	int err;

	/* forward packet to TURN-client */
	err = turnc_recv(alloc->turnc, &src, mb);
	if (err) {
		alloc->alloch(err, 0, NULL, NULL, NULL, alloc->arg);
		return;
	}

	/* available application data? */
	if (mbuf_get_left(mb)) {
		data_handler(alloc, &src, mb);
	}
}


static void dtls_close_handler(int err, void *arg)
{
	struct allocation *alloc = arg;

	re_fprintf(stderr, "dtls: close (%m)\n", err);

	alloc->alloch(err ? err : ECONNRESET, 0, NULL, NULL, NULL, alloc->arg);
}


static int start(struct allocation *alloc)
{
	struct sa laddr;
	int err = 0;

	if (!alloc)
		return EINVAL;

	sa_init(&laddr, sa_af(&alloc->srv));

	switch (alloc->proto) {

	case IPPROTO_UDP:
		err = udp_listen(&alloc->us, &laddr, udp_recv, alloc);
		if (err) {
			re_fprintf(stderr, "allocation: failed to"
				   " create UDP socket"
				   " (%m)\n", err);
			goto out;
		}

		udp_sockbuf_set(alloc->us, 524288);

		if (alloc->secure) {

			/* note: re-using UDP socket for DTLS-traffic */
			err = dtls_listen(&alloc->dtls_sock, NULL, alloc->us,
					  2, DTLS_LAYER, NULL, NULL);
			if (err) {
				re_fprintf(stderr, "dtls_listen error: %m\n",
					   err);
				goto out;
			}

			err = dtls_connect(&alloc->tlsc, alloc->tls,
					   alloc->dtls_sock, &alloc->srv,
					   dtls_estab_handler,
					   dtls_recv_handler,
					   dtls_close_handler, alloc);
			if (err) {
				re_fprintf(stderr, "dtls_connect error: %m\n",
					   err);
				goto out;
			}
		}
		else {
			err = turnc_alloc(&alloc->turnc, NULL, IPPROTO_UDP,
					  alloc->us, TURN_LAYER, &alloc->srv,
					  alloc->user, alloc->pass,
					  TURN_DEFAULT_LIFETIME,
					  turnc_handler, alloc);
			if (err) {
				re_fprintf(stderr, "allocation: failed to"
					   " create TURN client"
					   " (%m)\n", err);
				goto out;
			}
		}
		break;

	case IPPROTO_TCP:
		err = tcp_connect(&alloc->tc, &alloc->srv, tcp_estab_handler,
				  tcp_recv_handler, tcp_close_handler, alloc);
		if (err)
			break;

		if (alloc->secure) {
			err = tls_start_tcp(&alloc->tlsc, alloc->tls,
					    alloc->tc, 0);
			if (err)
				break;
		}
		break;

	default:
		err = EPROTONOSUPPORT;
		goto out;
	}

 out:
	return err;
}


static void destructor(void *arg)
{
	struct allocation *alloc = arg;

	list_unlink(&alloc->le);

	tmr_cancel(&alloc->tmr_ping);

	mem_deref(alloc->sender);

	/* note: order matters */
 	mem_deref(alloc->turnc);     /* close TURN client, to de-allocate */
	mem_deref(alloc->dtls_sock);
	mem_deref(alloc->us);        /* must be closed after TURN client */

	mem_deref(alloc->tlsc);
	mem_deref(alloc->tc);
	mem_deref(alloc->mb);
	mem_deref(alloc->us_tx);

	mem_deref(alloc->tls);
}


int allocation_create(struct allocator *allocator, unsigned ix, int proto,
		      const struct sa *srv,
		      const char *username, const char *password,
		      struct tls *tls, bool turn_ind,
		      allocation_h *alloch, void *arg)
{
	struct allocation *alloc;
	struct sa laddr;
	int err;

	if (!allocator || !proto || !srv)
		return EINVAL;

	sa_init(&laddr, sa_af(srv));

	alloc = mem_zalloc(sizeof(*alloc), destructor);
	if (!alloc)
		return ENOMEM;

	list_append(&allocator->allocl, &alloc->le, alloc);

	(void)gettimeofday(&alloc->sent, NULL);

	alloc->atime     = -1;
	alloc->ix        = ix;
	alloc->allocator = allocator;
	alloc->proto     = proto;
	alloc->secure    = tls != NULL;
	alloc->srv       = *srv;
	alloc->user      = username;
	alloc->pass      = password;
	alloc->turn_ind  = turn_ind;
	alloc->alloch    = alloch;
	alloc->arg       = arg;
	alloc->tls       = mem_ref(tls);

	receiver_init(&alloc->recv, allocator->session_cookie, alloc->ix);

	err = udp_listen(&alloc->us_tx, &laddr, NULL, NULL);
	if (err) {
		re_fprintf(stderr, "allocation: failed to create UDP tx socket"
			   " (%m)\n", err);
		goto out;
	}

	udp_local_get(alloc->us_tx, &alloc->laddr_tx);

	err = start(alloc);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(alloc);

	return err;
}


int allocation_tx(struct allocation *alloc, struct mbuf *mb)
{
	int err;

	if (!alloc || mbuf_get_left(mb) < 4)
		return EINVAL;

	err = udp_send(alloc->us_tx, &alloc->relay, mb);

	return err;
}


static void tmr_ui_handler(void *arg)
{
	struct allocator *allocator = arg;
	time_t duration = time(NULL) - allocator->traf_start_time;

	static const char uiv[] = ".,-'-,.";
	static size_t uic = 0;

	tmr_start(&allocator->tmr_ui, 50, tmr_ui_handler, allocator);

	re_fprintf(stderr, "\r%c %H", uiv[ uic++ % (sizeof(uiv)-1) ],
		   fmt_human_time, &duration);
}


static void check_all_senders(struct allocator *allocator)
{
	uint64_t now = tmr_jiffies();
	struct le *le;

	for (le = allocator->allocl.head; le; le = le->next) {
		struct allocation *alloc = le->data;

		sender_tick(alloc->sender, now);
	}
}


static void tmr_pace_handler(void *arg)
{
	struct allocator *allocator = arg;

	check_all_senders(allocator);

	tmr_start(&allocator->tmr_pace, PACING_INTERVAL_MS,
		  tmr_pace_handler, allocator);
}


int allocator_start_senders(struct allocator *allocator, unsigned bitrate,
			    size_t psize)
{
	struct le *le;
	double tbps = allocator->num_allocations * bitrate;
	unsigned ptime;
	int err = 0;

	ptime = calculate_ptime(bitrate, psize);

	re_printf("starting traffic generators:"
		  " psize=%zu, ptime=%u (total target bitrate is %H)\n",
		  psize, ptime, print_bitrate, &tbps);

	tmr_start(&allocator->tmr_ui, 1, tmr_ui_handler, allocator);

	for (le = allocator->allocl.head; le; le = le->next) {
		struct allocation *alloc = le->data;

		if (alloc->sender) {
			re_fprintf(stderr, "sender already started\n");
			return EALREADY;
		}

		err = sender_alloc(&alloc->sender, alloc,
				   allocator->session_cookie,
				   alloc->ix, bitrate, ptime, psize);
		if (err)
			return err;

		err = sender_start(alloc->sender);
		if (err) {
			re_fprintf(stderr, "could not start sender (%m)", err);
			return err;
		}
	}

	/* start sending timer/thread */
	tmr_start(&allocator->tmr_pace, PACING_INTERVAL_MS,
		  tmr_pace_handler, allocator);

	return 0;
}


void allocator_stop_senders(struct allocator *allocator)
{
	struct le *le;

	if (!allocator)
		return;

	tmr_cancel(&allocator->tmr_ui);
	tmr_cancel(&allocator->tmr_pace);

	for (le = allocator->allocl.head; le; le = le->next) {
		struct allocation *alloc = le->data;

		sender_stop(alloc->sender);
	}

}


void allocator_print_statistics(const struct allocator *allocator)
{
	struct le *le;
	double amin = 99999999, amax = 0, asum = 0, aavg;
	int ix_min = -1, ix_max = -1;

	/* show allocation summary */
	if (!allocator || !allocator->num_sent)
		return;

	for (le = allocator->allocl.head; le; le = le->next) {

		struct allocation *alloc = le->data;

		if (alloc->atime < amin) {
			amin = alloc->atime;
			ix_min = alloc->ix;
		}
		if (alloc->atime > amax) {
			amax = alloc->atime;
			ix_max = alloc->ix;
		}

		asum += alloc->atime;
	}

	aavg = asum / allocator->num_sent;

	re_printf("\nAllocation time statistics:\n");
	re_printf("min: %.1f ms (allocation #%d)\n", amin, ix_min);
	re_printf("avg: %.1f ms\n", aavg);
	re_printf("max: %.1f ms (allocation #%d)\n", amax, ix_max);
	re_printf("\n");
}


void allocator_reset(struct allocator *allocator)
{
	if (!allocator)
		return;

	tmr_cancel(&allocator->tmr);
	tmr_cancel(&allocator->tmr_ui);
	tmr_cancel(&allocator->tmr_pace);
	list_flush(&allocator->allocl);
}


void allocator_show_summary(const struct allocator *allocator)
{
	if (!allocator)
		return;

	if (allocator->tock > allocator->tick) {
		double duration;

		duration = (double)(allocator->tock - allocator->tick);

		re_printf("timing summary: %u allocations created in %.1f ms"
			  " (%.1f allocations per second)\n",
			  allocator->num_sent,
			  duration,
			  1.0 * allocator->num_sent / (duration / 1000.0));
	}
	else {
		re_fprintf(stderr, "duration was too short..\n");
	}

	if (allocator->num_sent)
		allocator_print_statistics(allocator);
}


void allocator_traffic_summary(struct allocator *allocator)
{
	size_t total_sent = 0;
	size_t total_recv = 0;
	double total_send_bitrate = 0;
	double total_recv_bitrate = 0;
	ssize_t lost;
	struct le *le;

	for (le = allocator->allocl.head; le; le = le->next) {

		struct allocation *alloc = le->data;

		if (!alloc->ok || !alloc->sender)
			continue;

		total_sent    += sender_get_packets(alloc->sender);
		total_recv    += alloc->recv.total_packets;

		total_send_bitrate += sender_get_bitrate(alloc->sender);
		total_recv_bitrate += receiver_get_bitrate(&alloc->recv);
	}

	lost = total_sent - total_recv;

	re_printf("traffic summary:\n");
	re_printf("total send bitrate:   %H\n",
		  print_bitrate, &total_send_bitrate);
	re_printf("total recv bitrate:   %H\n",
		  print_bitrate, &total_recv_bitrate);
	re_printf("total sent:           %zu packets\n", total_sent);
	re_printf("total received:       %zu packets\n", total_recv);
	re_printf("lost packets:         %zu packets (%.2f%% loss)\n",
		  lost, 100.0 * lost / total_sent);
	re_printf("\n");
}
