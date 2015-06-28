/**
 * @file main.c Main application code
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>
#include <re.h>
#include "turnperf.h"


static struct {
	const char *user, *pass;
	struct sa srv;
	int proto;
	int err;
	unsigned bitrate;
	size_t psize;
	struct tmr tmr_grace;
	struct tls *tls;
	struct stun_dns *dns;
	bool turn_ind;
} turnperf = {
	.user    = "demo",
	.pass    = "secret",
	.proto   = IPPROTO_UDP,
	.bitrate = 64000,
	.psize   = 160
};


static struct allocator gallocator = {
	.num_allocations = 100,
};


static void terminate(int err)
{
	turnperf.err = err;
	re_cancel();
}


static void allocation_handler(int err, uint16_t scode, const char *reason,
			       const struct sa *srv,  const struct sa *relay,
			       void *arg)
{
	struct allocator *allocator = arg;
	(void)srv;
	(void)relay;

	if (err || scode) {
		re_fprintf(stderr, "allocation failed (%m %u %s)\n",
			   err, scode, reason);
		terminate(err ? err : EPROTO);
		return;
	}

	allocator->num_received++;

	re_fprintf(stderr, "\r[ allocations: %u ]", allocator->num_received);

	if (allocator->num_received >= allocator->num_allocations) {

		re_printf("all allocations are ok.\n");

		if (allocator->server_info) {
			re_printf("\nserver:  %s, authentication=%s\n\n",
				  allocator->server_software,
				  allocator->server_auth ? "yes" : "no");
			re_printf("public address: %j\n",
				  &allocator->mapped_addr);
		}

		allocator->tock = tmr_jiffies();

		allocator_show_summary(allocator);

		err = allocator_start_senders(allocator, turnperf.bitrate,
					      turnperf.psize);
		if (err) {
			re_fprintf(stderr, "failed to start senders (%m)\n",
				   err);
			terminate(err);
		}
#if 0
		tmr_debug();
#endif

		allocator->traf_start_time = time(NULL);
	}
}


static void tmr_handler(void *arg)
{
	struct allocator *allocator = arg;
	unsigned i;
	int err;

	if (allocator->num_sent >= allocator->num_allocations) {
		return;
	}

	i = allocator->num_sent;

	err = allocation_create(allocator, i, turnperf.proto, &turnperf.srv,
				turnperf.user, turnperf.pass,
				turnperf.tls, turnperf.turn_ind,
				allocation_handler, allocator);
	if (err) {
		re_fprintf(stderr, "creating allocation number %u failed"
			   " (%m)\n", i, err);
		goto out;
	}

	allocator->num_sent++;

	tmr_start(&allocator->tmr, rand_u16()&3, tmr_handler, allocator);

 out:
	if (err)
		terminate(err);
}


static void allocator_start(struct allocator *allocator)
{
	if (!allocator)
		return;

	allocator->tick = tmr_jiffies();
	tmr_start(&allocator->tmr, 0, tmr_handler, allocator);
}


static void tmr_grace_handler(void *arg)
{
	(void)arg;
	re_cancel();
}


static void signal_handler(int signum)
{
	static bool term = false;
	(void)signum;

	if (term) {
		re_fprintf(stderr, "forced exit\n");
		exit(2);
	}

	re_fprintf(stderr, "cancelled\n");
	term = true;

	if (gallocator.num_received > 0) {
		time_t duration = time(NULL) - gallocator.traf_start_time;

		allocator_stop_senders(&gallocator);

		re_printf("total duration: %H\n", fmt_human_time, &duration);

		re_printf("wait 1 second for traffic to settle..\n");
		tmr_start(&turnperf.tmr_grace, 1000, tmr_grace_handler, 0);
	}
	else {
		re_cancel();
	}
}


static void dns_handler(int err, const struct sa *srv, void *arg)
{
	(void)arg;

	if (err)
		goto out;

	re_printf("resolved TURN-server: %J\n", srv);

	turnperf.srv = *srv;

	/* create a bunch of allocations, with timing */
	allocator_start(&gallocator);

 out:
	if (err)
		terminate(err);
}


static void usage(void)
{
	re_fprintf(stderr,
			 "turnperf -ihtT -u <user> -p <pass> "
			 "-P <port> turn-server\n");
	re_fprintf(stderr, "\t-h            Show summary of options\n");
	re_fprintf(stderr, "\t-m <method>   Use async polling method\n");
	re_fprintf(stderr, "\n");
	re_fprintf(stderr, "TURN server options:\n");
	re_fprintf(stderr, "\t-u <user>     TURN Username\n");
	re_fprintf(stderr, "\t-p <pass>     TURN Password\n");
	re_fprintf(stderr, "\t-P <port>     TURN Server port\n");
	re_fprintf(stderr, "\t-i            Use data/send indications\n");
	re_fprintf(stderr, "\n");
	re_fprintf(stderr, "Traffic options:\n");
	re_fprintf(stderr, "\t-a <num>      Number of TURN allocations\n");
	re_fprintf(stderr, "\t-b <bitrate>  Bitrate per allocation"
		   " (bits/s)\n");
	re_fprintf(stderr, "\t-s <bytes>    Packet size in bytes\n");
	re_fprintf(stderr, "\n");
	re_fprintf(stderr, "Transport options (default is UDP):\n");
	re_fprintf(stderr, "\t-t            Use TCP\n");
	re_fprintf(stderr, "\t-T            Use TLS\n");
	re_fprintf(stderr, "\t-D            Use DTLS\n");
}


int main(int argc, char *argv[])
{
	struct dnsc *dnsc = NULL;
	enum poll_method method = poll_method_best();
	const char *host;
	bool secure = false;
	uint64_t dport = STUN_PORT;
	uint16_t port = 0;
	int maxfds = 4096;
	int err = 0;

	for (;;) {

		const int c = getopt(argc, argv, "a:b:s:u:p:P:tTDhim:");
		if (0 > c)
			break;

		switch (c) {

		case 'a':
			gallocator.num_allocations = atoi(optarg);
			break;

		case 'b':
			turnperf.bitrate = atoi(optarg);
			break;

		case 's':
			turnperf.psize = atoi(optarg);
			break;

		case 'u':
			turnperf.user = optarg;
			break;

		case 'p':
			turnperf.pass = optarg;
			break;

		case 'i':
			turnperf.turn_ind = true;
			break;

		case 'P':
			port = atoi(optarg);
			break;

		case 't':
			turnperf.proto = IPPROTO_TCP;
			break;

		case 'T':
			turnperf.proto = IPPROTO_TCP;
			secure = true;
			break;

		case 'D':
			turnperf.proto = IPPROTO_UDP;
			secure = true;
			break;

		case 'm': {
			struct pl pollname;
			pl_set_str(&pollname, optarg);
			err = poll_method_type(&method, &pollname);
			if (err) {
				re_fprintf(stderr,
					   "could not resolve async polling"
					   " method '%r'\n", &pollname);
				return err;
			}
		}
			break;

		case '?':
			err = EINVAL;
			/*@fallthrough@*/
		case 'h':
			usage();
			return err;
		}
	}

	if (argc < 2 || argc != (optind + 1)) {
		usage();
		return -EINVAL;
	}

	host = argv[optind];

	(void)sys_coredump_set(true);

	err = libre_init();
	if (err) {
		(void)re_fprintf(stderr, "libre_init: %m\n", err);
		goto out;
	}

	switch (method) {

	case METHOD_SELECT:
		maxfds = 1024;
		break;

	default:
		maxfds = 32768;
		break;
	}

	err = fd_setsize(maxfds);
	if (err) {
		re_fprintf(stderr, "cannot set maxfds to %d: %m\n",
			   maxfds, err);
		goto out;
	}

	err = poll_method_set(method);
	if (err) {
		re_fprintf(stderr, "could not set polling method '%s' (%m)\n",
			   poll_method_name(method), err);
		goto out;
	}

	re_printf("using async polling method '%s' with maxfds=%d\n",
		  poll_method_name(method), maxfds);

	if (secure) {
		switch (turnperf.proto) {

		case IPPROTO_UDP:
			err = tls_alloc(&turnperf.tls, TLS_METHOD_DTLSV1,
					NULL, NULL);
			break;

		case IPPROTO_TCP:
			err = tls_alloc(&turnperf.tls, TLS_METHOD_SSLV23,
					NULL, NULL);
			break;
		}
		if (err)
			goto out;

		dport = STUNS_PORT;
	}

	/* A new random cookie for each session */
	gallocator.session_cookie = rand_u32();

	err = dns_init(&dnsc);
	if (err) {
		(void)re_fprintf(stderr, "dnsinit: %m\n", err);
		goto out;
	}

	re_printf("turnperf version %s\n", VERSION);
	re_printf("bitrate: %u bits/second (per allocation)\n",
		  turnperf.bitrate);
	re_printf("session cookie: 0x%08x\n", gallocator.session_cookie);
	re_printf("using TURN %s\n",
		  turnperf.turn_ind ? "DATA/SEND indications" : "Channels");

	if (0 == sa_set_str(&turnperf.srv, argv[optind],
			    port ? port : dport)) {

		re_printf("server: %J protocol=%s\n",
			  &turnperf.srv,
			  protocol_name(turnperf.proto, secure));

		/* create a bunch of allocations, with timing */
		allocator_start(&gallocator);
	}
	else {
		const char *stun_proto, *stun_usage;

		re_printf("server: %s protocol=%s\n",
			  host, protocol_name(turnperf.proto, secure));

		stun_usage = secure ? stuns_usage_relay : stun_usage_relay;

		switch (turnperf.proto) {

		case IPPROTO_UDP:
			stun_proto = stun_proto_udp;
			break;

		case IPPROTO_TCP:
			stun_proto = stun_proto_tcp;
			break;

		default:
			err = EPROTONOSUPPORT;
			goto out;
		}

		err = stun_server_discover(&turnperf.dns, dnsc,
                                           stun_usage, stun_proto,
                                           AF_INET, host, port,
                                           dns_handler, NULL);
		if (err) {
			re_fprintf(stderr, "stun discover failed (%m)\n",
				   err);
			goto out;
		}
	}

	re_main(signal_handler);

	if (turnperf.err) {
		re_fprintf(stderr, "turn performance failed (%m)\n",
			   turnperf.err);
		goto out;
	}

	allocator_traffic_summary(&gallocator);

 out:
	allocator_reset(&gallocator);
	mem_deref(dnsc);

	tmr_cancel(&turnperf.tmr_grace);
	mem_deref(turnperf.tls);
	mem_deref(turnperf.dns);

	libre_close();
	mem_debug();
	tmr_debug();

	return err;
}
