/**
 * @file receiver.c TURN client receiver side
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "turnperf.h"


void receiver_init(struct receiver *recvr,
		   uint32_t exp_cookie, uint32_t exp_allocid)
{
	if (!recvr)
		return;

	memset(recvr, 0, sizeof(*recvr));

	recvr->cookie = exp_cookie;
	recvr->allocid = exp_allocid;
}


int receiver_recv(struct receiver *recvr,
		  const struct sa *src, struct mbuf *mb)
{
	struct hdr hdr;
	uint64_t now = tmr_jiffies();
	size_t start, sz;
	int err;

	if (!recvr || !mb)
		return EINVAL;

	if (!recvr->ts_start)
		recvr->ts_start = now;
	recvr->ts_last = now;

	start = mb->pos;
	sz = mbuf_get_left(mb);

	/* decode packet */
	err = protocol_decode(&hdr, mb);
	if (err) {
		if (err == EBADMSG) {
			re_fprintf(stderr, "[%u] ignore a non-Turnperf packet"
				   " from %J (%zu bytes)\n",
				   recvr->allocid, src, sz);
			hexdump(stderr, mb->buf + start, sz);
			return 0;
		}

		re_fprintf(stderr, "receiver: protocol decode"
			   " error [%zu bytes from %J] (%m)\n", sz, src, err);
		re_fprintf(stderr, "          %w\n", mb->buf + start, sz);
		return err;
	}

	/* verify packet */
	if (hdr.session_cookie != recvr->cookie) {
		re_fprintf(stderr, "invalid cookie received"
			   " from %J [exp=%x, actual=%x] (%zu bytes)\n",
			   src, recvr->cookie, hdr.session_cookie, sz);
		protocol_packet_dump(&hdr);
		return EPROTO;
	}
	if (hdr.alloc_id != recvr->allocid) {
		re_fprintf(stderr, "invalid allocation-ID received"
			   " from %J [exp=%u, actual=%u] (%zu bytes)\n",
			   src, hdr.alloc_id, recvr->allocid, sz);
		protocol_packet_dump(&hdr);
		return EPROTO;
	}

	if (recvr->last_seq) {
		if (hdr.seq <= recvr->last_seq) {
			re_fprintf(stderr, "receiver[%u]: late or "
				   " out-of-order packet from %J"
				   " (last_seq=%u, seq=%u)\n",
				   recvr->allocid, src,
				   recvr->last_seq, hdr.seq);
		}
	}

#if 0
	protocol_packet_dump(&hdr);
#endif

	recvr->total_bytes   += sz;
	recvr->total_packets += 1;

	recvr->last_seq = hdr.seq;

	return 0;
}


void receiver_print(const struct receiver *recvr)
{
	double duration;

	if (!recvr || !recvr->ts_start)
		return;

	duration = recvr->ts_last - recvr->ts_start;

	re_printf("receiver: %zu bytes received in %.3f seconds"
		  " (average bitrate was %.1f bit/s)\n",
		  recvr->total_bytes, duration / 1000.0,
		  recvr->total_bytes / (duration / 1000.0 / 8) );
}


double receiver_get_bitrate(const struct receiver *recvr)
{
	double duration;

	duration = recvr->ts_last - recvr->ts_start;

	return recvr->total_bytes / (duration / 1000.0 / 8);
}
