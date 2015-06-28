/**
 * @file receiver.c TURN client receiver side
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "turnperf.h"


void receiver_init(struct receiver *recv,
		   uint32_t exp_cookie, uint32_t exp_allocid)
{
	if (!recv)
		return;

	memset(recv, 0, sizeof(*recv));

	recv->cookie = exp_cookie;
	recv->allocid = exp_allocid;
}


int receiver_recv(struct receiver *recv,
		  const struct sa *src, struct mbuf *mb)
{
	struct hdr hdr;
	uint64_t now = tmr_jiffies();
	size_t start, sz;
	int err;

	if (!recv || !mb)
		return EINVAL;

	if (!recv->ts_start)
		recv->ts_start = now;
	recv->ts_last = now;

	start = mb->pos;
	sz = mbuf_get_left(mb);

	/* decode packet */
	err = protocol_decode(&hdr, mb);
	if (err) {
		if (err == EBADMSG) {
			re_fprintf(stderr, "[%u] ignore a non-Turnperf packet"
				   " from %J (%zu bytes)\n",
				   recv->allocid, src, sz);
			hexdump(stderr, mb->buf + start, sz);
			return 0;
		}

		re_fprintf(stderr, "receiver: protocol decode"
			   " error [%zu bytes from %J] (%m)\n", sz, src, err);
		re_fprintf(stderr, "          %w\n", mb->buf + start, sz);
		return err;
	}

	/* verify packet */
	if (hdr.session_cookie != recv->cookie) {
		re_fprintf(stderr, "invalid cookie received"
			   " from %J [exp=%x, actual=%x] (%zu bytes)\n",
			   src, recv->cookie, hdr.session_cookie, sz);
		protocol_packet_dump(&hdr);
		return EPROTO;
	}
	if (hdr.alloc_id != recv->allocid) {
		re_fprintf(stderr, "invalid allocation-ID received"
			   " from %J [exp=%u, actual=%u] (%zu bytes)\n",
			   src, hdr.alloc_id, recv->allocid, sz);
		protocol_packet_dump(&hdr);
		return EPROTO;
	}

	if (recv->last_seq) {
		if (hdr.seq <= recv->last_seq) {
			re_fprintf(stderr, "receiver[%u]: late or "
				   " out-of-order packet from %J"
				   " (last_seq=%u, seq=%u)\n",
				   recv->allocid, src,
				   recv->last_seq, hdr.seq);
		}
	}

#if 0
	protocol_packet_dump(&hdr);
#endif

	recv->total_bytes   += sz;
	recv->total_packets += 1;

	recv->last_seq = hdr.seq;

	return 0;
}


void receiver_print(const struct receiver *recv)
{
	double duration;

	if (!recv || !recv->ts_start)
		return;

	duration = recv->ts_last - recv->ts_start;

	re_printf("receiver: %zu bytes received in %.3f seconds"
		  " (average bitrate was %.1f bit/s)\n",
		  recv->total_bytes, duration / 1000.0,
		  recv->total_bytes / (duration / 1000.0 / 8) );
}


double receiver_get_bitrate(const struct receiver *recv)
{
	double duration;

	duration = recv->ts_last - recv->ts_start;

	return recv->total_bytes / (duration / 1000.0 / 8);
}
