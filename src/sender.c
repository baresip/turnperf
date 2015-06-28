/**
 * @file sender.c TURN client sender side
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <pthread.h>
#include <re.h>
#include "turnperf.h"


/*
 * Sender:
 *
 * - send a continuous bitstream to target X
 * - use sequence numbers
 * - configuration:
 *   - packet time interval
 *   - packet size
 *   - bitrate
 */


struct sender {
	struct allocation *alloc;  /* pointer */
	uint32_t session_cookie;
	uint32_t alloc_id;
	uint32_t seq;

	unsigned bitrate;          /* target bitrate [bit/s] */
	unsigned ptime;
	size_t psize;

	uint64_t ts;               /* running timestamp */
	uint64_t ts_start;
	uint64_t ts_stop;

	uint64_t total_bytes;
	uint64_t total_packets;
};


static int send_packet(struct sender *snd)
{
	struct mbuf *mb = mbuf_alloc(1024);
#define PRESZ 48
	size_t payload_len;
	int err = 0;

	if (snd->psize < HDR_SIZE)
		return EINVAL;

	payload_len = snd->psize - HDR_SIZE;

	mb->pos = PRESZ;

	err = protocol_encode(mb, snd->session_cookie, snd->alloc_id,
			      ++snd->seq, payload_len, PATTERN);
	if (err)
		goto out;

	mb->pos = PRESZ;

	err = allocation_tx(snd->alloc, mb);
	if (err) {
		re_fprintf(stderr, "sender: allocation_tx(%zu bytes)"
			   " failed (%m)\n", snd->psize, err);
		goto out;
	}

	snd->total_bytes   += mbuf_get_left(mb);
	snd->total_packets += 1;

 out:
	mem_deref(mb);

	return err;
}


void sender_tick(struct sender *snd, uint64_t now)
{
	if (!snd)
		return;

	if (now >= snd->ts) {

		send_packet(snd);
		snd->ts += snd->ptime;
	}
}


static void destructor(void *arg)
{
	struct sender *snd = arg;
	(void)snd;
}


int sender_alloc(struct sender **senderp, struct allocation *alloc,
		 uint32_t session_cookie, uint32_t alloc_id,
		 unsigned bitrate, unsigned ptime, size_t psize)
{
	struct sender *snd;
	int err = 0;

	if (!senderp || !bitrate)
		return EINVAL;

	if (ptime < PACING_INTERVAL_MS) {
		re_fprintf(stderr, "ptime %u is too low\n", ptime);
		return EINVAL;
	}
	if (psize < HDR_SIZE) {
		re_fprintf(stderr, "sender: bitrate is too low..\n");
		return EINVAL;
	}

	snd = mem_zalloc(sizeof(*snd), destructor);
	if (!snd)
		return ENOMEM;

	snd->alloc          = alloc;
	snd->session_cookie = session_cookie;
	snd->alloc_id       = alloc_id;
	snd->bitrate        = bitrate;
	snd->ptime          = ptime;
	snd->psize          = psize;

	if (err)
		mem_deref(snd);
	else
		*senderp = snd;

	return err;
}


int sender_start(struct sender *snd)
{
	if (!snd)
		return EINVAL;

	snd->ts_start = tmr_jiffies();

	/* random component to smoothe traffic */
	snd->ts       = tmr_jiffies() + rand_u16() % 100;

	return 0;
}


void sender_stop(struct sender *snd)
{
	if (!snd)
		return;

	snd->ts_stop = tmr_jiffies();
}


uint64_t sender_get_packets(const struct sender *snd)
{
	return snd ? snd->total_packets : 0ULL;
}


double sender_get_bitrate(const struct sender *snd)
{
	double duration;

	if (!snd)
		return .0;
	if (!snd->ts_start || !snd->ts_stop)
		return -1.0;

	duration = snd->ts_stop - snd->ts_start;

	return (double)snd->total_bytes / (duration / 1000.0 / 8);
}
