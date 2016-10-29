/**
 * @file protocol.c TURNPERF Protocol
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include "turnperf.h"


static const uint32_t proto_magic = 'T'<<24 | 'P'<<16 | 'R'<<8 | 'F';


int protocol_encode(struct mbuf *mb,
		    uint32_t session_cookie, uint32_t alloc_id,
		    uint32_t seq, size_t payload_len, uint8_t pattern)
{
	int err = 0;

	err |= mbuf_write_u32(mb, htonl(proto_magic));
	err |= mbuf_write_u32(mb, htonl(session_cookie));
	err |= mbuf_write_u32(mb, htonl(alloc_id));
	err |= mbuf_write_u32(mb, htonl(seq));
	err |= mbuf_write_u32(mb, htonl((uint32_t)payload_len));
	err |= mbuf_fill(mb, pattern, payload_len);

	return err;
}


int protocol_decode(struct hdr *hdr, struct mbuf *mb)
{
	uint32_t magic;
	size_t start;
	int err = 0;

	if (!hdr || !mb)
		return EINVAL;

	start = mb->pos;

	if (mbuf_get_left(mb) < HDR_SIZE)
		return EBADMSG;

	magic = ntohl(mbuf_read_u32(mb));
	if (magic != proto_magic) {
		err = EBADMSG;
		goto out;
	}

	hdr->session_cookie = ntohl(mbuf_read_u32(mb));
	hdr->alloc_id       = ntohl(mbuf_read_u32(mb));
	hdr->seq            = ntohl(mbuf_read_u32(mb));
	hdr->payload_len    = ntohl(mbuf_read_u32(mb));

	if (mbuf_get_left(mb) < hdr->payload_len) {
		re_fprintf(stderr, "receiver: header said %zu bytes,"
			   " but payload is only %zu bytes\n",
			   hdr->payload_len, mbuf_get_left(mb));
		err = EPROTO;
		goto out;
	}

	/* save portions of the packet */
	memcpy(hdr->payload, mbuf_buf(mb),
	       min (mbuf_get_left(mb), sizeof(hdr->payload)));

	/* important, so that the TURN TCP-framing works */
	mbuf_advance(mb, hdr->payload_len);

 out:
	if (err)
		mb->pos = start;

	return 0;
}


void protocol_packet_dump(const struct hdr *hdr)
{
	if (!hdr)
		return;

	re_fprintf(stderr, "--- protocol packet: ---\n");
	re_fprintf(stderr, "session_cookie: 0x%08x\n", hdr->session_cookie);
	re_fprintf(stderr, "alloc_id:       %u\n", hdr->alloc_id);
	re_fprintf(stderr, "seq:            %u\n", hdr->seq);
	re_fprintf(stderr, "payload_len:    %u\n", hdr->payload_len);
	re_fprintf(stderr, "payload:        %w\n",
		   hdr->payload, hdr->payload_len);
	re_fprintf(stderr, "\n");
}
