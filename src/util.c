/**
 * @file util.c TURN utility functions
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */

#include <re.h>
#include "turnperf.h"


int dns_init(struct dnsc **dnsc)
{
	struct sa nsv[8];
	uint32_t nsn;
	int err;

	nsn = ARRAY_SIZE(nsv);

	err = dns_srv_get(NULL, 0, nsv, &nsn);
	if (err) {
		(void)re_fprintf(stderr, "dns_srv_get: %m\n", err);
		goto out;
	}

	err = dnsc_alloc(dnsc, NULL, nsv, nsn);
	if (err) {
		(void)re_fprintf(stderr, "dnsc_alloc: %m\n", err);
		goto out;
	}

 out:
	return err;
}


const char *protocol_name(int proto, bool secure)
{
	if (secure) {
		switch (proto) {

		case IPPROTO_UDP: return "DTLS";
		case IPPROTO_TCP: return "TLS";
		default: return "???";
		}
	}
	else {
		return net_proto2name(proto);
	}
}


unsigned calculate_psize(unsigned bitrate, unsigned ptime)
{
	return (bitrate * ptime) / (8 * 1000);
}


unsigned calculate_ptime(unsigned bitrate, size_t psize)
{
	return (8 * 1000) * (unsigned)psize / bitrate;
}
