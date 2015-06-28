/**
 * @file turnperf.h TURN client -- internal interface
 *
 * Copyright (C) 2010 - 2015 Creytiv.com
 */


#include <time.h>


#define PACING_INTERVAL_MS 5


/*
 * allocator
 */

typedef void (allocation_h)(int err, uint16_t scode, const char *reason,
			    const struct sa *srv,  const struct sa *relay,
			    void *arg);
struct allocator {
	struct list allocl;
	struct tmr tmr;
	struct tmr tmr_ui;
	unsigned num_allocations;
	unsigned num_sent;
	unsigned num_received;

	bool server_info;
	bool server_auth;
	char server_software[256];
	struct sa mapped_addr;

	uint64_t tick, tock;
	uint32_t session_cookie;
	time_t traf_start_time;

	struct tmr tmr_pace;
};

struct allocation;

int allocation_create(struct allocator *allocator, unsigned ix, int proto,
		      const struct sa *srv,
		      const char *username, const char *password,
		      struct tls *tls, bool turn_ind,
		      allocation_h *alloch, void *arg);
int allocation_tx(struct allocation *alloc, struct mbuf *mb);


void allocator_reset(struct allocator *allocator);
int  allocator_start_senders(struct allocator *allocator, unsigned bitrate,
			     size_t psize);
void allocator_stop_senders(struct allocator *allocator);
void allocator_print_statistics(const struct allocator *allocator);
void allocator_show_summary(const struct allocator *allocator);
void allocator_traffic_summary(struct allocator *allocator);


/*
 * sender
 */

struct sender;

int      sender_alloc(struct sender **senderp, struct allocation *alloc,
		      uint32_t session_cookie, uint32_t alloc_id,
		      unsigned bitrate, unsigned ptime, size_t psize);
int      sender_start(struct sender *snd);
void     sender_stop(struct sender *snd);
void     sender_tick(struct sender *snd, uint64_t now);
uint64_t sender_get_packets(const struct sender *snd);
double   sender_get_bitrate(const struct sender *snd);


/*
 * receiver
 */

struct receiver {
	uint32_t cookie;
	uint32_t allocid;
	uint64_t ts_start;
	uint64_t ts_last;
	uint64_t total_bytes;
	uint64_t total_packets;
	uint32_t last_seq;
};

void receiver_init(struct receiver *recv,
		   uint32_t exp_cookie, uint32_t exp_allocid);
int  receiver_recv(struct receiver *recv, const struct sa *src,
		   struct mbuf *mb);
void receiver_print(const struct receiver *recv);
double receiver_get_bitrate(const struct receiver *recv);


/*
 * protocol
 */

#define HDR_SIZE 20
#define PATTERN 0xa5

struct hdr {
	uint32_t session_cookie;
	uint32_t alloc_id;
	uint32_t seq;
	uint32_t payload_len;

	uint8_t payload[256];
};

int  protocol_encode(struct mbuf *mb,
		     uint32_t session_cookie, uint32_t alloc_id,
		     uint32_t seq, size_t payload_len, uint8_t pattern);
int  protocol_decode(struct hdr *hdr, struct mbuf *mb);
void protocol_packet_dump(const struct hdr *hdr);


/*
 * util
 */

int  dns_init(struct dnsc **dnsc);
const char *protocol_name(int proto, bool secure);
unsigned calculate_psize(unsigned bitrate, unsigned ptime);
unsigned calculate_ptime(unsigned bitrate, size_t psize);
