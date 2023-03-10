#include "vmlinux.h"
#include "bpf_helpers.h"
#include "endian.h"

#define MAX_LAYER 6

static __always_inline
bool check_eth(struct ethhdr *eth)
{
	return true;
}

static __always_inline
bool check_ipv4(struct iphdr *ip)
{
	return true;
}

static __always_inline
bool check_icmp(struct icmphdr *icmp)
{
	return true;
}

struct skb_checker {
	void *cursor;
	void *data_end;
};

static __always_inline
bool check_next_layer(struct skb_checker *checker, __u32 *this_proto)
{
	__u16 l2_proto = (__u16)(*this_proto >> 16);
	__u8 l3_proto = (__u8)(*this_proto & 0xff);

	struct ethhdr *eth = checker->cursor;
	struct iphdr *ip = checker->cursor;
	struct icmphdr *icmp = checker->cursor;

	switch (l3_proto) {
	case (__u32)IPPROTO_ICMP:
		if ((void *)icmp + sizeof(*icmp) <= checker->data_end) {
			*this_proto = (__u32)IPPROTO_MAX;
			return check_icmp(icmp);
		}
		return true;
	}

	switch (bpf_ntohs(l2_proto)) {
	case 0:
		if ((void *)eth + sizeof(*eth) <= checker->data_end) {
			*this_proto = ((__u32)eth->h_proto) << 16;
			checker->cursor += sizeof(*eth);
			return check_eth(eth);

		}
		return true;

	case ETH_P_IP:
		if ((void *)ip + sizeof(*ip) <= checker->data_end) {
			*this_proto = (__u32)ip->protocol;
			checker->cursor += sizeof(*ip);
			return check_ipv4(ip);
		}
		return true;
	}

	return true;
}
