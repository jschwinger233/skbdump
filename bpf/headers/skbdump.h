#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef MAX_QUEUE_SIZE
#define MAX_QUEUE_SIZE 10000
#endif

#ifndef MAX_DATA_SIZE
#define MAX_DATA_SIZE 1500
#endif

#ifndef MAX_TRACK_SIZE
#define MAX_TRACK_SIZE 1000
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806 /* Address Resolution packet	*/
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef SKB_META_DEFINED
#define SKB_META_DEFINED
struct skb_meta {
	bool	is_ingress;
	__u64	address;
	__u64	time_ns;

	/* fetch 13 fields from skb */
	__u32	len;
	__u32	pkt_type;
	__u32	mark;
	__u32	queue_mapping;
	__u32	protocol;
	__u32	vlan_present;
	__u32	vlan_tci;
	__u32	vlan_proto;
	__u32	priority;
	__u32	ingress_ifindex;
	__u32	ifindex;
	__u32	tc_index;
	__u32	cb[5];
};
#endif

#ifndef SKBDUMP_CONFIG_DEFINED
#define SKBDUMP_CONFIG_DEFINED
struct skbdump_config {
	bool skb_track;
};

static volatile const struct skbdump_config SKBDUMP_CONFIG = {};
#endif
