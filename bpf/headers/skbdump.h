#ifndef TC_ACT_OK
#define TC_ACT_OK 0
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

#ifndef SKBDUMP_CONFIG_DEFINED
#define SKBDUMP_CONFIG_DEFINED
struct skbdump_config {
	bool skb_track;
};

static volatile const struct skbdump_config SKBDUMP_CONFIG = {};
#endif
