# skbdump

skbdump is the tcpdump(8) implemented by eBPF.

skbdump tries to solve following tcpdump(8) issues without losing flexibility of pcap-filter(7):

1. tcpdump(8) will be bypassed if a bpf program on a netdev redirects the skb to another netdev;
2. tcpdump(8) `-i any` relies on Linux cooked-mode capture (SLL) so the link layer header isn't available;
3. tcpdump(8) can't capture skb metadata in the `struct __sk_buff` / `struct sk_buff`;
4. tcpdump(8) can't dump traffic on specific kernel functions, e.g. `ip_rcv`;

# Installation

Please download the latest binary in the [releases](https://github.com/jschwinger233/skbdump/releases).

### Requirements

Linux kernel version must be larger than 5.5.

# Usage

```
Usage of skbdump:
  -i, --interface string       interface to capture (default "lo")
  -a, --kaddrs string          kernel addresses to trace, e.g. "0xffffffffa0272110,0xffffffffa0272118"
  -f, --kfuncs string          kernel functions to trace, e.g. "ip_rcv,icmp_rcv"
  -n, --netns string           netns specifier, e.g. "pid:1234", "path:/var/run/netns/foo"
  -o, --output-fields string   output fields of skb, e.g. "mark,cb"
  -w, --pcap-filename string   output pcap filename (default "skbdump.pcap")
  -s, --skb-filename string    output skb filename (default "skbdump.meta")
```

### Example commands

1. `skbdump -i eth0 port 80 and host 10.10.1.1`
2. `skbdump -i eth0 udp or arp`
3. `skbdump -i any icmp or icmp6`
4. `skbdump -i any ip6 and dst host fd04::18ab`
5. `skbdump -i veth 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'`
6. `skbdump -i veth -f arp_rcv,arp_process 'arp and arp[7] = 1 and arp[24]= 169 and arp[25] = 254 and arp[26] = 0 and arp[27] = 1'`

### Example output

```
start tracing
1 ffff9b30ec48ad00 in@15(zcv-peer) cb= Ethernet(a2:c4:a3:6b:6f:f8>ff:ff:ff:ff:ff:ff) | ARP(who-has 169.254.0.1 tell 192.168.0.1)
2 ffff9b30ec48ad00 arp_rcv@15(zcv-peer) cb=[28,] Ethernet(a2:c4:a3:6b:6f:f8>ff:ff:ff:ff:ff:ff) | ARP(who-has 169.254.0.1 tell 192.168.0.1)
3 ffff9b30ec48ad00 arp_rcv+r@15(zcv-peer) rv=0 cb= Ethernet(a2:c4:a3:6b:6f:f8>ff:ff:ff:ff:ff:ff) | ARP(who-has 169.254.0.1 tell 192.168.0.1)
```

# Known Issues

1. Doesn't support L3 netdev such as wireguard or tun.
