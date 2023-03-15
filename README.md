# skbdump

skbdump takes advantages of [tc-bpf(8)](https://man7.org/linux/man-pages/man8/tc-bpf.8.html) to dump traffic on a network.

This tool is created by the following motives:

1. tcpdump(8) is bypassed when a bpf program on a device redirects the skb to another device;
2. tcpdump(8) works slowly and affects network performance;
3. tcpdump(8) `-i any` relies on Linux cooked-mode capture (SLL) and the link layer header isn't available;
4. tcpdump(8) doesn't reflect the information of direction: egress or ingress;
5. tcpdump(8) can't capture the skb metadata in the `struct __sk_buff`;

However, tcpdump(8) does have something I really appriciate, such as [pcap-filter(7)](https://linux.die.net/man/7/pcap-filter) for packet filtering, and I want to make sure my tool can still leverage the power of that.

# Installation

Please download the latest binary in the [releases](https://github.com/jschwinger233/skbdump/releases).

### Requirements

`tcpdump(8)` is required to generate cbpf bytecode, please install it.

# Usage

```
Usage of skbdump:
  -i, --interface string       interface to capture (default "lo")
  -w, --pcap-filename string   output pcap filename (default "skbdump.pcap")
      --perf-output            use bpf_perf_event_output to lift payload size limit
  -p, --priority uint32        filter priority (default 1)
  -s, --skb-filename string    output skb filename (default "skbdump.skb")
```

Please be aware that every capture will dump two files, one is `pcap` file which I recommand you open it by wireshark, and the other is `skb` text file just simply recording skb metadata in JSON.

### Some examples:

1. skbdump -i eth0 port 80 and host 10.10.1.1
2. skbdump -i eth0 udp or arp
3. skbdump -i any icmp or icmp6
4. skbdump -i any ip6 and dst host fd04::18ab
5. skbdump -i veth 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# Known Issues

1. Currently the tool only supports capturing packets with maximum 1500 bytes in default mode.
