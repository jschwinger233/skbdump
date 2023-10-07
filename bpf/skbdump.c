// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "skbdump.h"
#include "skb_data.h"

const static bool TRUE = true;

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") skb_addresses = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = MAX_TRACK_SIZE,
};

static __noinline
bool tc_pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline
void handle_skb(struct __sk_buff *skb, bool ingress)
{
	__u32 key = 0;
	struct skbdump *dump;

	__u64 skb_addr = (__u64)(void *)skb;
	if (SKBDUMP_CONFIG.skb_track)
		if (bpf_map_lookup_elem(&skb_addresses, &skb_addr))
			goto cont;

	if (!tc_pcap_filter((void *)skb, (void *)skb, (void *)skb,
			 (void *)(long)skb->data, (void *)(long)skb->data_end))
		return;

	if (SKBDUMP_CONFIG.skb_track)
		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);

cont:
	dump = bpf_map_lookup_elem(&bpf_stack, &key);
	if (!dump)
		return;

	dump->meta.at = ingress;
	dump->meta.time_ns = bpf_ktime_get_boot_ns();
	dump->meta.skb = skb_addr;

	dump->meta.data = skb->data;
	dump->meta.len = skb->len;
	dump->meta.protocol = skb->protocol;
	dump->meta.pkt_type = skb->pkt_type;
	dump->meta.mark = skb->mark;
	dump->meta.ifindex = skb->ifindex;
	dump->meta.cb[0] = skb->cb[0];
	dump->meta.cb[1] = skb->cb[1];
	dump->meta.cb[2] = skb->cb[2];
	dump->meta.cb[3] = skb->cb[3];
	dump->meta.cb[4] = skb->cb[4];

	bpf_skb_pull_data(skb, skb->len);
	bpf_tail_call(skb, &skb_payload_call,
		      skb->len > MAX_DATA_SIZE ? MAX_DATA_SIZE : skb->len);
}

SEC("tc")
int on_egress(struct __sk_buff *skb)
{
	handle_skb(skb, false);
	return TC_ACT_OK;
}

SEC("tc")
int on_ingress(struct __sk_buff *skb)
{
	handle_skb(skb, true);
	return TC_ACT_OK;
}
