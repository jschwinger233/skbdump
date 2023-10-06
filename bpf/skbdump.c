// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "skbdump.h"
#include "skb_data.h"

const static bool TRUE = true;

char __license[] SEC("license") = "Dual MIT/GPL";

// force emitting struct into the ELF.
const struct skb_meta *_ __attribute__((unused));

struct bpf_map_def SEC("maps") meta_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct skb_meta),
	.max_entries = MAX_QUEUE_SIZE,
};

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
	struct skb_meta meta;

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
	__builtin_memset(&meta, 0, sizeof(meta));
	bpf_skb_pull_data(skb, skb->len);

	meta.at = ingress;
	meta.time_ns = bpf_ktime_get_boot_ns();
	meta.address = skb_addr;

	meta.data = skb->data;
	meta.data_end = skb->data_end;
	meta.len = skb->len;
	meta.protocol = skb->protocol;
	meta.pkt_type = skb->pkt_type;
	meta.mark = skb->mark;
	meta.ifindex = skb->ifindex;
	meta.cb[0] = skb->cb[0];
	meta.cb[1] = skb->cb[1];
	meta.cb[2] = skb->cb[2];
	meta.cb[3] = skb->cb[3];
	meta.cb[4] = skb->cb[4];
	bpf_map_push_elem(&meta_queue, &meta, BPF_EXIST);

	bpf_tail_call(skb, &skb_data_call,
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
