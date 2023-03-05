// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "skbdump.h"
#include "skb_data.h"


char __license[] SEC("license") = "Dual MIT/GPL";

struct skb_meta {
	bool	is_ingress;
	__u8	h_source[ETH_HLEN];
	__u8	h_dest[ETH_HLEN];
	__u32	saddr;
	__u32	daddr;
	__u64	time_ns;
};

// force emitting struct into the ELF.
const struct skb_meta *_ __attribute__((unused));

struct bpf_map_def SEC("maps") meta_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct skb_meta),
	.max_entries = MAX_QUEUE_SIZE,
};

static __always_inline void
handle_skb(struct __sk_buff *skb, bool ingress)
{
	bpf_skb_pull_data(skb, 0);

	struct skb_meta meta = {};
	__builtin_memset(&meta, 0, sizeof(meta));
	meta.is_ingress = ingress;
	meta.time_ns = bpf_ktime_get_ns();
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
