// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "skbdump.h"
#include "skb_data.h"
#include "skb_checker.h"


char __license[] SEC("license") = "Dual MIT/GPL";

struct skb_meta {
	bool	is_ingress;
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

// force emitting struct into the ELF.
const struct skb_meta *_ __attribute__((unused));

struct bpf_map_def SEC("maps") meta_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct skb_meta),
	.max_entries = MAX_QUEUE_SIZE,
};

static __always_inline
void handle_skb(struct __sk_buff *skb, bool ingress)
{
	bpf_skb_pull_data(skb, 0);

	struct skb_checker checker;
	__builtin_memset(&checker, 0, sizeof(checker));
	checker.cursor = (void *)(long)skb->data;
	checker.data_end = (void *)(long)skb->data_end;

	__u32 this_proto = 0;
	for (int layer=0; layer<MAX_LAYER; layer++) {
		if (!check_next_layer(&checker, &this_proto))
			return;

		if (this_proto == (__u32)IPPROTO_MAX)
			break;
	}

	struct skb_meta meta = {};
	__builtin_memset(&meta, 0, sizeof(meta));
	meta.is_ingress = ingress;
	meta.time_ns = bpf_ktime_get_ns();
	/* copy from skb */
	meta.len = skb->len;
	meta.pkt_type = skb->pkt_type;
	meta.mark = skb->mark;
	meta.queue_mapping = skb->queue_mapping;
	meta.protocol = skb->protocol;
	meta.vlan_present = skb->vlan_present;
	meta.vlan_proto = skb->vlan_proto;
	meta.priority = skb->priority;
	meta.ingress_ifindex = skb->ingress_ifindex;
	meta.ifindex = skb->ifindex;
	meta.tc_index = skb->tc_index;
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
