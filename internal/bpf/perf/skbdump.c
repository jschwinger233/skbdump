// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "skbdump.h"


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

struct bpf_map_def SEC("maps") perf_output = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

static __always_inline
bool pcap_filter(void *data, void* data_end)
{
	return data_end > data;
}

static __always_inline
void handle_skb(struct __sk_buff *skb, bool ingress)
{
	bpf_skb_pull_data(skb, 0);

	if (!pcap_filter((void *)(long)skb->data, (void *)(long)skb->data_end))
		return;

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

	__u64 flags = BPF_F_CURRENT_CPU;
	flags |= (__u64)(skb->len) << 32;
	bpf_perf_event_output(skb, &perf_output, flags, &meta, sizeof(meta));
	return;
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
