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

struct bpf_map_def SEC("maps") skb_address = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = MAX_TRACK_SIZE,
};

static __always_inline
bool pcap_filter(void *data, void* data_end)
{
	bpf_printk("%p %p\n", data, data_end);
	return data < data_end;
}

static __always_inline
void handle_skb(struct __sk_buff *skb, bool ingress)
{
	struct skb_meta meta;
	__builtin_memset(&meta, 0, sizeof(meta));
	bpf_skb_pull_data(skb, 0);

	__u64 skb_addr = (__u64)(void *)skb;
	if (SKBDUMP_CONFIG.skb_track && bpf_map_lookup_elem(&skb_address, &skb_addr))
		goto cont;

	if (!pcap_filter((void *)(long)skb->data, (void *)(long)skb->data_end))
		return;

	bpf_map_update_elem(&skb_address, &skb_addr, &TRUE, BPF_ANY);

cont:
	meta.is_ingress = ingress;
	meta.time_ns = bpf_ktime_get_ns();
	meta.address = (long)(void *)skb;
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
