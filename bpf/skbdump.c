// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#include "skbdump.h"
#include "skb_payload.h"

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
void handle_skb_tc(struct __sk_buff *skb, bool ingress)
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
	handle_skb_tc(skb, false);
	return TC_ACT_OK;
}

SEC("tc")
int on_ingress(struct __sk_buff *skb)
{
	handle_skb_tc(skb, true);
	return TC_ACT_OK;
}

static __noinline bool
kprobe_pcap_filter_l3(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __noinline bool
kprobe_pcap_filter_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
kprobe_pcap_filter(struct sk_buff *skb) {
	if (BPF_CORE_READ(skb, mac_len) == 0) {
		void *skb_head = BPF_CORE_READ(skb, head);
		void *data = skb_head + BPF_CORE_READ(skb, network_header);
		void *data_end = skb_head + BPF_CORE_READ(skb, tail);
		return kprobe_pcap_filter_l3((void *)skb, (void *)skb, (void *)skb, data, data_end);
	}

	void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, mac_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);
	return kprobe_pcap_filter_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline int
handle_skb_kprobe(struct sk_buff *skb, struct pt_regs *ctx) {
	__u32 key = 0;
	struct skbdump *dump;

	__u64 skb_addr = (__u64)(void *)skb;
	if (SKBDUMP_CONFIG.skb_track)
		if (bpf_map_lookup_elem(&skb_addresses, &skb_addr))
			goto cont;

	if (!kprobe_pcap_filter(skb))
		return 0;

	if (SKBDUMP_CONFIG.skb_track)
		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);

cont:
	//if (SKBDUMP_CONFIG.netns != get_netns(skb))
		//return 0;

	dump = bpf_map_lookup_elem(&bpf_stack, &key);
	if (!dump)
		return 0;

	dump->meta.at = ctx->ip - 1;
	dump->meta.time_ns = bpf_ktime_get_boot_ns();
	dump->meta.skb = skb_addr;

	dump->meta.data = (__u64)BPF_CORE_READ(skb, data);
	__u16 off_l2_or_l3 = BPF_CORE_READ(skb, mac_len) ? BPF_CORE_READ(skb, mac_header) : BPF_CORE_READ(skb, network_header);
	dump->meta.len = BPF_CORE_READ(skb, tail) - (__u32)off_l2_or_l3;
	dump->meta.protocol = (__u32)BPF_CORE_READ_BITFIELD_PROBED(skb, pkt_type);
	BPF_CORE_READ_INTO(&dump->meta.protocol, skb, protocol);
	BPF_CORE_READ_INTO(&dump->meta.mark, skb, mark);
	BPF_CORE_READ_INTO(&dump->meta.ifindex, skb, dev, ifindex);
	BPF_CORE_READ_INTO(&dump->meta.cb[0], skb, cb[0]);
	BPF_CORE_READ_INTO(&dump->meta.cb[1], skb, cb[8]);
	BPF_CORE_READ_INTO(&dump->meta.cb[2], skb, cb[16]);
	BPF_CORE_READ_INTO(&dump->meta.cb[3], skb, cb[24]);
	BPF_CORE_READ_INTO(&dump->meta.cb[4], skb, cb[32]);

	void *skb_head = BPF_CORE_READ(skb, head);
	bpf_probe_read_kernel(&dump->payload, sizeof(dump->payload), (void *)(skb_head + off_l2_or_l3));
	bpf_ringbuf_output(&data_ringbuf, dump, sizeof(*dump), 0);
	return 0;
}


#define SKB_KPROBE(X)                                                     \
  SEC("kprobe/skb-" #X)                                             \
  int kprobe_skb_##X(struct pt_regs *ctx) {                                    \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);             \
    return handle_skb_kprobe(skb, ctx);                  \
  }

SKB_KPROBE(1)
SKB_KPROBE(2)
SKB_KPROBE(3)
SKB_KPROBE(4)
SKB_KPROBE(5)

SEC("kprobe/kfree_skbmem")
int kprobe_kfree_skbmem(struct pt_regs *ctx) {
	__u64 skb_addr = (__u64)PT_REGS_PARM1(ctx);
	if (SKBDUMP_CONFIG.skb_track)
		bpf_map_delete_elem(&skb_addresses, &skb_addr);
	return 0;
}
