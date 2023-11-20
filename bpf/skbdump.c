// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#define TC_ACT_OK 0

#define MAX_STRUCT_SIZE 4096
#define MAX_PAYLOAD_SIZE 1500
#define MAX_TRACK_SIZE 1000

#define __maybe_unused		__attribute__((__unused__))

struct skbdump_config {
	__u32 netns;
};

static volatile const struct skbdump_config SKBDUMP_CONFIG = {};

const static bool TRUE = true;
const static __u32 KEY = 0;

char __license[] SEC("license") = "Dual MIT/GPL";

struct skbmeta {
	__u64	at;
	__u64	skb;
	__u64	time_ns;
	__u64   rax;

	__u16	l2;
	__u32	len;
	__u32	ifindex;

	__u8    structure[MAX_STRUCT_SIZE];
};

struct skbdump {
	struct	skbmeta	meta;
	__u8	payload[MAX_PAYLOAD_SIZE];
};

// force emitting struct into the ELF.
const struct skbdump *__ __attribute__((unused));

struct bpf_map_def SEC("maps") bpf_stack = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct skbdump),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") skb_addresses = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = MAX_TRACK_SIZE,
};

struct bpf_map_def SEC("maps") tid2skb = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = MAX_TRACK_SIZE,
};

struct bpf_map_def SEC("maps") tid2sp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = MAX_TRACK_SIZE,
};

struct bpf_map_def SEC("maps") sp2ip = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = MAX_TRACK_SIZE,
};

struct bpf_map_def SEC("maps") perf_output = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

static __noinline
bool tc_pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline
void handle_skb_tc(struct __sk_buff *skb, bool ingress)
{
	struct skbdump *dump;

	__u64 skb_addr = (__u64)(void *)skb;
	if (bpf_map_lookup_elem(&skb_addresses, &skb_addr))
			goto cont;

	if (!tc_pcap_filter((void *)skb, (void *)skb, (void *)skb,
			 (void *)(long)skb->data, (void *)(long)skb->data_end))
		return;

	bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);

cont:
	dump = bpf_map_lookup_elem(&bpf_stack, &KEY);
	if (!dump)
		return;

	dump->meta.at = ingress;
	dump->meta.time_ns = bpf_ktime_get_boot_ns();
	dump->meta.skb = skb_addr;

	dump->meta.l2 = 1;
	dump->meta.len = skb->len;
	dump->meta.ifindex = skb->ifindex;

	bpf_skb_pull_data(skb, skb->len);
	__u64 payload_len = dump->meta.len > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : dump->meta.len;

	struct btf_ptr p = {};
	p.type_id = bpf_core_type_id_kernel(struct __sk_buff);
	p.ptr = skb;
	bpf_snprintf_btf((char *)&dump->meta.structure, MAX_STRUCT_SIZE, &p,
			 sizeof(p), BTF_F_COMPACT | BTF_F_PTR_RAW);

	bpf_perf_event_output(skb, &perf_output, BPF_F_CURRENT_CPU | (payload_len<<32),
			      dump, offsetof(struct skbdump, payload));
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
kprobe_pcap_filter(struct sk_buff *skb)
{
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

static __always_inline u32
get_netns(struct sk_buff *skb) {
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)	{
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}
	}

	return netns;
}

static __always_inline int
collect_skb(struct sk_buff *skb, struct pt_regs *ctx, struct skbdump *dump)
{
	dump->meta.time_ns = bpf_ktime_get_boot_ns();
	dump->meta.skb = (__u64)skb;
	dump->meta.rax = ctx->ax;

	dump->meta.l2 = BPF_CORE_READ(skb, mac_len) ? 1 : 0;
	__u16 off_l2_or_l3 = dump->meta.l2 ? BPF_CORE_READ(skb, mac_header) : BPF_CORE_READ(skb, network_header);
	dump->meta.len = BPF_CORE_READ(skb, tail) - (__u32)off_l2_or_l3;
	BPF_CORE_READ_INTO(&dump->meta.ifindex, skb, dev, ifindex);

	struct btf_ptr p = {};
	p.type_id = bpf_core_type_id_kernel(struct sk_buff);
	p.ptr = skb;
	bpf_snprintf_btf((char *)&dump->meta.structure, MAX_STRUCT_SIZE, &p,
			 sizeof(p), BTF_F_COMPACT | BTF_F_PTR_RAW);

	void *skb_head = BPF_CORE_READ(skb, head);
	__u64 payload_len = dump->meta.len > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : dump->meta.len;
	bpf_probe_read_kernel(&dump->payload, payload_len, (void *)(skb_head + off_l2_or_l3));

	bpf_perf_event_output(ctx, &perf_output, BPF_F_CURRENT_CPU, dump, offsetof(struct skbdump, payload) + payload_len);
	return 0;
}


static __always_inline int
handle_skb_kprobe(struct sk_buff *skb, struct pt_regs *ctx)
{
	__u32 tid;
	__u64 skb_addr = (__u64)skb;
	if (bpf_map_lookup_elem(&skb_addresses, &skb_addr))
		goto cont;

	if (!kprobe_pcap_filter(skb))
		return 0;

	bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);

cont:
	if (SKBDUMP_CONFIG.netns != get_netns(skb))
		return 0;

	tid = bpf_get_current_pid_tgid() & 0xffffffff;
	if (!bpf_map_lookup_elem(&tid2skb, &tid)) {
		bpf_map_update_elem(&tid2skb, &tid, &skb, BPF_ANY);
		__u64 sp = ctx->sp;
		bpf_map_update_elem(&tid2sp, &tid, &sp, BPF_ANY);
	}

	struct skbdump *dump = (struct skbdump *)bpf_map_lookup_elem(&bpf_stack, &KEY);
	if (!dump)
		return 0;

	dump->meta.at = ctx->ip - 1;
	__u64 sp = ctx->sp;
	bpf_map_update_elem(&sp2ip, &sp, &dump->meta.at, BPF_ANY);
	return collect_skb(skb, ctx, dump);
}


#define SKB_KPROBE(X)                                                     \
  SEC("kprobe/skb-" #X)                                             \
  int on_kprobe##X(struct pt_regs *ctx) \
  {                                    \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);             \
    return handle_skb_kprobe(skb, ctx);                  \
  }

SKB_KPROBE(1)
SKB_KPROBE(2)
SKB_KPROBE(3)
SKB_KPROBE(4)
SKB_KPROBE(5)

SEC("kprobe/skb-tid")
int on_kprobe_tid(struct pt_regs *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	struct sk_buff **skb = (struct sk_buff **)bpf_map_lookup_elem(&tid2skb, &tid);
	if (skb) {
		struct skbdump *dump = (struct skbdump *)bpf_map_lookup_elem(&bpf_stack, &KEY);
		if (!dump)
			return 0;

		dump->meta.at = ctx->ip - 1;
		__u64 sp = ctx->sp;
		bpf_map_update_elem(&sp2ip, &sp, &dump->meta.at, BPF_ANY);
		collect_skb(*skb, ctx, dump);
	}
	return 0;
}

SEC("kretprobe/skb")
int on_kretprobe(struct pt_regs *ctx)
{
	__u64 sp = ctx->sp - 8;
	__u64 *ip = (__u64 *)bpf_map_lookup_elem(&sp2ip, &sp);
	if (!ip)
		return 0;

	__u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
	struct sk_buff **skb = (struct sk_buff **)bpf_map_lookup_elem(&tid2skb, &tid);
	if (!skb)
		return 0;

	struct skbdump *dump = (struct skbdump *)bpf_map_lookup_elem(&bpf_stack, &KEY);
	if (!dump)
		return 0;

	dump->meta.at = (*ip) - 1;
	collect_skb(*skb, ctx, dump);

	bpf_map_delete_elem(&sp2ip, &sp);

	__u64 *creator_sp = (__u64 *)bpf_map_lookup_elem(&tid2sp, &tid);
	if (creator_sp && *creator_sp == sp) {
		bpf_map_delete_elem(&tid2sp, &tid);
		bpf_map_delete_elem(&tid2skb, &tid);
	}
	return 0;
}

SEC("kprobe/kfree_skbmem")
int on_kprobe_kfree_skbmem(struct pt_regs *ctx)
{
	__u64 skb_addr = (__u64)PT_REGS_PARM1(ctx);
	bpf_map_delete_elem(&skb_addresses, &skb_addr);
	return 0;
}
