package queue

import (
	"context"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	internalbpf "github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I../headers -I. -Wall

const (
	/* bpf bytecode
				00000000000467a8 <on_ingress>:
				; {
					36085:	r6 = r1
					36086:	r7 = 0
				; 	bpf_skb_pull_data(skb, 0);
					36087:	r2 = 0
					36088:	call 39
				; 	__u64 skb_addr = (__u64)(void *)skb;
					36089:	*(u64 *)(r10 - 104) = r6
					36090:	r2 = r10
					36091:	r2 += -104
				; 	if (bpf_map_lookup_elem(&skb_address, &skb_addr))
					36092:	r1 = 0 ll
					36094:	call 1
	GotoIndex ->	36095:	if r0 != 0 goto +11 <LBB1501_3>
				; 	if (!pcap_filter((void *)(long)skb->data, (void *)(long)skb->data_end))
					36096:	r1 = *(u32 *)(r6 + 80)
					36097:	r2 = *(u32 *)(r6 + 76)
	FilterIndex ->	36098:	if r2 >= r1 goto +71 <LBB1501_6>
	*/
	FilterIndex = 12
	GotoIndex   = 9
)

type QueueBpfObjects struct {
	spec *ebpf.CollectionSpec
	objs *SkbdumpObjects
}

func New() (_ *QueueBpfObjects, err error) {
	spec, err := LoadSkbdump()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &QueueBpfObjects{
		spec: spec,
		objs: &SkbdumpObjects{},
	}, nil
}

func (o *QueueBpfObjects) setFilter(cbpfFilter []bpf.Instruction) (err error) {
	if len(cbpfFilter) == 0 {
		return
	}

	ebpfFilter, err := cbpfc.ToEBPF(cbpfFilter, cbpfc.EBPFOpts{
		PacketStart: asm.R2, // skb->data
		PacketEnd:   asm.R1, // skb->data_end
		Result:      asm.R4,
		ResultLabel: "result",
		Working:     [4]asm.Register{asm.R4, asm.R5, asm.R8, asm.R9},
		LabelPrefix: "filter",
	})
	if err != nil {
		return
	}

	ebpfFilter = append(ebpfFilter,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("result"), // r0 = TC_ACT_OK
		asm.JNE.Imm(asm.R4, 0, "continue"),          // if r4 != 0 (match): jump to continue
		asm.Return().WithSymbol("return"),           // else return TC_ACT_OK
		asm.Mov.Imm(asm.R0, 0).WithSymbol("continue"),
	)

	o.spec.Programs["on_ingress"].Instructions = internalbpf.InjectInstructions(o.spec.Programs["on_ingress"].Instructions, ebpfFilter, FilterIndex, FilterIndex+1, []int{GotoIndex})
	o.spec.Programs["on_egress"].Instructions = internalbpf.InjectInstructions(o.spec.Programs["on_egress"].Instructions, ebpfFilter, FilterIndex, FilterIndex+1, []int{GotoIndex})
	return
}

func (o *QueueBpfObjects) Load(cbpfFilter []bpf.Instruction) (err error) {
	if err = o.setFilter(cbpfFilter); err != nil {
		return
	}
	if err = errors.WithStack(o.spec.LoadAndAssign(o.objs, nil)); err != nil {
		return
	}
	return nil
}

func (o *QueueBpfObjects) EgressFilter() *ebpf.Program {
	return o.objs.OnEgress
}
func (o *QueueBpfObjects) IngressFilter() *ebpf.Program {
	return o.objs.OnIngress
}

func (o *QueueBpfObjects) PollSkb(ctx context.Context) (_ <-chan internalbpf.Skb, err error) {
	ch := make(chan internalbpf.Skb)
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			meta := SkbdumpSkbMeta{}
			if err := o.objs.MetaQueue.LookupAndDelete(nil, &meta); err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Millisecond):
					continue
				}
			}
			data := SkbdumpSkbData{}
			for {
				if err := o.objs.DataQueue.LookupAndDelete(nil, &data); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Microsecond):
					continue
				}
			}
			ch <- internalbpf.Skb{
				Meta: internalbpf.Meta{
					IsIngress:      meta.IsIngress,
					TimeNs:         meta.TimeNs,
					Address:        meta.Address,
					Len:            meta.Len,
					PktType:        meta.PktType,
					Mark:           meta.Mark,
					QueueMapping:   meta.QueueMapping,
					Protocol:       meta.Protocol,
					VlanPresent:    meta.VlanPresent,
					VlanTci:        meta.VlanTci,
					VlanProto:      meta.VlanProto,
					Priority:       meta.Priority,
					IngressIfindex: meta.IngressIfindex,
					Ifindex:        meta.Ifindex,
					TcIndex:        meta.TcIndex,
					Cb:             meta.Cb,
				},
				Data: data.Content[:data.Len],
			}
		}
	}()
	return ch, nil
}
