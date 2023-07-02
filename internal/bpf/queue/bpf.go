package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	internalbpf "github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I../headers -I. -Wall

const (
	/*
				00000000000467c8 <on_ingress>:
				; {
					36089:	r6 = r1
				; 	bpf_skb_pull_data(skb, 0);
					36090:	r2 = 0
					36091:	call 39
				; 	__u64 skb_addr = (__u64)(void *)skb;
					36092:	*(u64 *)(r10 - 104) = r6
				; 	if (SKBDUMP_CONFIG.skb_track && bpf_map_lookup_elem(&skb_address, &skb_addr))
					36093:	r1 = 0 ll
					36095:	r1 = *(u8 *)(r1 + 0)
					36096:	if r1 == 0 goto +6 <LBB1501_2>
					36097:	r2 = r10
					36098:	r2 += -104
				; 	if (SKBDUMP_CONFIG.skb_track && bpf_map_lookup_elem(&skb_address, &skb_addr))
					36099:	r1 = 0 ll
					36101:	call 1
		GotoIndex ->		36102:	if r0 != 0 goto +11 <LBB1501_4>

				0000000000046838 <LBB1501_2>:
				; 	if (!pcap_filter((void *)(long)skb->data, (void *)(long)skb->data_end))
					36103:	r1 = *(u32 *)(r6 + 80)
					36104:	r2 = *(u32 *)(r6 + 76)
		FilterIndex ->		36105:	if r2 >= r1 goto +72 <LBB1501_7>
	*/
	FilterIndex = 14
	GotoIndex   = 11
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

func (o *QueueBpfObjects) Load(opts internalbpf.LoadOptions) (err error) {
	if err = errors.WithStack(o.spec.RewriteConstants(map[string]interface{}{"SKBDUMP_CONFIG": opts.BpfConfig})); err != nil {
		return
	}

	for _, prog := range o.spec.Programs {
		internalbpf.InjectPcapFilter(prog, opts.Filter)
	}
	if err = errors.WithStack(o.spec.LoadAndAssign(o.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize,
		},
	})); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}
		return errors.WithMessage(err, verifierLog)
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
