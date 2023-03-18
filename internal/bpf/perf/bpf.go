package perf

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/perf"
	"github.com/cloudflare/cbpfc"
	internalbpf "github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta Skbdump ./skbdump.c -- -I../headers -I. -Wall

type PerfBpfObjects struct {
	spec *ebpf.CollectionSpec
	objs *SkbdumpObjects
}

type SkbdumpSkb struct {
	SkbdumpSkbMeta
	Data [100]byte
}

func New() (_ *PerfBpfObjects, err error) {
	spec, err := LoadSkbdump()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &PerfBpfObjects{
		spec: spec,
		objs: &SkbdumpObjects{},
	}, nil
}

func (o *PerfBpfObjects) setFilter(cbpfFilter []bpf.Instruction) (err error) {
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
	ingressInsts := o.spec.Programs["on_ingress"].Instructions
	ingressInsts = append(ingressInsts[:6], append(ebpfFilter, ingressInsts[7:]...)...)
	o.spec.Programs["on_ingress"].Instructions = ingressInsts

	egressInsts := o.spec.Programs["on_egress"].Instructions
	egressInsts = append(egressInsts[:6], append(ebpfFilter, egressInsts[7:]...)...)
	o.spec.Programs["on_egress"].Instructions = egressInsts
	return
}

func (o *PerfBpfObjects) Load(cbpfFilter []bpf.Instruction) (err error) {
	if err = o.setFilter(cbpfFilter); err != nil {
		return
	}
	if err = errors.WithStack(o.spec.LoadAndAssign(o.objs, nil)); err != nil {
		return
	}
	return nil
}

func (o *PerfBpfObjects) EgressFilter() *ebpf.Program {
	return o.objs.OnEgress
}
func (o *PerfBpfObjects) IngressFilter() *ebpf.Program {
	return o.objs.OnIngress
}

func (o *PerfBpfObjects) PollSkb(ctx context.Context) (_ <-chan internalbpf.Skb, err error) {
	perfReader, err := perf.NewReader(o.objs.PerfOutput, 40960)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ch := make(chan internalbpf.Skb)
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			perfReader.SetDeadline(time.Now().Add(time.Second))
			record, err := perfReader.Read()
			if err != nil {
				continue
			}

			meta := SkbdumpSkbMeta{}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &meta); err != nil {
				continue
			}
			ch <- internalbpf.Skb{
				Meta: internalbpf.Meta{
					IsIngress:      meta.IsIngress,
					TimeNs:         meta.TimeNs,
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
				Data: record.RawSample[unsafe.Sizeof(meta):],
			}
		}
	}()
	return ch, nil
}
