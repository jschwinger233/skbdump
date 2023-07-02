package perf

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	internalbpf "github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/pkg/errors"
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

func (o *PerfBpfObjects) Load(opts internalbpf.LoadOptions) (err error) {
	for _, prog := range o.spec.Programs {
		internalbpf.InjectPcapFilter(prog, opts.Filter)
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
				Data: record.RawSample[unsafe.Sizeof(meta):],
			}
		}
	}()
	return ch, nil
}
