package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	internalbpf "github.com/jschwinger233/skbdump/bpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I../headers -I. -Wall

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

	for _, progName := range []string{"on_ingress", "on_egress"} {
		if err = internalbpf.InjectPcapFilter(o.spec.Programs[progName], opts.Filter); err != nil {
			return
		}
	}
	if err = errors.WithStack(o.spec.LoadAndAssign(o.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize * 8,
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
