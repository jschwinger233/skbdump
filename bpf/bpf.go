package bpf

import (
	"context"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/elibpcap"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I./headers -I. -Wall

type Skb struct {
	Meta SkbdumpSkbMeta
	Data []byte
}

type LoadOptions struct {
	Filter    string
	BpfConfig BpfConfig
}

type BpfConfig struct {
	SkbTrack bool
}

type Objects interface {
	Load(LoadOptions) error
	TcIngress() *ebpf.Program
	TcEgress() *ebpf.Program
	Kprobe() *ebpf.Program
	Kretprobe() *ebpf.Program
	PollSkb(context.Context) (<-chan Skb, error)
}

type BpfObjects struct {
	spec *ebpf.CollectionSpec
	objs *SkbdumpObjects
}

func New() (_ *BpfObjects, err error) {
	spec, err := LoadSkbdump()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &BpfObjects{
		spec: spec,
		objs: &SkbdumpObjects{},
	}, nil
}

func (o *BpfObjects) Load(opts LoadOptions) (err error) {
	if err = errors.WithStack(o.spec.RewriteConstants(map[string]interface{}{"SKBDUMP_CONFIG": opts.BpfConfig})); err != nil {
		return
	}

	for _, progName := range []string{"on_ingress", "on_egress"} {
		prog, ok := o.spec.Programs[progName]
		if !ok {
			return errors.Errorf("program %s not found", progName)
		}
		if prog.Instructions, err = elibpcap.Inject(opts.Filter,
			prog.Instructions,
			elibpcap.Options{AtBpf2Bpf: "tc_pcap_filter"},
		); err != nil {
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

func (o *BpfObjects) TcIngress() *ebpf.Program {
	return o.objs.OnEgress
}
func (o *BpfObjects) TcEgress() *ebpf.Program {
	return o.objs.OnIngress
}

func (o *BpfObjects) Kprobe() *ebpf.Program {
	return nil
}

func (o *BpfObjects) Kretprobe() *ebpf.Program {
	return nil
}

func (o *BpfObjects) PollSkb(ctx context.Context) (_ <-chan Skb, err error) {
	ch := make(chan Skb)
	go func() {
		defer close(ch)

		dataReader, err := ringbuf.NewReader(o.objs.DataRingbuf)
		if err != nil {
			log.Printf("Failed to open ringbuf: %+v", err)
		}
		defer dataReader.Close()

		go func() {
			<-ctx.Done()
			dataReader.Close()
		}()

		for {
			rec, err := dataReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Failed to read ringbuf: %+v", err)
				continue
			}

			meta := SkbdumpSkbMeta{}
			if err := o.objs.MetaQueue.LookupAndDelete(nil, &meta); err != nil {
				log.Printf("Failed to read meta queue: %+v", err)
				continue
			}

			ch <- Skb{
				Meta: meta,
				Data: rec.RawSample,
			}
		}
	}()
	return ch, nil
}
