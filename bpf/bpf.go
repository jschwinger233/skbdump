package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/elibpcap"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skbdump Bpf ./skbdump.c -- -I./headers -I. -Wall

type Skbdump = BpfSkbdump

type LoadOptions struct {
	Filter    string
	BpfConfig BpfConfig
}

type BpfConfig struct {
	Netns    uint32
	SkbTrack uint32
}

type Objects interface {
	Load(LoadOptions) error
	TcIngress() *ebpf.Program
	TcEgress() *ebpf.Program
	Kprobe(pos int) *ebpf.Program
	Kretprobe(pos int) *ebpf.Program
	PollSkb(context.Context) (<-chan Skbdump, error)
}

type Bpf struct {
	spec *ebpf.CollectionSpec
	objs *BpfObjects
}

func New() (_ *Bpf, err error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Bpf{
		spec: spec,
		objs: &BpfObjects{},
	}, nil
}

func (o *Bpf) Load(opts LoadOptions) (err error) {
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

func (o *Bpf) TcIngress() *ebpf.Program {
	return o.objs.OnEgress
}
func (o *Bpf) TcEgress() *ebpf.Program {
	return o.objs.OnIngress
}

func (o *Bpf) Kprobe(pos int) *ebpf.Program {
	switch pos {
	case 1:
		return o.objs.OnKprobe1
	case 2:
		return o.objs.OnKprobe2
	case 3:
		return o.objs.OnKprobe3
	case 4:
		return o.objs.OnKprobe4
	case 5:
		return o.objs.OnKprobe5
	default:
		log.Fatalf("Invalid kprobe position: %d", pos)
	}
	return nil
}

func (o *Bpf) Kretprobe(pos int) *ebpf.Program {
	return nil
}

func (o *Bpf) PollSkb(ctx context.Context) (_ <-chan Skbdump, err error) {
	ch := make(chan Skbdump)
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

			skb := Skbdump{}
			if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &skb.Meta); err != nil {
				log.Printf("Failed to read event: %+v", err)
				continue
			}
			copy(skb.Payload[:], rec.RawSample[unsafe.Sizeof(skb.Meta):])

			ch <- skb
		}
	}()
	return ch, nil
}
