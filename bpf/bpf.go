package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/elibpcap"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skbdump Bpf ./skbdump.c -- -I./headers -I. -Wall

type Skbdump = BpfSkbdump

func (d *Skbdump) Field(f string) string {
	idx := bytes.Index(d.Meta.Structure[:], []byte(fmt.Sprintf(".%s = ", f)))
	if idx == -1 {
		return ""
	}
	nested := false
	for i := idx + len(f) + 4; i < len(d.Meta.Structure); i++ {
		if d.Meta.Structure[i] == ',' && !nested {
			value := string(d.Meta.Structure[idx+len(f)+4 : i])
			if strings.HasPrefix(value, "(") {
				value = value[strings.Index(value, ")")+1:]
			}
			return value
		}
		switch d.Meta.Structure[i] {
		case '{', '[', '(':
			nested = true
		case '}', ']', ')':
			if nested {
				nested = false
			}
		}
	}
	return ""
}

type LoadOptions struct {
	Filter    string
	BpfConfig BpfConfig
}

type BpfConfig struct {
	Netns uint32
}

type Objects interface {
	Load(LoadOptions) error
	TcIngress(l2 bool) *ebpf.Program
	TcEgress(l2 bool) *ebpf.Program
	Kprobe(pos int) *ebpf.Program
	Kretprobe() *ebpf.Program
	KprobeTid() *ebpf.Program
	KprobeKfree() *ebpf.Program
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

	for _, suffix := range []string{"l2", "l3"} {
		for _, progName := range []string{"on_ingress", "on_egress"} {
			progName = fmt.Sprintf("%s_%s", progName, suffix)
			prog, ok := o.spec.Programs[progName]
			if !ok {
				return errors.Errorf("program %s not found", progName)
			}
			if prog.Instructions, err = elibpcap.Inject(
				opts.Filter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:        "tc_pcap_filter_" + suffix,
					PacketAccessMode: elibpcap.BpfProbeReadKernel,
					L2Skb:            true,
				},
			); err != nil {
				return
			}
		}
	}
	for _, progName := range []string{"on_kprobe1", "on_kprobe2", "on_kprobe3", "on_kprobe4", "on_kprobe5"} {
		prog, ok := o.spec.Programs[progName]
		if !ok {
			return errors.Errorf("program %s not found", progName)
		}
		if prog.Instructions, err = elibpcap.Inject(
			opts.Filter,
			prog.Instructions,
			elibpcap.Options{
				AtBpf2Bpf:        "kprobe_pcap_filter_l2",
				PacketAccessMode: elibpcap.BpfProbeReadKernel,
				L2Skb:            true,
			},
		); err != nil {
			return
		}
		if prog.Instructions, err = elibpcap.Inject(
			opts.Filter,
			prog.Instructions,
			elibpcap.Options{
				AtBpf2Bpf:        "kprobe_pcap_filter_l3",
				PacketAccessMode: elibpcap.BpfProbeReadKernel,
				L2Skb:            false,
			},
		); err != nil {
			if !strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
				return
			}
			if prog.Instructions, err = elibpcap.Inject(
				"__reject_all__",
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:        "kprobe_pcap_filter_l3",
					PacketAccessMode: elibpcap.BpfProbeReadKernel,
					L2Skb:            false,
				},
			); err != nil {
				return
			}
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

func (o *Bpf) TcIngress(l2 bool) *ebpf.Program {
	if l2 {
		return o.objs.OnIngressL2
	}
	return o.objs.OnIngressL3
}
func (o *Bpf) TcEgress(l2 bool) *ebpf.Program {
	if l2 {
		return o.objs.OnEgressL2
	}
	return o.objs.OnEgressL3
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

func (o *Bpf) Kretprobe() *ebpf.Program {
	return o.objs.OnKretprobe
}

func (o *Bpf) KprobeTid() *ebpf.Program {
	return o.objs.OnKprobeTid
}

func (o *Bpf) KprobeKfree() *ebpf.Program {
	return o.objs.OnKprobeKfreeSkbmem
}

func (o *Bpf) PollSkb(ctx context.Context) (_ <-chan Skbdump, err error) {
	dataReader, err := perf.NewReader(o.objs.PerfOutput, 1500*1000)
	if err != nil {
		log.Printf("Failed to open perf: %+v", err)
	}

	ch := make(chan Skbdump)
	go func() {
		defer close(ch)
		defer dataReader.Close()

		go func() {
			<-ctx.Done()
			dataReader.Close()
		}()

		records := make(chan perf.Record)
		go func() {
			defer close(records)
			for {
				rec, err := dataReader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Failed to read ringbuf: %+v", err)
					continue
				}
				records <- rec
			}
		}()

		var pool []Skbdump
		for {
			var ok bool
			var rec perf.Record
			select {
			case <-time.After(10 * time.Millisecond):
				for _, skb := range pool {
					ch <- skb
				}
				pool = nil
				continue
			case rec, ok = <-records:
				if !ok {
					return
				}
			}

			skb := Skbdump{}
			if err = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &skb.Meta); err != nil {
				log.Printf("Failed to read event: %+v", err)
				continue
			}
			copy(skb.Payload[:], rec.RawSample[unsafe.Offsetof(skb.Payload):])

			if len(pool) > 100 {
				ch <- pool[0]
				pool = pool[1:]
			}

			idx, _ := slices.BinarySearchFunc(pool, skb, func(a, b Skbdump) int {
				if a.Meta.TimeNs < b.Meta.TimeNs {
					return -1
				} else if a.Meta.TimeNs > b.Meta.TimeNs {
					return 1
				}
				return 0
			})
			pool = slices.Insert(pool, idx, skb)
		}
	}()
	return ch, nil
}
