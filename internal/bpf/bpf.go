package bpf

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/packetcap/go-pcap/filter"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I./headers -I. -Wall

func setFilter(spec *ebpf.CollectionSpec, exp string) (err error) {
	if len(strings.Trim(exp, " ")) == 0 {
		return
	}
	cbpfFilter, err := filter.NewExpression(exp).Compile().Compile()
	if err != nil {
		return errors.WithStack(err)
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
		return errors.WithStack(err)
	}

	ebpfFilter = append(ebpfFilter,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("result"), // r0 = TC_ACT_OK
		asm.JNE.Imm(asm.R4, 0, "continue"),          // if r4 != 0 (match): jump to continue
		asm.Return().WithSymbol("return"),           // else return TC_ACT_OK
		asm.Mov.Imm(asm.R0, 0).WithSymbol("continue"),
	)
	ingressInsts := spec.Programs["on_ingress"].Instructions
	ingressInsts = append(ingressInsts[:6], append(ebpfFilter, ingressInsts[7:]...)...)
	spec.Programs["on_ingress"].Instructions = ingressInsts

	egressInsts := spec.Programs["on_egress"].Instructions
	egressInsts = append(egressInsts[:6], append(ebpfFilter, egressInsts[7:]...)...)
	spec.Programs["on_egress"].Instructions = egressInsts
	return
}

func initTailcallMap(objs *SkbdumpObjects) (err error) {
	r := reflect.ValueOf(objs)
	for i := 1; i <= 1500; i++ {
		tailFunc := reflect.Indirect(r).FieldByName(fmt.Sprintf("TailSkbData%d", i)).Interface().(*ebpf.Program)
		key := uint32(i)
		value := int32(tailFunc.FD())
		if err = errors.WithStack(objs.SkbDataCall.Put(&key, &value)); err != nil {
			return
		}
	}
	return
}

func LoadBpfObjects(filterExp string) (_ *SkbdumpObjects, err error) {
	objs := &SkbdumpObjects{}
	spec, err := LoadSkbdump()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err = setFilter(spec, filterExp); err != nil {
		return nil, errors.WithStack(err)
	}

	if err = errors.WithStack(spec.LoadAndAssign(objs, nil)); err != nil {
		return
	}

	return objs, errors.WithStack(initTailcallMap(objs))
}
