package bpf

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

func InjectPcapFilter(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	if filterExpr == "" {
		return
	}

	injectIdx := -1
	for idx, inst := range program.Instructions {
		if inst.Symbol() == "pcap_filter" {
			injectIdx = idx
		}
	}
	if injectIdx == -1 {
		return errors.New("Cannot find pcap_filter label")
	}

	filterEbpf, err := CompileEbpf(filterExpr, cbpfc.EBPFOpts{
		PacketStart: asm.R1,
		PacketEnd:   asm.R2,
		Result:      asm.R0,
		ResultLabel: "result",
		Working:     [4]asm.Register{asm.R3, asm.R4, asm.R5, asm.R0},
		LabelPrefix: "filter",
		StackOffset: 0,
	})
	if err != nil {
		return
	}

	filterEbpf[0] = filterEbpf[0].WithMetadata(program.Instructions[injectIdx].Metadata)
	program.Instructions[injectIdx] = program.Instructions[injectIdx].WithMetadata(asm.Metadata{})
	program.Instructions = append(program.Instructions[:injectIdx],
		append(filterEbpf, program.Instructions[injectIdx:]...)...,
	)

	return nil

}
