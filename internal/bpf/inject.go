package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

func InjectPcapFilter(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	injectIdx := 0
	for idx, inst := range program.Instructions {
		if inst.OpCode.JumpOp() == asm.Call && inst.Constant == int64(asm.FnTracePrintk) {
			injectIdx = idx
			break
		}

		if inst.OpCode.Class().IsJump() {
			if inst.Offset == 0 {
				continue
			}

			if inst.Reference() != "" {
				program.Instructions[idx].Offset = -1
				continue
			}

			var gotoIns *asm.Instruction
			iter := asm.Instructions(program.Instructions[idx+1:]).Iterate()
			for iter.Next() {
				if int16(iter.Offset) == inst.Offset {
					gotoIns = iter.Ins
					break
				}
			}
			if gotoIns == nil {
				return errors.New("Cannot find the jump target")
			}
			symbol := gotoIns.Symbol()
			if symbol == "" {
				symbol = fmt.Sprintf("skbdump_%d", idx)
				*gotoIns = gotoIns.WithSymbol(symbol)
			}
			program.Instructions[idx] = program.Instructions[idx].WithReference(symbol)
			program.Instructions[idx].Offset = -1
		}
	}
	if injectIdx == 0 {
		return errors.New("Cannot find the injection position")
	}

	if filterExpr == "" {
		program.Instructions = append(program.Instructions[:injectIdx],
			program.Instructions[injectIdx+1:]...,
		)
		return
	}

	var (
		dataReg    asm.Register = 255
		dataEndReg asm.Register = 255
	)
	for idx := injectIdx - 1; idx >= 0; idx-- {
		inst := program.Instructions[idx]
		if inst.OpCode.ALUOp() == asm.Mov {
			if inst.Dst == asm.R3 {
				dataReg = inst.Src
			} else if inst.Dst == asm.R4 {
				dataEndReg = inst.Src
			}
		}
		if dataReg != 255 && dataEndReg != 255 {
			break
		}
	}
	if dataReg == 255 || dataEndReg == 255 {
		return errors.New("Cannot find the data / data_end registers")
	}

	filterEbpf, err := CompileEbpf(filterExpr, cbpfc.EBPFOpts{
		PacketStart: dataReg,
		PacketEnd:   dataEndReg,
		Result:      asm.R4,
		ResultLabel: "result",
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "filter",
		StackOffset: 40,
	})
	if err != nil {
		return
	}

	program.Instructions = append(program.Instructions[:injectIdx-4],
		append(filterEbpf, program.Instructions[injectIdx+2:]...)...,
	)

	return nil

}
