package bpf

import (
	"github.com/cilium/ebpf/asm"
)

func InjectInstructions(old, new []asm.Instruction, start, end int, gotoIndices []int) []asm.Instruction {
	old = append(old[:start], append(new, old[end:]...)...)
	for _, gotoIdx := range gotoIndices {
		old[gotoIdx].Offset += int16(len(new) - (end - start))
	}
	return old
}
