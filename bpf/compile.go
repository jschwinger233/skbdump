package bpf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

/*
#cgo LDFLAGS: -L/usr/local/lib -lpcap -static
#include <stdlib.h>
#include <pcap.h>
*/
import "C"

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144
)

func CompileCbpf(expr string) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	pcap := C.pcap_open_dead(C.DLT_EN10MB, MAXIMUM_SNAPLEN)
	if pcap == nil {
		return nil, fmt.Errorf("failed to pcap_open_dead: %+v\n", C.PCAP_ERROR)
	}
	defer C.pcap_close(pcap)

	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var bpfProg pcapBpfProgram
	if C.pcap_compile(pcap, (*C.struct_bpf_program)(&bpfProg), cexpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, fmt.Errorf("failed to pcap_compile '%s': %+v", expr, C.GoString(C.pcap_geterr(pcap)))
	}
	defer C.pcap_freecode((*C.struct_bpf_program)(&bpfProg))

	for _, v := range (*[bpfInstructionBufferSize]C.struct_bpf_insn)(unsafe.Pointer(bpfProg.bf_insns))[0:bpfProg.bf_len:bpfProg.bf_len] {
		insts = append(insts, bpf.RawInstruction{
			Op: uint16(v.code),
			Jt: uint8(v.jt),
			Jf: uint8(v.jf),
			K:  uint32(v.k),
		}.Disassemble())
	}
	return
}

func CompileEbpf(expr string, opts cbpfc.EBPFOpts) (insts asm.Instructions, err error) {
	cbpfInsts, err := CompileCbpf(expr)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, opts)
	if err != nil {
		return
	}

	return adjustEbpf(ebpfInsts, opts)

}

func adjustEbpf(insts asm.Instructions, opts cbpfc.EBPFOpts) (newInsts asm.Instructions, err error) {

	insts = append(insts,
		asm.Mov.Reg(asm.R1, asm.R0).WithSymbol("result"), // r1 = r0 = $result
		asm.Mov.Imm(asm.R2, 0),                           // r2 = 0
		asm.Mov.Imm(asm.R3, 0),                           // r3 = 0
		asm.Mov.Imm(asm.R4, 0),                           // r4 = 0
		asm.Mov.Imm(asm.R5, 0),                           // r5 = 0
	)

	return insts, nil
}
