package bpf

import (
	"log"
	"unsafe"

	"golang.org/x/net/bpf"
)

/*
#cgo linux LDFLAGS: -lpcap
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

func MustPcapCompile(expr string) (insts []bpf.Instruction) {
	buf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	cptr := C.pcap_open_live(C.CString("lo"), C.int(MAXIMUM_SNAPLEN), C.int(0), C.int(0), buf)
	if cptr == nil {
		log.Fatalf("failed to pcap_open_live: %+v\n", C.GoString(buf))
	}

	var bpfProg pcapBpfProgram

	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if C.pcap_compile(cptr, (*C.struct_bpf_program)(&bpfProg), cexpr, 1, C.bpf_u_int32(0)) < 0 {
		log.Fatalf("failed to pcap_compile: %+v", C.GoString(C.pcap_geterr(cptr)))
	}
	defer C.pcap_freecode((*C.struct_bpf_program)(&bpfProg))

	bpfInsn := (*[bpfInstructionBufferSize]C.struct_bpf_insn)(unsafe.Pointer(bpfProg.bf_insns))[0:bpfProg.bf_len:bpfProg.bf_len]
	for _, v := range bpfInsn {
		insts = append(insts, bpf.RawInstruction{
			Op: uint16(v.code),
			Jt: uint8(v.jt),
			Jf: uint8(v.jf),
			K:  uint32(v.k),
		}.Disassemble())
	}
	return
}
