package bpf

import (
	"log"
	"net"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
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

func mustFindUpDevice() string {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("%+v", errors.WithStack(err))
	}

	for _, link := range links {
		if link.Attrs().Flags&net.FlagUp != 0 {
			return link.Attrs().Name
		}
	}
	log.Fatal("cannot find an up device to call pcap_open_live")
	return ""
}

func MustPcapCompile(expr string) (insts []bpf.Instruction) {
	if len(expr) == 0 {
		return
	}

	buf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	cptr := C.pcap_open_live(C.CString(mustFindUpDevice()), C.int(MAXIMUM_SNAPLEN), C.int(0), C.int(0), buf)
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
