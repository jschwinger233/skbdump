package bpf

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

func newBpfInstruction(inst string) (_ bpf.Instruction, err error) {
	parts := strings.Split(inst, " ")
	if len(parts) != 6 {
		return nil, errors.New(fmt.Sprintf("invalid bpf inst string: `%s`", inst))
	}

	op, err := strconv.ParseUint(strings.TrimPrefix(strings.Trim(parts[1], ","), "0x"), 16, 64)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	jt, err := strconv.ParseUint(strings.Trim(parts[2], ","), 10, 64)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	jf, err := strconv.ParseUint(strings.Trim(parts[3], ","), 10, 64)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	k, err := strconv.ParseUint(strings.TrimPrefix(strings.Trim(parts[4], ","), "0x"), 16, 64)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return bpf.RawInstruction{
		Op: uint16(op),
		Jt: uint8(jt),
		Jf: uint8(jf),
		K:  uint32(k),
	}.Disassemble(), nil
}

func MustGenerateCbpf(exp string) (insts []bpf.Instruction) {
	out, err := exec.Command("tcpdump", "-dd", exp).Output()
	if err != nil {
		log.Fatalf("invalid pcap filter expression `%s`: %+v", exp, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		inst, err := newBpfInstruction(scanner.Text())
		if err != nil {
			log.Fatalf("failed to extract instruction: %+v", err)
		}
		insts = append(insts, inst)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to read tcpdump stdout by line: %+v", err)
	}
	return insts
}
