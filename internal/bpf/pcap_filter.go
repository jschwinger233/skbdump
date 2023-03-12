package bpf

import (
	"bufio"
	"bytes"
	"fmt"
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

func dumpPcapFilterBpf(exp string) (insts []bpf.Instruction, err error) {
	out, err := exec.Command("tcpdump", "-dd", exp).Output()
	if err != nil {
		return nil, errors.Wrapf(err, "invalid pcap filter expression: %s", exp)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		inst, err := newBpfInstruction(scanner.Text())
		if err != nil {
			return nil, err
		}
		insts = append(insts, inst)
	}
	return insts, errors.WithStack(scanner.Err())
}
