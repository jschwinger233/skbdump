package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I./headers -I. -Wall

func LoadBpfObjects() (_ *SkbdumpObjects, err error) {
	objs := SkbdumpObjects{}
	return &objs, errors.WithStack(LoadSkbdumpObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize:  ebpf.DefaultVerifierLogSize * 4,
			LogLevel: 2,
		},
	}))
}
