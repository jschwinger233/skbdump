package kfunc

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/skbdump/bpf"
)

type Kfunc struct {
	Fname string

	kprobe, kretprobe func(bpf.Objects) *ebpf.Program
	kp, krp           link.Link
}

func GetSkbfuncs(kfnames string) (kfuncs []*Kfunc, err error) {
	if kfnames == "" {
		return
	}
	for _, kfname := range strings.Split(kfnames, ",") {
		if pos, ok := positions[kfname]; ok {
			kfuncs = append(kfuncs, &Kfunc{
				Fname:     kfname,
				kprobe:    func(o bpf.Objects) *ebpf.Program { return o.Kprobe(pos) },
				kretprobe: func(o bpf.Objects) *ebpf.Program { return o.Kretprobe() }})
		} else {
			fmt.Printf("Cannot find BTF for %s, fallback to TID\n", kfname)
			kfuncs = append(kfuncs, &Kfunc{
				Fname:     kfname,
				kprobe:    func(o bpf.Objects) *ebpf.Program { return o.KprobeTid() },
				kretprobe: func(o bpf.Objects) *ebpf.Program { return o.Kretprobe() },
			})
		}
	}
	kfuncs = append(kfuncs, &Kfunc{
		Fname:  "kfree_skbmem",
		kprobe: func(o bpf.Objects) *ebpf.Program { return o.KprobeKfree() },
	})
	return
}

func (kf *Kfunc) Attach(objs bpf.Objects) (err error) {
	if kf.kprobe != nil {
		if kf.kp, err = link.Kprobe(kf.Fname, kf.kprobe(objs), nil); err != nil {
			return
		}
	}
	if kf.kretprobe != nil {
		if kf.krp, err = link.Kretprobe(kf.Fname, kf.kretprobe(objs), nil); err != nil {
			return
		}
	}
	return
}

func (kf *Kfunc) Detach() error {
	if kf.kp != nil {
		kf.kp.Close()
	}
	if kf.krp != nil {
		kf.krp.Close()
	}
	return nil
}
