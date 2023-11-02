package kfunc

import (
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/pkg/errors"
)

type Kfunc struct {
	Fname string

	kp, krp link.Link
}

func GetSkbfuncs(kfnames string) (kfuncs []*Kfunc, err error) {
	if kfnames == "" {
		return
	}
	for _, kfname := range strings.Split(kfnames, ",") {
		kfuncs = append(kfuncs, &Kfunc{Fname: kfname})
	}
	return
}

func (kf *Kfunc) Attach(objs bpf.Objects) (err error) {
	pos, ok := positions[kf.Fname]
	if !ok {
		return errors.Errorf("invalid kfunc: %s", kf.Fname)
	}
	if kf.kp, err = link.Kprobe(kf.Fname, objs.Kprobe(pos), nil); err != nil {
		return
	}
	kf.krp, err = link.Kretprobe(kf.Fname, objs.Kretprobe(), nil)
	return err
}

func (kf *Kfunc) Detach() error {
	kf.kp.Close()
	kf.krp.Close()
	return nil
}
