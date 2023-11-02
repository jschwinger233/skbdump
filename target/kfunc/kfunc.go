package kfunc

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/pkg/errors"
)

type Kfunc struct {
	Fname string

	kp, krp link.Link
}

type SkbKfunc Kfunc
type TidKfunc Kfunc

func GetSkbfuncs(kfnames string) (skbKfuncs []*SkbKfunc, tidKfuncs []*TidKfunc, err error) {
	if kfnames == "" {
		return
	}
	for _, kfname := range strings.Split(kfnames, ",") {
		if _, ok := positions[kfname]; ok {
			skbKfuncs = append(skbKfuncs, &SkbKfunc{Fname: kfname})
		} else {
			fmt.Printf("Cannot find BTF for %s, fallback to TID\n", kfname)
			tidKfuncs = append(tidKfuncs, &TidKfunc{Fname: kfname})
		}
	}
	return
}

func (kf *SkbKfunc) Attach(objs bpf.Objects) (err error) {
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

func (kf *SkbKfunc) Detach() error {
	kf.kp.Close()
	kf.krp.Close()
	return nil
}

func (kf *TidKfunc) Attach(objs bpf.Objects) (err error) {
	if kf.kp, err = link.Kprobe(kf.Fname, objs.KprobeTid(), nil); err != nil {
		return
	}
	kf.krp, err = link.Kretprobe(kf.Fname, objs.Kretprobe(), nil)
	return
}

func (kf *TidKfunc) Detach() (err error) {
	kf.kp.Close()
	kf.krp.Close()
	return nil
}
