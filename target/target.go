package target

import (
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/target/dev"
	"github.com/jschwinger233/skbdump/target/kfunc"
)

type Target interface {
	Attach(bpfObjects bpf.Objects) error
	Detach() error
}

func Parse(iface, skbfuncs string) (targets []Target, err error) {
	devs, err := dev.GetDevices(iface)
	if err != nil {
		return
	}
	for _, dev := range devs {
		targets = append(targets, Target(dev))
	}

	skbKfuncs, tidKfuncs, err := kfunc.GetSkbfuncs(skbfuncs)
	if err != nil {
		return
	}
	for _, kfunc := range skbKfuncs {
		targets = append(targets, Target(kfunc))
	}
	for _, kfunc := range tidKfuncs {
		targets = append(targets, Target(kfunc))
	}
	return
}
