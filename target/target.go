package target

import (
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/target/dev"
	"github.com/jschwinger233/skbdump/target/kaddr"
	"github.com/jschwinger233/skbdump/target/kfunc"
	"github.com/jschwinger233/skbdump/utils"
)

type Target interface {
	Attach(bpfObjects bpf.Objects) error
	Detach() error
}

func Parse(netns *utils.Netns, iface, skbfuncs string, addrs string) (targets []Target, err error) {
	devs, err := dev.GetDevices(netns, iface)
	if err != nil {
		return
	}
	for _, dev := range devs {
		targets = append(targets, Target(dev))
	}

	kfuncs, err := kfunc.GetSkbfuncs(skbfuncs)
	if err != nil {
		return
	}
	for _, kfunc := range kfuncs {
		targets = append(targets, Target(kfunc))
	}

	kaddrs, err := kaddr.GetKaddrs(addrs)
	if err != nil {
		return
	}
	for _, kaddr := range kaddrs {
		targets = append(targets, Target(kaddr))
	}
	return
}
