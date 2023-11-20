package kaddr

import (
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/utils"
)

type Kaddr struct {
	Addr uint64

	kp link.Link
}

func GetKaddrs(addrs string) (kaddrs []*Kaddr, err error) {
	if addrs == "" {
		return
	}
	for _, addr := range strings.Split(addrs, ",") {
		if strings.HasPrefix(addr, "0x") {
			addr = addr[2:]
		}
		a, err := strconv.ParseUint(addr, 16, 64)
		if err != nil {
			return nil, err
		}
		kaddrs = append(kaddrs, &Kaddr{Addr: a})
	}
	return
}

func (ka *Kaddr) Attach(objs bpf.Objects) (err error) {
	ksym, offset := utils.Addr2ksym(ka.Addr)
	ka.kp, err = link.Kprobe(ksym, objs.KprobeTid(), &link.KprobeOptions{Offset: offset})
	return
}

func (ka *Kaddr) Detach() (err error) {
	if ka.kp != nil {
		ka.kp.Close()
	}
	return
}
