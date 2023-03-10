package main

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

func withTcnl(fn func(nl *tc.Tc) error) (err error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("failed to open rtnl socket: %w", err)
	}
	defer func() {
		if e := tcnl.Close(); e != nil {
			err = fmt.Errorf("failed to close rtnl socket: %w", err)
		}
	}()

	return fn(tcnl)
}

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func prepareTcObjMsgIngress(ifindex int) tc.Msg {
	var msg tc.Msg

	protocol := htons(unix.ETH_P_ALL)

	msg.Family = unix.AF_UNSPEC
	msg.Ifindex = uint32(ifindex)
	msg.Parent = core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress)
	msg.Handle = core.BuildHandle(tc.HandleRoot, 1)
	msg.Info = getConfig().Priority<<16 | uint32(protocol)

	return msg
}

func prepareTcObjMsgEgress(ifindex int) tc.Msg {
	var msg tc.Msg

	protocol := htons(unix.ETH_P_ALL)

	msg.Family = unix.AF_UNSPEC
	msg.Ifindex = uint32(ifindex)
	msg.Parent = core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)
	msg.Handle = core.BuildHandle(tc.HandleRoot, 2)
	msg.Info = getConfig().Priority<<16 | uint32(protocol)

	return msg
}

func getTcQdiscObj(ifindex int) *tc.Object {
	msg := prepareTcObjMsgEgress(ifindex)
	msg.Handle = core.BuildHandle(tc.HandleRoot, 0)
	msg.Parent = tc.HandleIngress

	return &tc.Object{
		Msg: msg,
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
}

func replaceTcQdisc(ifindex int) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Qdisc().Replace(getTcQdiscObj(ifindex))
	})
}

func deleteTcQdisc(ifindex int) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Qdisc().Delete(getTcQdiscObj(ifindex))
	})
}

func getTcFilterIngressObj(ifindex int, prog *ebpf.Program) *tc.Object {
	var obj tc.Object

	progFD := uint32(prog.FD())
	annotation := "tcdump.o:[on_ingress]"

	obj.Msg = prepareTcObjMsgIngress(ifindex)
	obj.Attribute.Kind = "bpf"
	obj.Attribute.BPF = new(tc.Bpf)
	obj.Attribute.BPF.FD = &progFD
	obj.Attribute.BPF.Name = &annotation

	return &obj
}

func addTcFilterIngress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Add(getTcFilterIngressObj(ifindex, prog))
	})
}

func deleteTcFilterIngress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Delete(getTcFilterIngressObj(ifindex, prog))
	})
}

func getTcFilterEgressObj(ifindex int, prog *ebpf.Program) *tc.Object {
	var obj tc.Object

	progFD := uint32(prog.FD())
	annotation := "tcdump.o:[on_egress]"

	obj.Msg = prepareTcObjMsgEgress(ifindex)
	obj.Attribute.Kind = "bpf"
	obj.Attribute.BPF = new(tc.Bpf)
	obj.Attribute.BPF.FD = &progFD
	obj.Attribute.BPF.Name = &annotation

	return &obj
}

func addTcFilterEgress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Add(getTcFilterEgressObj(ifindex, prog))
	})
}

func deleteTcFilterEgress(ifindex int, prog *ebpf.Program) error {
	return withTcnl(func(nl *tc.Tc) error {
		return nl.Filter().Delete(getTcFilterEgressObj(ifindex, prog))
	})
}
