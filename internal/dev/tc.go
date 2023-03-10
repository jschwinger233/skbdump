package dev

import (
	"encoding/binary"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func withTcnl(fn func(nl *tc.Tc) error) (err error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if e := tcnl.Close(); e != nil {
			err = errors.WithStack(e)
		}
	}()

	return fn(tcnl)
}

func (d *Device) EnsureTcQdisc() error {
	return withTcnl(func(nl *tc.Tc) error {
		return errors.WithStack(nl.Qdisc().Replace(&tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(d.Ifindex),
				Handle:  core.BuildHandle(tc.HandleRoot, 0),
				Parent:  tc.HandleIngress,
			},
			Attribute: tc.Attribute{
				Kind: "clsact",
			},
		}))
	})
}

func (d *Device) tcObject(fd int, priority, parent, handle uint32) *tc.Object {
	_fd := uint32(fd)
	return &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(d.Ifindex),
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
			Handle:  core.BuildHandle(tc.HandleRoot, handle),
			Info:    priority<<16 | uint32(htons(unix.ETH_P_ALL)),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD: &_fd,
			},
		},
	}
}

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func (d *Device) AddIngressFilter(prog *ebpf.Program, priority uint32) (del func() error, err error) {
	tcObj := d.tcObject(prog.FD(), priority, tc.HandleMinIngress, 1)
	return func() error {
			return withTcnl(func(nl *tc.Tc) error {
				return nl.Filter().Delete(tcObj)
			})
		}, withTcnl(func(nl *tc.Tc) error {
			return errors.WithStack(nl.Filter().Add(tcObj))
		})
}

func (d *Device) AddEgressFilter(prog *ebpf.Program, priority uint32) (del func() error, err error) {
	tcObj := d.tcObject(prog.FD(), priority, tc.HandleMinEgress, 2)
	return func() error {
			return withTcnl(func(nl *tc.Tc) error {
				return nl.Filter().Delete(tcObj)
			})
		}, withTcnl(func(nl *tc.Tc) error {
			return errors.WithStack(nl.Filter().Add(tcObj))
		})
}
