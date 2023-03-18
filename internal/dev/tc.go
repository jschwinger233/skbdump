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

var BPF_NAME = "skbdump"

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

func (d *Device) tcObject(fd int, parent uint32) *tc.Object {
	_fd := uint32(fd)
	return &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(d.Ifindex),
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
			Handle:  0,
			Info:    1<<16 | uint32(htons(unix.ETH_P_ALL)),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:   &_fd,
				Name: &BPF_NAME,
			},
		},
	}
}

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func (d *Device) AddIngressFilter(prog *ebpf.Program) (del func() error, err error) {
	return d.addFilter(prog.FD(), tc.HandleMinIngress)
}

func (d *Device) AddEgressFilter(prog *ebpf.Program) (del func() error, err error) {
	return d.addFilter(prog.FD(), tc.HandleMinEgress)
}

func (d *Device) addFilter(fd int, parent uint32) (del func() error, err error) {
	tcObj := d.tcObject(fd, parent)
	return func() error {
			return withTcnl(func(nl *tc.Tc) error {
				return nl.Filter().Delete(tcObj)
			})
		}, withTcnl(func(nl *tc.Tc) error {
			if e := errors.WithStack(nl.Filter().Add(tcObj)); e != nil {
				return e
			}
			objs, e := nl.Filter().Get(&tcObj.Msg)
			if e != nil {
				return errors.WithStack(e)
			}
			for _, obj := range objs {
				if obj.Attribute.BPF != nil && obj.Attribute.BPF.Name != nil && *obj.Attribute.BPF.Name == BPF_NAME {
					tcObj = &obj
					return nil
				}
			}
			return errors.New("skbdump bpf object not found")
		})
}
