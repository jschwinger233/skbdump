package utils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type Netns struct {
	Specifier string

	Inode uint32
	ns    netns.NsHandle
}

func NewNetns(specifier string) (_ *Netns, err error) {
	var ns netns.NsHandle
	switch {
	case specifier == "":
		ns, err = netns.Get()
	case strings.HasPrefix(specifier, "pid:"):
		pid, err := strconv.Atoi(specifier[4:])
		if err != nil {
			break
		}
		ns, err = netns.GetFromPid(pid)
	case strings.HasPrefix(specifier, "path:"):
		ns, err = netns.GetFromPath(specifier[5:])
	default:
		err = fmt.Errorf("invalid netns specifier: %s", specifier)
	}
	if err != nil {
		return
	}

	var s unix.Stat_t
	if err = unix.Fstat(int(ns), &s); err != nil {
		return
	}
	return &Netns{Specifier: specifier, ns: ns, Inode: uint32(s.Ino)}, nil
}

func (n *Netns) Do(f func() error) (err error) {

	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	netns.Set(n.ns)
	defer netns.Set(orig)
	return f()
}
