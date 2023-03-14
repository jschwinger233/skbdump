package dev

import (
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

type Device struct {
	Name    string
	Ifindex int
	Link    netlink.Link
}

func FindDevices(iface string) (devices []Device, err error) {
	links := []netlink.Link{}

	if iface == "any" {
		if links, err = netlink.LinkList(); err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		links = append(links, link)
	}

	for _, link := range links {
		linkAttrs := link.Attrs()
		devices = append(devices, Device{
			Name:    linkAttrs.Name,
			Ifindex: linkAttrs.Index,
			Link:    link,
		})
	}
	return
}

func (d *Device) IsL3Device() bool {
	lladdr := d.Link.Attrs().HardwareAddr
	return (lladdr == nil || len(lladdr) != 6) && !d.IsLoopback()
}

func (d *Device) IsLoopback() bool {
	return d.Link.Attrs().Flags&net.FlagLoopback != 0
}
