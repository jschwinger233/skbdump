package dev

import (
	"net"

	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/utils"
	"github.com/vishvananda/netlink"
)

type Device struct {
	Name    string
	Ifindex int
	Link    netlink.Link
	Netns   *utils.Netns

	delIngress func() error
	delEgress  func() error
}

func GetDevices(netns *utils.Netns, iface string) (devices []*Device, _ error) {
	return devices, netns.Do(func() (err error) {
		links := []netlink.Link{}

		if iface == "any" {
			if links, err = netlink.LinkList(); err != nil {
				return
			}
		} else {
			link, err := netlink.LinkByName(iface)
			if err != nil {
				return err
			}
			links = append(links, link)
		}

		for _, link := range links {
			linkAttrs := link.Attrs()
			devices = append(devices, &Device{
				Name:    linkAttrs.Name,
				Ifindex: linkAttrs.Index,
				Link:    link,
				Netns:   netns,
			})
		}
		return
	})
}

func (d *Device) IsL3Device() bool {
	lladdr := d.Link.Attrs().HardwareAddr
	return (lladdr == nil || len(lladdr) != 6) && !d.IsLoopback()
}

func (d *Device) IsLoopback() bool {
	return d.Link.Attrs().Flags&net.FlagLoopback != 0
}

func (d *Device) Attach(objs bpf.Objects) error {
	return d.Netns.Do(func() (err error) {
		if err = d.EnsureTcQdisc(); err != nil {
			return
		}
		d.delIngress, err = d.AddIngressFilter(objs.TcIngress(!d.IsL3Device()))
		if err != nil {
			return
		}
		d.delEgress, err = d.AddEgressFilter(objs.TcEgress(!d.IsL3Device()))
		return
	})
}

func (d *Device) Detach() error {
	return d.Netns.Do(func() (err error) {
		d.delIngress()
		d.delEgress()
		return
	})
}
