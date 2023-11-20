package main

import (
	"log"
	"strings"

	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/utils"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

type Config struct {
	Iface         string
	Kfuncs        string
	Kaddrs        string
	OutputFields  []string
	SkbFilename   string
	PcapFilename  string
	PcapFilterExp string

	*utils.Netns
	ifindex2name map[uint32]string
}

var (
	config  Config
	bpfObjs bpf.Objects
)

func mustInitConfig() {
	flag.StringVarP(&config.Iface, "interface", "i", "lo", "interface to capture")
	flag.StringVarP(&config.Kfuncs, "kfuncs", "f", "", "kernel functions to trace, e.g. \"ip_rcv,icmp_rcv\"")
	flag.StringVarP(&config.Kaddrs, "kaddrs", "a", "", "kernel addresses to trace, e.g. \"0xffffffffa0272110,0xffffffffa0272118\"")
	var outputFields string
	flag.StringVarP(&outputFields, "output-fields", "o", "", "output fields of skb, e.g. \"mark,cb\"")
	flag.StringVarP(&config.SkbFilename, "skb-filename", "s", "skbdump.meta", "output skb filename")
	flag.StringVarP(&config.PcapFilename, "pcap-filename", "w", "skbdump.pcap", "output pcap filename")
	var netnsSpecifier string
	flag.StringVarP(&netnsSpecifier, "netns", "n", "", "netns specifier, e.g. \"pid:1234\", \"path:/var/run/netns/foo\"")
	flag.Parse()

	var err error
	if config.Netns, err = utils.NewNetns(netnsSpecifier); err != nil {
		log.Fatalf("failed to parse netns: %+v", err)
	}
	if err = config.Netns.Do(func() (err error) {
		config.ifindex2name = make(map[uint32]string)
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			config.ifindex2name[uint32(link.Attrs().Index)] = link.Attrs().Name
		}
		return
	}); err != nil {
		log.Fatalf("failed to get links: %+v", err)
	}

	if outputFields != "" {
		config.OutputFields = strings.Split(outputFields, ",")
	}
	config.PcapFilterExp = strings.Join(flag.Args(), " ")

	if bpfObjs, err = bpf.New(); err != nil {
		log.Fatalf("%+v", err)
	}
}
