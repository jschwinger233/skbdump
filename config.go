package main

import (
	"log"
	"strings"

	"github.com/jschwinger233/skbdump/bpf"
	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type Config struct {
	Iface         string
	Kfuncs        string
	Kaddrs        string
	OutputFields  []string
	SkbFilename   string
	PcapFilename  string
	PcapFilterExp string

	Netns uint32
}

var (
	config  Config
	bpfObjs bpf.Objects
)

func mustInitConfig() {
	flag.StringVarP(&config.Iface, "interface", "i", "lo", "interface to capture")
	flag.StringVarP(&config.Kfuncs, "kfuncs", "f", "", "skb kfuncs to trace, e.g. \"ip_rcv,icmp_rcv\"")
	flag.StringVarP(&config.Kaddrs, "kaddrs", "a", "", "addresses to trace, e.g. \"0xffffffffa0272110,0xffffffffa0272118\"")
	var outputFields string
	flag.StringVarP(&outputFields, "output-fields", "o", "", "output fields, e.g. mark,cb")
	flag.StringVarP(&config.SkbFilename, "skb-filename", "s", "skbdump.meta", "output skb filename")
	flag.StringVarP(&config.PcapFilename, "pcap-filename", "w", "skbdump.pcap", "output pcap filename")
	flag.Parse()
	if outputFields != "" {
		config.OutputFields = strings.Split(outputFields, ",")
	}
	config.PcapFilterExp = strings.Join(flag.Args(), " ")

	ns, err := netns.Get()
	if err != nil {
		log.Fatalf("Failed to get netns: %+v", err)
	}
	var s unix.Stat_t
	if err = unix.Fstat(int(ns), &s); err != nil {
		return
	}
	config.Netns = uint32(s.Ino)

	bpfObjs, err = bpf.New()
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
