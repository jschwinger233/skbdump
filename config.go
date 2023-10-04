package main

import (
	"log"
	"strings"

	"github.com/jschwinger233/skbdump/bpf"
	flag "github.com/spf13/pflag"
)

type Config struct {
	Iface         string
	Skbfuncs      string
	SkbTrack      bool
	SkbFilename   string
	PcapFilename  string
	PcapFilterExp string
}

var (
	config  Config
	bpfObjs bpf.Objects
)

func mustInitConfig() {
	flag.StringVarP(&config.Iface, "interface", "i", "lo", "interface to capture")
	flag.StringVarP(&config.Skbfuncs, "skbfuncs", "k", "", "skb kfuncs to trace, e.g. \"ip_rcv,tcp_rcv\"")
	flag.StringVarP(&config.SkbFilename, "skb-filename", "s", "skbdump.meta", "output skb filename")
	flag.StringVarP(&config.PcapFilename, "pcap-filename", "w", "skbdump.pcap", "output pcap filename")
	flag.BoolVarP(&config.SkbTrack, "skb-track", "t", false, "track skb by address")
	flag.Parse()
	config.PcapFilterExp = strings.Join(flag.Args(), " ")

	var err error
	bpfObjs, err = bpf.New()
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
