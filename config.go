package main

import (
	"log"
	"strings"

	"github.com/jschwinger233/skbdump/bpf"
	flag "github.com/spf13/pflag"
)

type Config struct {
	Iface         string
	SkbTrack      bool
	SkbFilename   string
	PcapFilename  string
	PcapFilterExp string
}

var (
	config     Config
	bpfObjects bpf.BpfObjects
)

func mustInitConfig() {
	flag.StringVarP(&config.Iface, "interface", "i", "lo", "interface to capture")
	flag.StringVarP(&config.SkbFilename, "skb-filename", "s", "skbdump.meta", "output skb filename")
	flag.StringVarP(&config.PcapFilename, "pcap-filename", "w", "skbdump.pcap", "output pcap filename")
	flag.BoolVarP(&config.SkbTrack, "skb-track", "t", false, "track skb by address")
	flag.Parse()
	config.PcapFilterExp = strings.Join(flag.Args(), " ")

	var err error
	bpfObjects, err = bpf.New()
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
