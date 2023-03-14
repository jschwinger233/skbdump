package main

import (
	"log"
	"strings"

	"github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/jschwinger233/skbdump/internal/bpf/queue"
	flag "github.com/spf13/pflag"
)

type Config struct {
	Iface         string
	Priority      uint32
	SkbFilename   string
	PcapFilename  string
	PcapFilterExp string
}

var (
	config     Config
	bpfObjects bpf.BpfObjects
)

func initConfig() {
	flag.StringVarP(&config.Iface, "interface", "i", "lo", "interface to capture")
	flag.Uint32VarP(&config.Priority, "priority", "p", 1, "filter priority")
	flag.StringVarP(&config.SkbFilename, "skb-filename", "s", "skbdump.skb", "output skb filename")
	flag.StringVarP(&config.PcapFilename, "pcap-filename", "w", "skbdump.pcap", "output pcap filename")
	flag.Parse()
	config.PcapFilterExp = strings.Join(flag.Args(), " ")

	objs, err := queue.New()
	if err != nil {
		log.Fatalf("%+v", err)
	}
	bpfObjects = objs
}
