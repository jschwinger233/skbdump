package main

import (
	"log"
	"strings"

	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/bpf/perf"
	"github.com/jschwinger233/skbdump/bpf/queue"
	flag "github.com/spf13/pflag"
)

type Config struct {
	Iface         string
	PerfOutput    bool
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
	flag.BoolVarP(&config.PerfOutput, "perf-output", "", false, "use bpf_perf_event_output to lift payload size limit")
	flag.StringVarP(&config.SkbFilename, "skb-filename", "s", "skbdump.meta", "output skb filename")
	flag.StringVarP(&config.PcapFilename, "pcap-filename", "w", "skbdump.pcap", "output pcap filename")
	flag.BoolVarP(&config.SkbTrack, "skb-track", "t", false, "track skb by address")
	flag.Parse()
	config.PcapFilterExp = strings.Join(flag.Args(), " ")

	var err error
	if config.PerfOutput {
		bpfObjects, err = perf.New()
	} else {
		bpfObjects, err = queue.New()
	}
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
