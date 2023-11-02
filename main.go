package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-sysinfo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/target"
	"github.com/pkg/errors"
)

func init() {
	mustInitConfig()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}
}

func main() {
	var err error
	defer func() {
		if err != nil {
			log.Fatalf("%+v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err = bpfObjs.Load(bpf.LoadOptions{
		Filter: config.PcapFilterExp,
		BpfConfig: bpf.BpfConfig{
			Netns:    config.Netns,
			SkbTrack: config.SkbTrack,
		},
	}); err != nil {
		return
	}

	targets, err := target.Parse(config.Iface, config.Kfuncs)
	if err != nil {
		return
	}

	for _, target := range targets {
		if err = target.Attach(bpfObjs); err != nil {
			return
		}
		defer target.Detach()
	}

	f, err := os.Create(config.PcapFilename)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	linktype := layers.LinkTypeEthernet
	// TODO: support l3 device
	//if len(devices) == 1 && devices[0].IsL3Device() {
	//	linktype = layers.LinkTypeRaw
	//}
	if err = errors.WithStack(pcapw.WriteFileHeader(1600, linktype)); err != nil {
		return
	}

	skbw, e := os.Create(config.SkbFilename)
	if e != nil {
		err = errors.WithStack(e)
		return
	}
	defer skbw.Close()

	host, err := sysinfo.Host()
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	bootTime := host.Info().BootTime

	println("start tracing")
	skbChan, err := bpfObjs.PollSkb(ctx)
	if err != nil {
		return
	}
	for skb := range skbChan {
		jb, e := json.Marshal(skb.Meta)
		if e != nil {
			err = errors.WithStack(err)
			return
		}
		skbPrint(&skb, linktype)
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      bootTime.Add(time.Duration(skb.Meta.TimeNs)),
			CaptureLength:  int(skb.Meta.Len),
			Length:         int(skb.Meta.Len),
			InterfaceIndex: int(skb.Meta.Ifindex),
		}
		if _, err = skbw.Write(append(jb, '\n')); err != nil {
			err = errors.WithStack(err)
			return
		}
		if err = pcapw.WritePacket(captureInfo, skb.Payload[:skb.Meta.Len]); err != nil {
			err = errors.WithStack(err)
			return
		}

	}
}

/*
- funcgraph
- l2/l3 tc
*/
