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
	"github.com/jschwinger233/skbdump/dev"
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

	if err = bpfObjects.Load(bpf.LoadOptions{
		Filter:    config.PcapFilterExp,
		BpfConfig: bpf.BpfConfig{SkbTrack: config.SkbTrack},
	}); err != nil {
		return
	}

	devices, err := dev.FindDevices(config.Iface)
	if err != nil {
		return
	}

	for _, device := range devices {
		if err = device.EnsureTcQdisc(); err != nil {
			return
		}

		delIngress, e := device.AddIngressFilter(bpfObjects.IngressFilter())
		if e != nil {
			err = e
			return
		}
		defer delIngress()

		delEgress, e := device.AddEgressFilter(bpfObjects.EgressFilter())
		if e != nil {
			err = e
			return
		}
		defer delEgress()
	}

	f, err := os.Create(config.PcapFilename)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	linktype := layers.LinkTypeEthernet
	if len(devices) == 1 && devices[0].IsL3Device() {
		linktype = layers.LinkTypeRaw
	}
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
	skbChan, err := bpfObjects.PollSkb(ctx)
	if err != nil {
		return
	}
	for skb := range skbChan {
		jb, e := json.Marshal(skb.Meta)
		if e != nil {
			err = errors.WithStack(err)
			return
		}
		skbPrint(skb, linktype)
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      bootTime.Add(time.Duration(skb.Meta.TimeNs)),
			CaptureLength:  len(skb.Data),
			Length:         len(skb.Data),
			InterfaceIndex: int(skb.Meta.Ifindex),
		}
		if _, err = skbw.Write(append(jb, '\n')); err != nil {
			err = errors.WithStack(err)
			return
		}
		if err = pcapw.WritePacket(captureInfo, skb.Data); err != nil {
			err = errors.WithStack(err)
			return
		}

	}
}
