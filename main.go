package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/jschwinger233/skbdump/internal/dev"
	"github.com/pkg/errors"
)

func init() {
	initConfig()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}
}

func exitWithErr(err error) {
	log.Fatalf("%+v", err)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bpfObjs, err := bpf.LoadBpfObjects(config.PcapFilterExp)
	if err != nil {
		exitWithErr(errors.WithStack(err))
	}

	devices, err := dev.FindDevices(config.Iface)
	if err != nil {
		exitWithErr(errors.WithStack(err))
	}

	for _, device := range devices {
		if err = device.EnsureTcQdisc(); err != nil {
			exitWithErr(errors.WithStack(err))
		}

		delIngress, err := device.AddIngressFilter(bpfObjs.OnIngress, config.Priority)
		if err != nil {
			exitWithErr(errors.WithStack(err))
		}
		defer delIngress()

		delEgress, err := device.AddEgressFilter(bpfObjs.OnEgress, config.Priority)
		if err != nil {
			exitWithErr(errors.WithStack(err))
		}
		defer delEgress()
	}

	f, err := os.Create(config.PcapFilename)
	if err != nil {
		exitWithErr(errors.WithStack(err))
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	linktype := layers.LinkTypeEthernet
	if devices[0].IsL3Device() {
		linktype = layers.LinkTypeRaw
	}
	if err = errors.WithStack(pcapw.WriteFileHeader(1600, linktype)); err != nil {
		exitWithErr(errors.WithStack(err))
	}

	skbw, e := os.Create(config.SkbFilename)
	if e != nil {
		exitWithErr(errors.WithStack(e))
	}
	defer skbw.Close()

	host, err := sysinfo.Host()
	if err != nil {
		exitWithErr(errors.WithStack(err))
	}
	bootTime := host.Info().BootTime

	println("start tracing")
	for {
		meta := bpf.SkbdumpSkbMeta{}
		if err := bpfObjs.MetaQueue.LookupAndDelete(nil, &meta); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
				continue
			}
		}
		data := bpf.SkbdumpSkbData{}
		for {
			if err := bpfObjs.DataQueue.LookupAndDelete(nil, &data); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}
		jb, e := json.Marshal(meta)
		if e != nil {
			err = errors.WithStack(err)
			return
		}
		fmt.Printf("%s\n", string(jb))
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      bootTime.Add(time.Duration(meta.TimeNs)),
			CaptureLength:  int(data.Len),
			Length:         int(data.Len),
			InterfaceIndex: int(meta.Ifindex),
		}
		if _, err = skbw.Write(append(jb, '\n')); err != nil {
			exitWithErr(errors.WithStack(err))
		}
		if err = pcapw.WritePacket(captureInfo, data.Data[:data.Len]); err != nil {
			exitWithErr(errors.WithStack(err))
		}
	}
}
