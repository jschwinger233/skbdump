package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-sysinfo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/skbdump/internal/bpf"
	"github.com/jschwinger233/skbdump/internal/dev"
)

func init() {
	initConfig()
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

	bpfObjs, err := bpf.LoadBpfObjects()
	if err != nil {
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

		delIngress, err := device.AddIngressFilter(bpfObjs.OnIngress, config.Priority)
		if err != nil {
			return
		}
		defer delIngress()

		delEgress, err := device.AddEgressFilter(bpfObjs.OnEgress, config.Priority)
		if err != nil {
			return
		}
		defer delEgress()
	}

	f, err := os.Create(config.PcapFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	skbFilename := strings.TrimSuffix(config.PcapFilename, ".pcap") + ".skb"
	skbw, err := os.Create(skbFilename)
	if err != nil {
		log.Fatalf("failed to create skb filename: %+v", err)
	}
	defer skbw.Close()

	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		meta := bpf.SkbdumpSkbMeta{}
		if err := bpfObjs.MetaQueue.LookupAndDelete(nil, &meta); err != nil {
			time.Sleep(time.Millisecond)
			continue
		}
		data := bpf.SkbdumpSkbData{}
		for {
			if err := bpfObjs.DataQueue.LookupAndDelete(nil, &data); err == nil {
				break
			}
			time.Sleep(time.Microsecond)

		}
		jb, err := json.Marshal(meta)
		if err != nil {
			log.Fatalf("failed to marshal json: %+v\n", err)
		}
		fmt.Printf("%s\n", string(jb))
		captureInfo := gopacket.CaptureInfo{
			Timestamp:      bootTime.Add(time.Duration(meta.TimeNs)),
			CaptureLength:  int(data.Len),
			Length:         int(data.Len),
			InterfaceIndex: int(meta.Ifindex),
		}
		if _, err := skbw.Write(append(jb, '\n')); err != nil {
			log.Fatalf("failed to write skb file: %+v", err)
		}
		if err := pcapw.WritePacket(captureInfo, data.Data[:data.Len]); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}
}
