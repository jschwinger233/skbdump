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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-sysinfo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/skbdump/internal/bpf"
)

func init() {
	initConfig()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	objs := bpf.SkbdumpObjects{}
	if err := bpf.LoadSkbdumpObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize:  ebpf.DefaultVerifierLogSize * 4,
			LogLevel: 2,
		},
	}); err != nil {
		log.Printf("load failed: %+w\n", err)
		return
	}
	defer objs.Close()

	if err := replaceTcQdisc(getConfig().Ifindex); err != nil {
		log.Printf("Failed to replace tc-qdisc for if@%d: %v", getConfig().Ifindex, err)
		return
	}

	if err := addTcFilterIngress(getConfig().Ifindex, objs.OnIngress); err != nil {
		log.Printf("Failed to add tc-filter ingress for if@%d: %v", getConfig().Ifindex, err)
		return
	} else {
		defer deleteTcFilterIngress(getConfig().Ifindex, objs.OnIngress)
	}

	if err := addTcFilterEgress(getConfig().Ifindex, objs.OnEgress); err != nil {
		log.Printf("Failed to add tc-filter egress for if@%d: %v", getConfig().Ifindex, err)
	} else {
		defer deleteTcFilterEgress(getConfig().Ifindex, objs.OnEgress)
	}

	f, err := os.Create(getConfig().PcapFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}
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
		if err := objs.MetaQueue.LookupAndDelete(nil, &meta); err != nil {
			time.Sleep(time.Millisecond)
			continue
		}
		data := bpf.SkbdumpSkbData{}
		for {
			if err := objs.DataQueue.LookupAndDelete(nil, &data); err == nil {
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
		if err := pcapw.WritePacket(captureInfo, data.Data[:data.Len]); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}
}
