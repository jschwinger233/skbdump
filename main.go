package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/elastic/go-sysinfo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/skbdump/internal/bpf"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

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

	ifindex, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	if err := replaceTcQdisc(ifindex); err != nil {
		log.Printf("Failed to replace tc-qdisc for if@%d: %v", ifindex, err)
		return
	}

	if err := addTcFilterIngress(ifindex, objs.OnIngress); err != nil {
		log.Printf("Failed to add tc-filter ingress for if@%d: %v", ifindex, err)
		return
	} else {
		defer deleteTcFilterIngress(ifindex, objs.OnIngress)
	}

	if err := addTcFilterEgress(ifindex, objs.OnEgress); err != nil {
		log.Printf("Failed to add tc-filter egress for if@%d: %v", ifindex, err)
	} else {
		defer deleteTcFilterEgress(ifindex, objs.OnEgress)
	}

	f, err := os.Create("/tmp/lo.pcap")
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
		}
		println(meta.IsIngress, data.Len)

		captureInfo := gopacket.CaptureInfo{
			Timestamp:      bootTime.Add(time.Duration(meta.TimeNs)),
			CaptureLength:  int(data.Len),
			Length:         int(data.Len),
			InterfaceIndex: ifindex,
		}
		if err := pcapw.WritePacket(captureInfo, data.Data[:data.Len]); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}
}
