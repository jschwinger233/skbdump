package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jschwinger233/skbdump/bpf"
	"github.com/jschwinger233/skbdump/utils"
)

var (
	idx      int
	strfuncs map[string]func([]byte) string
)

func init() {
	strfuncs = map[string]func([]byte) string{
		"Ethernet": stringifyEthernet,
		"ARP":      stringifyARP,
		"IPv4":     stringifyIPv4,
		"IPv6":     stringifyIPv6,
		"UDP":      stringifyUDP,
		"TCP":      stringifyTCP,
		"IPSecESP": stringifyESP,
		"Payload":  stringifyPayload,
	}
}

func skbPrint(skb *bpf.Skbdump, linktype layers.LinkType) {
	idx++
	fmt.Printf("%d %016x ", idx, skb.Meta.Skb)

	ifname, ok := config.ifindex2name[skb.Meta.Ifindex]
	if !ok {
		ifname = "unknown"
	}

	ksym, off := utils.Addr2ksym(skb.Meta.At)
	if off != 0 {
		ksym = fmt.Sprintf("%s+%d", ksym, off)
	}
	fmt.Printf("%s@%d(%s) ", ksym, skb.Meta.Ifindex, ifname)
	if skb.Meta.Ret == 1 {
		fmt.Printf("rv=%x ", skb.Meta.Rax)
	}

	for _, outputField := range config.OutputFields {
		fmt.Printf("%s=%s ", outputField, skb.Field(outputField))
	}

	payload := []byte{}
	if skb.Meta.L2 == 0 {
		for i := 0; i < 12; i++ {
			payload = append(payload, 0)
		}
		ethertype := make([]byte, 2)
		proto, err := strconv.ParseUint(skb.Field("protocol"), 10, 16)
		if err != nil {
			proto = 0
		}
		binary.BigEndian.PutUint16(ethertype, uint16(proto))
		payload = append(payload, ethertype[1], ethertype[0])
	}
	payloadLen := 1500
	if int(skb.Meta.Len) < payloadLen {
		payloadLen = int(skb.Meta.Len)
	}
	payload = append(payload, skb.Payload[:payloadLen]...)
	copy(skb.Payload[:], payload)
	skb.Meta.Len = uint32(len(payload))

	packet := gopacket.NewPacket(payload, layers.LayerTypeEthernet, gopacket.NoCopy)
	layerNum := len(packet.Layers())
	for idx, layer := range packet.Layers() {

		layerType := layer.LayerType().String()
		strfunc, ok := strfuncs[layerType]
		if ok {
			fmt.Printf("%s(%s)", layerType, strfunc(layer.LayerContents()))
		} else {
			fmt.Printf("%s", layerType)
		}

		if idx+1 < layerNum {
			fmt.Printf(" | ")
		} else {
			fmt.Printf("\n")
		}
	}
}

func stringifyEthernet(data []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x>%02x:%02x:%02x:%02x:%02x:%02x",
		data[6], data[7], data[8], data[9], data[10], data[11],
		data[0], data[1], data[2], data[3], data[4], data[5],
	)
}

func stringifyIPv4(data []byte) string {
	src := net.IPv4(data[12], data[13], data[14], data[15])
	dest := net.IPv4(data[16], data[17], data[18], data[19])
	return fmt.Sprintf("%s>%s", src.String(), dest.String())
}

func stringifyARP(data []byte) string {
	if !bytes.Equal(data[:2], []byte{0x0, 0x1}) {
		// hardware type != ethernet
		return ""
	}
	if !bytes.Equal(data[2:4], []byte{0x8, 0x0}) {
		// proto type != ipv4
		return ""
	}
	var senderMac, targetMac [6]byte
	copy(senderMac[:], data[8:14])
	senderIP := net.IPv4(data[14], data[15], data[16], data[17]).String()
	copy(targetMac[:], data[18:24])
	targetIP := net.IPv4(data[24], data[25], data[26], data[27]).String()

	switch data[7] {
	case 1:
		return fmt.Sprintf("who-has %s tell %s", targetIP, senderIP)
	case 2:
		return fmt.Sprintf("%s is-at %02x:%02x:%02x:%02x:%02x:%02x", senderIP, senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5])
	default:
		return ""
	}
	return ""
}

func stringifyIPv6(data []byte) string {
	src := net.IP{data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]}
	dest := net.IP{data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]}
	return fmt.Sprintf("%s>%s", src.To16().String(), dest.To16().String())
}

func stringifyUDP(data []byte) string {
	sport := binary.BigEndian.Uint16(data[:2])
	dport := binary.BigEndian.Uint16(data[2:4])
	return fmt.Sprintf("%d>%d", sport, dport)
}

func stringifyTCP(data []byte) string {
	sport := binary.BigEndian.Uint16(data[:2])
	dport := binary.BigEndian.Uint16(data[2:4])
	flags := []string{}
	if data[13]&0b00100000 != 0 {
		flags = append(flags, "U")
	}
	if data[13]&0b00010000 != 0 {
		flags = append(flags, ".")
	}
	if data[13]&0b00001000 != 0 {
		flags = append(flags, "P")
	}
	if data[13]&0b00000100 != 0 {
		flags = append(flags, "R")
	}
	if data[13]&0b00000010 != 0 {
		flags = append(flags, "S")
	}
	if data[13]&0b00000001 != 0 {
		flags = append(flags, "F")
	}
	seq := binary.BigEndian.Uint32(data[4:8])
	ack := binary.BigEndian.Uint32(data[8:12])
	return fmt.Sprintf("%d>%d,flags=%s,seq=%d,ack=%d", sport, dport, strings.Join(flags, ""), seq%10000, ack%10000)
}

func stringifyESP(data []byte) string {
	spi := binary.BigEndian.Uint32(data[:4])
	seq := binary.BigEndian.Uint32(data[4:8])
	return fmt.Sprintf("spi=%d,seq=%d", spi, seq)
}

func stringifyPayload(data []byte) string {
	return fmt.Sprintf("%d bytes", len(data))
}
