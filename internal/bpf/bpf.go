package bpf

import (
	"context"

	"github.com/cilium/ebpf"
)

type Meta struct {
	IsIngress bool
	TimeNs    uint64
	Address   uint64

	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TcIndex        uint32
	Cb             [5]uint32
}

type Skb struct {
	Meta
	Data []byte
}

type LoadOptions struct {
	Filter    string
	BpfConfig BpfConfig
}

type BpfConfig struct {
	SkbTrack bool
}

type BpfObjects interface {
	Load(LoadOptions) error
	IngressFilter() *ebpf.Program
	EgressFilter() *ebpf.Program
	PollSkb(context.Context) (<-chan Skb, error)
}
