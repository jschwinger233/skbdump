package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type skb_meta -type skb_data Skbdump ./skbdump.c -- -I./headers -Wall
