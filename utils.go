package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var kallsymsByAddr map[uint64]string = make(map[uint64]string)

func init() {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		kallsymsByAddr[addr] = fmt.Sprintf(">%s", parts[2])
		kallsymsByAddr[addr-1] = fmt.Sprintf("<%s", parts[2])
	}
	kallsymsByAddr[0] = "<"
	kallsymsByAddr[1] = ">"
}

func ksym(addr uint64) string {
	return kallsymsByAddr[addr]
}
