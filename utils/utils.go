package utils

import (
	"fmt"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type Symbol struct {
	Type string
	Name string
	Addr uint64
}

var kallsyms []Symbol
var kallsymsByAddr map[uint64]Symbol = make(map[uint64]Symbol)

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
		typ, name := parts[1], parts[2]
		if typ == "t" || typ == "T" {
			kallsymsByAddr[addr] = Symbol{typ, name, addr}
			kallsymsByAddr[addr-1] = Symbol{typ, fmt.Sprintf("%s+r", name), addr - 1}
			kallsyms = append(kallsyms, kallsymsByAddr[addr], kallsymsByAddr[addr-1])
		}
	}
	kallsymsByAddr[0] = Symbol{"t", "out", 0}
	kallsymsByAddr[1] = Symbol{"t", "in", 1}
	kallsyms = append(kallsyms, kallsymsByAddr[0], kallsymsByAddr[1])
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func Ksym(addr uint64) string {
	return kallsymsByAddr[addr].Name
}

func nearestSymbol(addr uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int {
		if x.Addr > addr {
			return 1
		} else if x.Addr < addr {
			return -1
		}
		return 0
	})
	if idx == len(kallsyms) {
		return kallsyms[idx-1]
	}
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx]
	}
	if idx == 0 {
		return kallsyms[0]
	}
	return kallsyms[idx-1]
}

func Addr2ksym(addr uint64) (ksym string, offset uint64) {
	sym := nearestSymbol(addr)
	return sym.Name, addr - sym.Addr
}
