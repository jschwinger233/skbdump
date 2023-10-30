package kfunc

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/btf"
)

var positions map[string]int

func init() {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	if positions, err = GetPositions(btfSpec); err != nil {
		log.Fatalf("Failed to get positions: %s", err)
	}
}

func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func GetPositions(spec *btf.Spec) (map[string]int, error) {
	funcs := map[string]int{}

	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iters := []iterator{{"", spec.Iterate()}}

	files, err := os.ReadDir("/sys/kernel/btf")
	if err != nil {
		log.Fatalf("Failed to read directory: %s", err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		module := file.Name()
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s btf: %v", module, err)
		}
		iters = append(iters, iterator{module, modSpec.Iterate()})

	}

	for _, it := range iters {
		for it.iter.Next() {
			typ := it.iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)

			availableFnName := fnName
			if it.kmod != "" {
				availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
			}
			if _, ok := availableFuncs[availableFnName]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i <= 5 {
							name := fnName
							funcs[name] = i
							continue
						}
					}
				}
				i += 1
			}
		}
	}

	return funcs, nil
}
