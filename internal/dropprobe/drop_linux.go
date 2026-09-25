package dropprobe

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Sample is an aggregate of kfree_skb calls, not an AF_PACKET capture loss.
type Sample struct {
	NetNS    uint64
	Source   netip.AddrPort
	Target   netip.AddrPort
	Protocol uint8
	Reason   string
	Count    uint64
}

type symbol struct {
	address uint64
	name    string
}

func Start(ctx context.Context, namespaces []uint64) (<-chan []Sample, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove drop probe memlock limit: %w", err)
	}
	objects := new(DropObjects)
	if err := LoadDropObjects(objects, nil); err != nil {
		return nil, fmt.Errorf("load kernel drop probe: %w", err)
	}
	for _, ns := range namespaces {
		if err := objects.Namespaces.Update(ns, uint8(1), ebpf.UpdateAny); err != nil {
			_ = objects.Close()
			return nil, fmt.Errorf("configure drop namespace %d: %w", ns, err)
		}
	}
	attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "kfree_skb", Program: objects.CountDrop})
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("attach kernel drop tracepoint: %w", err)
	}
	var reasons map[uint32]string
	if spec, err := btf.LoadKernelSpec(); err == nil {
		var enum *btf.Enum
		if spec.TypeByName("skb_drop_reason", &enum) == nil {
			reasons = make(map[uint32]string, len(enum.Values))
			for _, value := range enum.Values {
				//nolint:gosec // G115: skb_drop_reason is a 32-bit kernel enum.
				reasons[uint32(value.Value)] = strings.TrimPrefix(value.Name, "SKB_DROP_REASON_")
			}
		}
	}
	symbols := readSymbols()
	cpuCount, err := ebpf.PossibleCPU()
	if err != nil {
		_ = attached.Close()
		_ = objects.Close()
		return nil, fmt.Errorf("count possible CPUs: %w", err)
	}
	updates := make(chan []Sample, 2)
	go func() {
		defer close(updates)
		defer func() { _ = attached.Close() }()
		defer func() { _ = objects.Close() }()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				if batch := drain(objects.Drops, cpuCount, reasons, symbols); len(batch) > 0 {
					updates <- batch
				}
				return
			case <-ticker.C:
				batch := drain(objects.Drops, cpuCount, reasons, symbols)
				if len(batch) > 0 {
					select {
					case updates <- batch:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return updates, nil
}

func drain(m *ebpf.Map, cpuCount int, reasons map[uint32]string, symbols []symbol) []Sample {
	var batch []Sample
	var keys []DropDropKey
	values := make([]uint64, cpuCount)
	iter := m.Iterate()
	var key DropDropKey
	for iter.Next(&key, &values) {
		var count uint64
		for _, value := range values {
			count += value
		}
		if count == 0 {
			continue
		}
		keys = append(keys, key)
		batch = append(batch, decode(key, count, reasons, symbols))
	}
	for _, key := range keys {
		_ = m.Delete(key)
	}
	return batch
}

func decode(key DropDropKey, count uint64, reasons map[uint32]string, symbols []symbol) Sample {
	reason := reasons[key.Reason]
	if reason == "" || reason == "NOT_SPECIFIED" {
		reason = locationName(key.Location, symbols)
	}
	var source, target netip.Addr
	switch key.Family {
	case 4:
		source = netip.AddrFrom4([4]byte(key.Source[:4]))
		target = netip.AddrFrom4([4]byte(key.Target[:4]))
	case 6:
		source = netip.AddrFrom16(key.Source).Unmap()
		target = netip.AddrFrom16(key.Target).Unmap()
	}
	return Sample{NetNS: key.Netns, Source: netip.AddrPortFrom(source, key.SourcePort), Target: netip.AddrPortFrom(target, key.TargetPort), Protocol: key.Protocol, Reason: reason, Count: count}
}

func readSymbols() []symbol {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var result []symbol
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) < 3 {
			continue
		}
		address, err := strconv.ParseUint(fields[0], 16, 64)
		if err == nil && address != 0 {
			result = append(result, symbol{address, fields[2]})
		}
	}
	slices.SortFunc(result, func(a, b symbol) int { return cmp.Compare(a.address, b.address) })
	return result
}

func locationName(address uint64, symbols []symbol) string {
	if address == 0 {
		return "NOT_SPECIFIED"
	}
	i, _ := slices.BinarySearchFunc(symbols, address, func(s symbol, address uint64) int { return cmp.Compare(s.address, address) })
	if i < len(symbols) && symbols[i].address == address {
		return symbols[i].name
	}
	if i > 0 {
		return symbols[i-1].name
	}
	return fmt.Sprintf("0x%x", address)
}
