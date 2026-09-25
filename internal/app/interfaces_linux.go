package app

import (
	"fmt"
	"maps"
	"math/bits"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const maxCaptureInterfaces = 8

var captureInterfaces []string

// interfaceSet keeps the common first 64 interfaces inline. Explicit capture
// can use any number of interfaces; only those beyond 64 need a map.
type interfaceSet struct {
	first uint64
	extra map[int]struct{}
}

func (s *interfaceSet) add(index int) {
	if index < 64 {
		s.first |= 1 << index
		return
	}
	if s.extra == nil {
		s.extra = make(map[int]struct{})
	}
	s.extra[index] = struct{}{}
}

func (s *interfaceSet) union(other interfaceSet) {
	s.first |= other.first
	for index := range other.extra {
		s.add(index)
	}
}

func (s interfaceSet) clone() interfaceSet {
	return interfaceSet{first: s.first, extra: maps.Clone(s.extra)}
}

func (s interfaceSet) has(index int) bool {
	if index < 64 {
		return s.first&(1<<index) != 0
	}
	_, ok := s.extra[index]
	return ok
}

// interfacesOf names the capture interfaces in set.
func interfacesOf(set interfaceSet) []string {
	var names []string
	for i, name := range captureInterfaces {
		if set.has(i) {
			names = append(names, name)
		}
	}
	return names
}

// interfaceList names the capture interfaces in set for a table cell: up
// to limit of them and a count of the rest, or all of them for limit 0.
func interfaceList(set interfaceSet, limit int) string {
	if len(set.extra) == 0 && bits.OnesCount64(set.first) == 1 && bits.TrailingZeros64(set.first) < len(captureInterfaces) {
		return captureInterfaces[bits.TrailingZeros64(set.first)] // Most flows: no allocation.
	}
	names := interfacesOf(set)
	switch {
	case len(names) == 0:
		return "-"
	case limit > 0 && len(names) > limit:
		return strings.Join(names[:limit], ",") + fmt.Sprintf(" +%d", len(names)-limit)
	}
	return strings.Join(names, ",")
}

// defaultInterfaces prefers active physical links, then host-level virtual
// links. Container and VM child links can be selected explicitly.
func defaultInterfaces(interfaces []net.Interface, sysfsNet string) ([]string, []string, error) {
	var physical, virtual []string
	for _, iface := range interfaces {
		if iface.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning || iface.Name == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(sysfsNet, iface.Name, "device")); err == nil {
			physical = append(physical, iface.Name)
		} else if !isGuestInterface(iface.Name) {
			virtual = append(virtual, iface.Name)
		}
	}
	slices.Sort(physical)
	slices.Sort(virtual)
	names := slices.Concat(physical, virtual)
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("no active capture interfaces found; specify --interface <name>")
	}
	if len(names) > maxCaptureInterfaces {
		return names[:maxCaptureInterfaces], names[maxCaptureInterfaces:], nil
	}
	return names, nil, nil
}

func isGuestInterface(name string) bool {
	for _, prefix := range [...]string{"veth", "br-", "docker", "vnet", "tap", "virbr", "ovs-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func resolveInterfaces(specified interfaceFlags) (interfaceFlags, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	if len(specified) != 0 {
		return expandInterfaces(specified, interfaces)
	}
	names, omitted, err := defaultInterfaces(interfaces, "/sys/class/net")
	if err != nil {
		return nil, err
	}
	if len(omitted) > 0 {
		fmt.Fprintf(os.Stderr, "socktrail: capturing first %d interfaces (physical first); omitted %s (use --interface to choose)\n", maxCaptureInterfaces, strings.Join(omitted, ","))
	}
	return interfaceFlags(names), nil
}

func expandInterfaces(patterns interfaceFlags, interfaces []net.Interface) (interfaceFlags, error) {
	var names interfaceFlags
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		var matched []string
		for _, iface := range interfaces {
			ok, err := path.Match(pattern, iface.Name)
			if err != nil {
				return nil, fmt.Errorf("interface pattern %q: %w", pattern, err)
			}
			if ok {
				matched = append(matched, iface.Name)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("interface pattern %q matched no interfaces", pattern)
		}
		slices.Sort(matched)
		for _, name := range matched {
			if !seen[name] {
				names = append(names, name)
				seen[name] = true
			}
		}
	}
	return names, nil
}
