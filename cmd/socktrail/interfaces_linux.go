package main

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

const maxCaptureInterfaces = 8

// defaultInterfaces selects host-facing interfaces in the current network
// namespace. Per-container and VM tap links are omitted to avoid opening many
// duplicate capture sockets on hosts with numerous guests.
func defaultInterfaces(interfaces []net.Interface) ([]string, error) {
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning || iface.Name == "" || isGuestInterface(iface.Name) {
			continue
		}
		names = append(names, iface.Name)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no active host interfaces found; specify --interface <name>")
	}
	if len(names) > maxCaptureInterfaces {
		return nil, fmt.Errorf("found %d active host interfaces (maximum %d); specify up to %d with --interface", len(names), maxCaptureInterfaces, maxCaptureInterfaces)
	}
	return names, nil
}

func isGuestInterface(name string) bool {
	return strings.HasPrefix(name, "veth") ||
		strings.HasPrefix(name, "br-") ||
		strings.HasPrefix(name, "docker") ||
		strings.HasPrefix(name, "vnet") ||
		strings.HasPrefix(name, "ovs-")
}

func resolveInterfaces(specified interfaceFlags) (interfaceFlags, error) {
	if len(specified) != 0 {
		if len(specified) > maxCaptureInterfaces {
			return nil, fmt.Errorf("specify at most %d interfaces", maxCaptureInterfaces)
		}
		return specified, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	names, err := defaultInterfaces(interfaces)
	if err != nil {
		return nil, err
	}
	return interfaceFlags(names), nil
}
