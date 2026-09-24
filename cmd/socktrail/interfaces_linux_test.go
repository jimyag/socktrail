package main

import (
	"net"
	"strings"
	"testing"
)

func TestDefaultInterfacesIncludesHostAndTunnelLinks(t *testing.T) {
	up := net.FlagUp | net.FlagRunning
	interfaces := []net.Interface{
		{Name: "lo", Flags: up | net.FlagLoopback},
		{Name: "br0", Flags: up},
		{Name: "dae0", Flags: up},
		{Name: "tailscale0", Flags: up | net.FlagPointToPoint},
		{Name: "docker0", Flags: up},
		{Name: "br-abcdef", Flags: up},
		{Name: "veth123", Flags: up},
		{Name: "eno1", Flags: net.FlagUp},
	}
	names, err := defaultInterfaces(interfaces)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(names, ","), "br0,dae0,lo,tailscale0"; got != want {
		t.Fatalf("interfaces = %q, want %q", got, want)
	}
}

func TestDefaultInterfacesFailsWhenTooMany(t *testing.T) {
	interfaces := make([]net.Interface, maxCaptureInterfaces+1)
	for i := range interfaces {
		interfaces[i] = net.Interface{Name: "host" + string(rune('a'+i)), Flags: net.FlagUp | net.FlagRunning}
	}
	if _, err := defaultInterfaces(interfaces); err == nil {
		t.Fatal("expected an error instead of silently omitting an interface")
	}
}
