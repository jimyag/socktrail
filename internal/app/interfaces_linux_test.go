package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultInterfacesSelectsPhysicalLinks(t *testing.T) {
	sysfsNet := t.TempDir()
	for _, name := range []string{"eno1", "wlan0"} {
		if err := os.MkdirAll(filepath.Join(sysfsNet, name, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	up := net.FlagUp | net.FlagRunning
	interfaces := []net.Interface{
		{Name: "lo", Flags: up | net.FlagLoopback},
		{Name: "br0", Flags: up},
		{Name: "dae0", Flags: up},
		{Name: "tailscale0", Flags: up | net.FlagPointToPoint},
		{Name: "br-abcdef", Flags: up},
		{Name: "docker0", Flags: up},
		{Name: "veth123", Flags: up},
		{Name: "vnet0", Flags: up},
		{Name: "tap0", Flags: up},
		{Name: "eno1", Flags: up},
		{Name: "wlan0", Flags: up},
		{Name: "eno2", Flags: net.FlagUp},
	}
	names, omitted, err := defaultInterfaces(interfaces, sysfsNet)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(names, ","), "eno1,wlan0,br0,dae0,lo,tailscale0"; got != want || len(omitted) != 0 {
		t.Fatalf("interfaces = %q, want %q", got, want)
	}
}

func TestExpandInterfacesIncludesAllMatches(t *testing.T) {
	interfaces := make([]net.Interface, 12)
	for i := range interfaces {
		interfaces[i].Name = fmt.Sprintf("veth%02d", i)
	}
	names, err := expandInterfaces(interfaceFlags{"veth*", "veth01"}, interfaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 12 || names[0] != "veth00" || names[11] != "veth11" {
		t.Fatalf("expanded interfaces = %v", names)
	}
	if _, err := expandInterfaces(interfaceFlags{"tap*"}, interfaces); err == nil {
		t.Fatal("unmatched interface pattern was accepted")
	}
}

func TestInterfaceSetBeyond64(t *testing.T) {
	old := captureInterfaces
	defer func() { captureInterfaces = old }()
	captureInterfaces = make([]string, 67)
	for i := range captureInterfaces {
		captureInterfaces[i] = fmt.Sprintf("eth%d", i)
	}
	var first, second interfaceSet
	first.add(0)
	first.add(65)
	second.add(66)
	merged := first.clone()
	merged.union(second)
	if got, want := interfaceList(merged, 0), "eth0,eth65,eth66"; got != want {
		t.Fatalf("interfaces = %q, want %q", got, want)
	}
	if first.has(66) || !merged.has(66) {
		t.Fatal("merging mutated the source set or lost interface 66")
	}
}

func TestDefaultInterfacesKeepsFirstEight(t *testing.T) {
	sysfsNet := t.TempDir()
	interfaces := make([]net.Interface, maxCaptureInterfaces+1)
	for i := range interfaces {
		name := "host" + string(rune('i'-i))
		interfaces[i] = net.Interface{Name: name, Flags: net.FlagUp | net.FlagRunning}
	}
	if err := os.MkdirAll(filepath.Join(sysfsNet, "hosti", "device"), 0o755); err != nil {
		t.Fatal(err)
	}
	names, omitted, err := defaultInterfaces(interfaces, sysfsNet)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(names, ","), "hosti,hosta,hostb,hostc,hostd,hoste,hostf,hostg"; got != want {
		t.Fatalf("selected = %q, want %q", got, want)
	}
	if got, want := strings.Join(omitted, ","), "hosth"; got != want {
		t.Fatalf("omitted = %q, want %q", got, want)
	}
}
