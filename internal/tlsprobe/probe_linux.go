package tlsprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/jimyag/socktrail/internal/procname"
)

type Event struct {
	PID      int
	StartNS  uint64
	NetNS    uint64
	Local    netip.AddrPort
	Remote   netip.AddrPort
	Hostname string
	Source   string
	Process  string
}

type Statistics struct {
	Received atomic.Uint64
	Invalid  atomic.Uint64
	Dropped  atomic.Uint64
}

// Start observes SNI only in dynamically linked system OpenSSL. It reads
// SSL_ctrl / SSL_get_servername strings and verifies a socket tuple from an
// OpenSSL fd or a TCP send during SSL_connect. No TLS plaintext or key is copied.
func Start(ctx context.Context, netNS uint64) (<-chan Event, <-chan error, *Statistics, string, error) {
	if runtime.GOARCH != "amd64" {
		return nil, nil, nil, "", fmt.Errorf("OpenSSL probe supports amd64 only")
	}
	path, err := systemOpenSSL()
	if err != nil {
		return nil, nil, nil, "", err
	}
	if err := rlimit.RemoveMemlock(); err != nil { // Kernels before 5.11 charge BPF maps to it.
		return nil, nil, nil, "", fmt.Errorf("remove eBPF memlock limit: %w", err)
	}
	objects := new(TlsObjects)
	if err := LoadTlsObjects(objects, nil); err != nil {
		return nil, nil, nil, "", fmt.Errorf("load OpenSSL eBPF probe: %w", err)
	}
	key := uint32(0)
	if err := objects.TargetNetns.Update(key, netNS, ebpf.UpdateAny); err != nil {
		objects.Close()
		return nil, nil, nil, "", fmt.Errorf("configure OpenSSL probe netns: %w", err)
	}
	executable, err := link.OpenExecutable(path)
	if err != nil {
		objects.Close()
		return nil, nil, nil, "", err
	}
	cryptoPath := strings.Replace(path, "libssl.so", "libcrypto.so", 1)
	crypto, err := link.OpenExecutable(cryptoPath)
	if err != nil {
		objects.Close()
		return nil, nil, nil, "", fmt.Errorf("open matching OpenSSL BIO library %s: %w", cryptoPath, err)
	}
	var links []link.Link
	attach := func(target *link.Executable, symbol string, program *ebpf.Program, returning bool) error {
		var attached link.Link
		var err error
		if returning {
			attached, err = target.Uretprobe(symbol, program, nil)
		} else {
			attached, err = target.Uprobe(symbol, program, nil)
		}
		if err != nil {
			return fmt.Errorf("attach %s on %s: %w", symbol, path, err)
		}
		links = append(links, attached)
		return nil
	}
	cleanup := func() {
		for _, attached := range links {
			attached.Close()
		}
		objects.Close()
	}
	for _, hook := range []struct {
		crypto  bool
		symbol  string
		program *ebpf.Program
		ret     bool
	}{
		{true, "BIO_new_socket", objects.BioNewSocketEnter, false},
		{true, "BIO_new_socket", objects.BioNewSocketReturn, true},
		{true, "BIO_free", objects.BioFreeEnter, false},
		{false, "SSL_set_fd", objects.SetFdEnter, false},
		{false, "SSL_set_fd", objects.SetFdReturn, true},
		{false, "SSL_set0_rbio", objects.Set0RbioEnter, false},
		{false, "SSL_set_bio", objects.SetBioEnter, false},
		{false, "SSL_ctrl", objects.CtrlEnter, false},
		{false, "SSL_ctrl", objects.CtrlReturn, true},
		{false, "SSL_get_servername", objects.GetServernameEnter, false},
		{false, "SSL_get_servername", objects.GetServernameReturn, true},
		{false, "SSL_connect", objects.ConnectEnter, false},
		{false, "SSL_connect", objects.ConnectReturn, true},
		{false, "SSL_do_handshake", objects.HandshakeEnter, false},
		{false, "SSL_free", objects.FreeEnter, false},
	} {
		target := executable
		if hook.crypto {
			target = crypto
		}
		if err := attach(target, hook.symbol, hook.program, hook.ret); err != nil {
			cleanup()
			return nil, nil, nil, "", err
		}
	}
	tcpSend, err := link.AttachTracing(link.TracingOptions{Program: objects.ConnectTcpSend})
	if err != nil {
		cleanup()
		return nil, nil, nil, "", fmt.Errorf("attach OpenSSL TCP socket correlation: %w", err)
	}
	links = append(links, tcpSend)
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		cleanup()
		return nil, nil, nil, "", err
	}
	events := make(chan Event, 1024)
	done := make(chan error, 1)
	stats := new(Statistics)
	go func() {
		<-ctx.Done()
		reader.Close()
	}()
	go func() {
		defer close(events)
		defer cleanup()
		var readErr error
		for {
			record, err := reader.Read()
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				break
			}
			if err != nil {
				readErr = fmt.Errorf("read OpenSSL probe: %w", err)
				break
			}
			var raw TlsEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &raw); err != nil {
				stats.Invalid.Add(1)
				continue
			}
			event, err := decodeEvent(raw)
			if err != nil {
				stats.Invalid.Add(1)
				continue
			}
			stats.Received.Add(1)
			select {
			case events <- event:
			default:
				stats.Dropped.Add(1)
			}
		}
		done <- readErr
	}()
	return events, done, stats, path, nil
}

func decodeEvent(raw TlsEvent) (Event, error) {
	var local, remote netip.Addr
	switch raw.Family {
	case 4:
		local = netip.AddrFrom4([4]byte(raw.LocalIp[:4]))
		remote = netip.AddrFrom4([4]byte(raw.RemoteIp[:4]))
	case 6:
		local = netip.AddrFrom16(raw.LocalIp)
		remote = netip.AddrFrom16(raw.RemoteIp)
	default:
		return Event{}, fmt.Errorf("invalid OpenSSL socket family %d", raw.Family)
	}
	if raw.LocalPort == 0 || raw.RemotePort == 0 || !local.IsValid() || !remote.IsValid() {
		return Event{}, fmt.Errorf("incomplete OpenSSL socket tuple")
	}
	var name []byte
	for _, c := range raw.Hostname {
		if c == 0 {
			break
		}
		b := byte(c)
		if b < 33 || b > 126 || b == '/' || b == ':' || b == '\\' {
			return Event{}, fmt.Errorf("invalid OpenSSL hostname")
		}
		name = append(name, b)
	}
	if len(name) == 0 || len(name) > 253 {
		return Event{}, fmt.Errorf("invalid OpenSSL hostname length")
	}
	source := "openssl_set_sni"
	if raw.Source == 2 {
		source = "openssl_get_servername"
	} else if raw.Source != 1 {
		return Event{}, fmt.Errorf("invalid OpenSSL hostname source")
	}
	return Event{
		PID: int(raw.Pid), StartNS: raw.StartNs, NetNS: raw.Netns,
		Local:    netip.AddrPortFrom(local.Unmap(), raw.LocalPort),
		Remote:   netip.AddrPortFrom(remote.Unmap(), raw.RemotePort),
		Hostname: strings.ToLower(strings.TrimSuffix(string(name), ".")), Source: source,
		Process: procname.Clean(bytesFromInt8(raw.Comm[:])),
	}, nil
}

func bytesFromInt8(value []int8) []byte {
	result := make([]byte, len(value))
	for i, b := range value {
		result[i] = byte(b)
	}
	return result
}

func systemOpenSSL() (string, error) {
	for _, pattern := range []string{
		"/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib64/libssl.so.3", "/usr/lib64/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1", "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib64/libssl.so.1.1", "/usr/lib64/libssl.so.1.1",
	} {
		path, err := filepath.EvalSymlinks(pattern)
		if err == nil {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("system libssl.so.3/1.1 not found")
}
