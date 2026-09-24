package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/jimyag/socktrail/internal/kernelbtf"
	"github.com/jimyag/socktrail/internal/procname"
)

// StartEmbedded attaches the compiled eBPF probes. The executable contains
// their bytecode and does not invoke a separate tracing process at runtime.
// Events come in batches, each what the ring held when it was read.
func StartEmbedded(ctx context.Context, netNS uint64, port uint16) (<-chan []Event, <-chan error, *Statistics, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("remove eBPF memlock limit: %w", err)
	}
	spec, err := LoadBpf()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read embedded eBPF programs: %w", err)
	}
	// Only one accept probe loads: __inet_accept exists from Linux 6.8, and
	// inet_csk_accept took a different signature in 6.10.
	if kernelbtf.Params("__inet_accept") >= 0 {
		delete(spec.Programs, "tcp_accept_exit")
	} else {
		delete(spec.Programs, "inet_accept_entry")
	}
	kernelbtf.KeepRecvmsgVariants(spec, "tcp_recv_exit", "udp_recv_exit", "udpv6_recv_exit")
	// Hooks that exist only on some kernels: generic_splice_sendpage is gone
	// from 6.5, where splice sends through tcp_sendmsg and is counted there.
	for program, function := range map[string]string{"splice_send_exit": "generic_splice_sendpage", "splice_recv_exit": "tcp_splice_read", "tcp_retransmit_exit": "tcp_retransmit_skb", "tcp_loss_probe_exit": "tcp_send_loss_probe"} {
		if kernelbtf.Params(function) < 0 {
			delete(spec.Programs, program)
		}
	}
	// Kernel TLS sockets move data through the tls module. Its hooks load
	// only when the module is loaded at start; one loaded later goes unseen.
	for program, function := range map[string]string{
		"ktls_send_exit": "tls_sw_sendmsg", "ktls_device_send_exit": "tls_device_sendmsg",
		"ktls_recv_exit": "tls_sw_recvmsg", "ktls_recv_exit_old": "tls_sw_recvmsg",
		"ktls_splice_recv_exit": "tls_sw_splice_read",
	} {
		if kernelbtf.ModuleParams("tls", function) < 0 {
			delete(spec.Programs, program)
		}
	}
	if kernelbtf.ModuleParams("tls", "tls_sw_recvmsg") == 6 { // With nonblock, before 5.19.
		delete(spec.Programs, "ktls_recv_exit")
	} else {
		delete(spec.Programs, "ktls_recv_exit_old")
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load embedded eBPF programs (need BTF and CAP_BPF/CAP_PERFMON): %w", err)
	}
	key := uint32(0)
	if err := objects.Maps["settings"].Update(key, BpfConfig{Netns: netNS, Port: port}, ebpf.UpdateAny); err != nil {
		objects.Close()
		return nil, nil, nil, fmt.Errorf("configure eBPF network namespace: %w", err)
	}
	var links []link.Link
	for name, program := range objects.Programs {
		attached, err := link.AttachTracing(link.TracingOptions{Program: program})
		if err != nil {
			for _, previous := range links {
				previous.Close()
			}
			objects.Close()
			if runtime.GOARCH == "arm64" && errors.Is(err, ebpf.ErrNotSupported) {
				// arm64 attaches fentry/fexit through ftrace direct calls, new in 6.4.
				return nil, nil, nil, fmt.Errorf("attach eBPF probe %s: %w (arm64 needs Linux 6.4 or later)", name, err)
			}
			return nil, nil, nil, fmt.Errorf("attach eBPF probe %s: %w", name, err)
		}
		links = append(links, attached)
	}
	reader, err := ringbuf.NewReader(objects.Maps["events"])
	if err != nil {
		for _, attached := range links {
			attached.Close()
		}
		objects.Close()
		return nil, nil, nil, fmt.Errorf("open eBPF event ring: %w", err)
	}
	// Up to 16 batches of 1024 events wait for the consumer: the ring is read
	// in bursts, which one event at a time would not absorb.
	const maxBatch = 1024
	events := make(chan []Event, 16)
	done := make(chan error, 1)
	stats := new(Statistics)
	pollCtx, stopPoll := context.WithCancel(ctx)
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				var lost uint64
				if err := objects.Maps["lost"].Lookup(key, &lost); err == nil {
					stats.KernelLost.Store(lost)
				}
			case <-pollCtx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		reader.Close()
	}()
	go func() {
		defer close(events)
		defer objects.Close()
		defer func() {
			for _, attached := range links {
				attached.Close()
			}
		}()
		var readErr error
		var record ringbuf.Record // Reused: every event is copied out of it.
		var batch []Event
		send := func() {
			if len(batch) == 0 {
				return
			}
			select {
			case events <- batch:
			default:
				stats.Dropped.Add(uint64(len(batch)))
			}
			batch = nil
		}
		for {
			// The program wakes the reader only once events pile up; the
			// deadline drains the ring at least this often.
			reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
			err := reader.ReadInto(&record)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				send() // Everything pending has been read.
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				break
			}
			if err != nil {
				readErr = fmt.Errorf("read eBPF event ring: %w", err)
				break
			}
			if len(record.RawSample) < int(unsafe.Sizeof(BpfEvent{})) {
				stats.Invalid.Add(1)
				continue
			}
			// The program wrote the struct in the generated layout; reflection
			// through encoding/binary cost a tenth of the CPU under load.
			event, err := decodeEvent(*(*BpfEvent)(unsafe.Pointer(&record.RawSample[0])))
			if err != nil {
				stats.Invalid.Add(1)
				continue
			}
			stats.Received.Add(1)
			if batch = append(batch, event); record.Remaining == 0 || len(batch) == maxBatch {
				send()
			}
		}
		send()
		var lost uint64
		stopPoll()
		<-pollDone
		if err := objects.Maps["lost"].Lookup(key, &lost); err == nil {
			stats.KernelLost.Store(lost)
		}
		done <- readErr
	}()
	return events, done, stats, nil
}

func decodeEvent(raw BpfEvent) (Event, error) {
	var local, remote netip.Addr
	switch raw.Family {
	case 4:
		local = netip.AddrFrom4([4]byte(raw.LocalIp[:4]))
		remote = netip.AddrFrom4([4]byte(raw.RemoteIp[:4]))
	case 6:
		local = netip.AddrFrom16(raw.LocalIp)
		remote = netip.AddrFrom16(raw.RemoteIp)
	default:
		return Event{}, fmt.Errorf("invalid eBPF address family %d", raw.Family)
	}
	role := "out"
	if raw.Role == 2 {
		role = "in"
	} else if raw.Role != 1 {
		return Event{}, fmt.Errorf("invalid eBPF socket role %d", raw.Role)
	}
	if raw.Protocol != 6 && raw.Protocol != 17 && raw.Protocol != 1 && raw.Protocol != 58 {
		return Event{}, fmt.Errorf("invalid eBPF protocol %d", raw.Protocol)
	}
	operation := map[uint8]string{1: "connect", 2: "accept", 3: "send", 4: "recv", 5: "retransmit"}[raw.Operation]
	if operation == "" {
		return Event{}, fmt.Errorf("invalid eBPF operation %d", raw.Operation)
	}
	name := make([]byte, 0, len(raw.Comm))
	for _, c := range raw.Comm {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	return Event{
		Protocol:      raw.Protocol,
		Family:        int(raw.Family),
		Role:          role,
		Operation:     operation,
		AppBytes:      raw.AppBytes,
		PID:           int(raw.Pid),
		StartNS:       raw.StartNs,
		Process:       procname.Clean(name),
		ParentPID:     int(raw.Ppid),
		ParentStartNS: raw.ParentStartNs,
		CgroupID:      raw.CgroupId,
		NetNS:         raw.Netns,
		Local:         netip.AddrPortFrom(local.Unmap(), raw.LocalPort),
		Remote:        netip.AddrPortFrom(remote.Unmap(), raw.RemotePort),
		TCP: TCPInfo{
			RTT: time.Duration(raw.SrttUs) * time.Microsecond, RTTVar: time.Duration(raw.RttvarUs) * time.Microsecond,
			Cwnd: raw.SndCwnd, SegsOut: raw.DataSegsOut, Retransmits: raw.TotalRetrans,
		},
	}, nil
}
