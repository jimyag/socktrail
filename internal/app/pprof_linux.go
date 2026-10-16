package app

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"time"
)

func startPprof(address string, bpfStats bool) (*http.Server, error) {
	if address == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddrPort(address)
	if err != nil || !addr.Addr().IsLoopback() {
		return nil, fmt.Errorf("--pprof needs a loopback IP and port, such as 127.0.0.1:6060 or [::1]:6060")
	}
	listener, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("listen for pprof: %w", err)
	}
	mux := http.NewServeMux()
	if bpfStats {
		mux.HandleFunc("GET /debug/ebpf", serveBPFStats)
	}
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "socktrail: pprof server: %v\n", err)
		}
	}()
	fmt.Fprintf(os.Stderr, "socktrail: pprof listening on http://%s/debug/pprof/\n", server.Addr)
	return server, nil
}
