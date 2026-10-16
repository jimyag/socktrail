package app

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPprofDisabledAndInvalidAddresses(t *testing.T) {
	server, err := startPprof("", false)
	if err != nil || server != nil {
		t.Fatalf("disabled pprof = %v, %v", server, err)
	}
	for _, address := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.0.2.1:6060", "127.0.0.1", "127.0.0.1:65536"} {
		if server, err := startPprof(address, false); err == nil || server != nil {
			if server != nil {
				_ = server.Close()
			}
			t.Errorf("accepted pprof address %q", address)
		}
	}
}

func TestPprofEndpointsAndLifecycle(t *testing.T) {
	server, err := startPprof("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/debug/pprof/", http.StatusOK},
		{http.MethodGet, "/debug/pprof/heap", http.StatusOK},
		{http.MethodGet, "/debug/pprof/allocs", http.StatusOK},
		{http.MethodGet, "/debug/pprof/goroutine?debug=1", http.StatusOK},
		{http.MethodPost, "/debug/pprof/heap", http.StatusMethodNotAllowed},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, "/debug/ebpf", http.StatusNotFound},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://"+server.Addr+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != tc.status || len(body) == 0 {
			t.Errorf("%s %s: status=%d, bytes=%d", tc.method, tc.path, resp.StatusCode, len(body))
		}
	}
	if other, err := startPprof(server.Addr, false); err == nil {
		_ = other.Close()
		t.Fatal("accepted an occupied pprof address")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("pprof listener remained open: %v", err)
	}
	_ = listener.Close()
}
