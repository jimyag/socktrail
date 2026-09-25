package geoip

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMissingDatabaseAndPrivateAddress(t *testing.T) {
	if got := Open("").Status(); !strings.Contains(got, "directory unavailable") {
		t.Fatal(got)
	}
	db := Open(t.TempDir())
	defer db.Close()
	if db.Available() {
		t.Fatal("empty directory reported an available database")
	}
	if !strings.Contains(db.Status(), CountryFile+" missing") || !strings.Contains(db.Status(), ASNFile+" missing") {
		t.Fatal(db.Status())
	}
	for _, ip := range []string{"10.0.0.1", "::1", "fe80::1", "::ffff:192.168.1.1", "8.8.8.8"} {
		if got := db.Lookup(netip.MustParseAddr(ip)); got != nil {
			t.Fatalf("lookup %s = %+v", ip, got)
		}
	}
}

func TestDefaultDirUsesXDGDataHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root uses the invoking sudo user's home")
	}
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", base)
	dir, err := DefaultDir()
	if err != nil || dir != filepath.Join(base, "socktrail", "geoip") {
		t.Fatalf("default directory = %q, %v", dir, err)
	}
}

func TestFailedDownloadPreservesInstalledDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, CountryFile)
	if err := os.WriteFile(path, []byte("old database"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("invalid mmdb"))
		gz.Close()
	}))
	defer server.Close()
	if err := download(context.Background(), dir, server.URL, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), server.Client()); err == nil {
		t.Fatal("invalid database was installed")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old database" {
		t.Fatalf("installed database changed: %q, %v", got, err)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".dbip-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v, %v", matches, err)
	}
}
