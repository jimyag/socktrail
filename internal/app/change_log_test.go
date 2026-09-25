package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChangeLogPermissionsAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changes.ndjson")
	log, err := openChangeLog(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	log.size = maxChangeLogSize
	if _, err := log.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{path: "second\n", path + ".1": "first\n"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Errorf("%s: got %q, want %q", name, data, want)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", name, mode)
		}
	}
}
