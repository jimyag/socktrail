package app

import (
	"strings"
	"testing"
)

func TestCurrentNetworkNamespace(t *testing.T) {
	ns, err := openNetworkNamespace("")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.file.Close() }()
	if ns.inode == 0 {
		t.Fatal("missing network namespace inode")
	}
	if err := ns.do(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidContainerNamespaceID(t *testing.T) {
	_, err := openNetworkNamespace("container:not-hex-id")
	if err == nil || !strings.Contains(err.Error(), "at least 12 hex") {
		t.Fatalf("error = %v", err)
	}
}
