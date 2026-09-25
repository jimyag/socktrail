package app

import (
	"testing"
	"unsafe"
)

func TestFlowFits768ByteSizeClass(t *testing.T) {
	// Pointerful allocations over 512 bytes need an 8-byte malloc header.
	if size := unsafe.Sizeof(flow{}); size > 760 {
		t.Fatalf("flow size = %d bytes; exceeds usable 760 bytes in the 768-byte allocation class", size)
	}
}
