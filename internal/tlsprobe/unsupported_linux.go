//go:build linux && !386 && !amd64 && !arm64

package tlsprobe

import (
	"context"
	"fmt"
)

// Start reports that the OpenSSL probe has no program for this
// architecture: uprobes read registers, and objects exist for amd64 and
// arm64 only.
func Start(ctx context.Context, netNS uint64) (<-chan Event, <-chan error, *Statistics, string, error) {
	return nil, nil, nil, "", fmt.Errorf("OpenSSL probe supports amd64 and arm64 only")
}
