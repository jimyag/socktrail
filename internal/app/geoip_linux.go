package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/jimyag/socktrail/internal/geoip"
)

// downloadGeoIP writes the default sudo user's database as that user, so a
// later unprivileged download can replace it. Custom directories keep the
// caller's permissions.
func downloadGeoIP(ctx context.Context, dir string) error {
	defaultDir, err := geoip.DefaultDir()
	if os.Geteuid() != 0 || os.Getenv("SUDO_USER") == "" || err != nil || dir != defaultDir {
		return geoip.Download(ctx, dir)
	}
	owner, err := user.Lookup(os.Getenv("SUDO_USER"))
	if err != nil {
		return fmt.Errorf("find GeoIP directory owner: %w", err)
	}
	uid, err := strconv.ParseUint(owner.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(owner.Gid, 10, 32)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, exe, "--download-geoip-db", "--geoip-dir", dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	cmd.Env = []string{"HOME=" + owner.HomeDir, "PATH=/usr/bin:/bin"}
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"} {
		if value := os.Getenv(key); value != "" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("download GeoIP as %s: %w: %s", owner.Username, err, strings.TrimSpace(string(output)))
	}
	return nil
}
