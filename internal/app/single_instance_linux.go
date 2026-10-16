package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// processLockPath is one fixed path, not one under HOME or XDG_RUNTIME_DIR:
// those differ between the root and unprivileged launch paths that must
// exclude each other, and /run/lock is root-only.
const processLockPath = "/tmp/socktrail.lock"

// errInstanceRunning reports that another socktrail holds the process lock.
var errInstanceRunning = errors.New("another socktrail is already running; use --allow-multiple to run more than one")

// lockProcess takes the whole-process lock with flock, which the kernel
// releases on exit, including a crash, so no stale-lock logic is needed. A nil
// file with no error means the lock file could not be opened at all: a file
// another user owns with restrictive permissions must neither fail the start
// nor let them block root, who can still open and lock it.
func lockProcess(path string) (*os.File, error) {
	file, openErr := openLockFile(path)
	if openErr != nil {
		fmt.Fprintf(os.Stderr, "socktrail: single-instance lock %s: %v; continuing without it\n", path, openErr)
		return nil, nil
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errInstanceRunning
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return file, nil
}

// openLockFile creates the lock file readable by other users, so they can take
// the lock through a read-only descriptor. A symlink at the path is refused
// rather than followed, and an existing file we may not read is an error the
// caller continues from without the lock.
func openLockFile(path string) (*os.File, error) {
	//nolint:gosec // G302: the lock file holds no data; read bits are for other users.
	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o644)
	if err == nil {
		// The umask may have removed the read bits other users need; a failed
		// chmod only weakens the cross-user case.
		_ = file.Chmod(0o644)
		return file, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	//nolint:gosec // G304: the lock path is a fixed constant at the call site.
	file, err = os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return file, nil
}
