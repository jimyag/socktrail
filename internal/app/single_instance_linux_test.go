package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Two instances in one process are two descriptors on the same file: the
// second must fail while the first holds LOCK_EX, and succeed once it is
// released, with no unlink of the file in between.
func TestLockProcessExcludesSecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.lock")
	first, err := lockProcess(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if first == nil {
		t.Fatal("the first lock should be held")
	}
	if _, err := lockProcess(path); !errors.Is(err, errInstanceRunning) {
		t.Fatalf("second lock = %v, want errInstanceRunning", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := lockProcess(path)
	if err != nil || second == nil {
		t.Fatalf("lock after release = %v, %v", second, err)
	}
	_ = second.Close()
}

// The lock lives in the kernel: a descriptor left open by a process that was
// killed still excludes, and closing it releases. Nothing depends on the
// lock file's contents or existence.
func TestLockProcessDoesNotNeedFileContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socktrail.lock")
	writer, err := lockProcess(path)
	if err != nil || writer == nil {
		t.Fatalf("lock: %v", err)
	}
	// A second descriptor opened read-only sees the same lock.
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("read-only descriptor flock = %v, want EWOULDBLOCK", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("read-only descriptor flock after release: %v", err)
	}
}

// A lock file another user owns with restrictive permissions is not ours to
// fail on: the guard must never turn a permission problem into "already
// running", so lockProcess continues without the lock and says so.
func TestLockProcessSkipsUnreadableLockFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file, so it would take the lock")
	}
	path := filepath.Join(t.TempDir(), "socktrail.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	lock, err := lockProcess(path)
	if err != nil {
		t.Fatalf("lockProcess on an unreadable file = %v, want no lock and no error", err)
	}
	if lock != nil {
		_ = lock.Close()
		t.Fatal("lockProcess should not hold a lock it could not open")
	}
}

// A symlink at the lock path must not be followed: opening it could take a
// lock in a file the user chooses, and a failed start is worse than no guard.
func TestLockProcessRefusesSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "socktrail.lock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	lock, err := lockProcess(path)
	if err != nil || lock != nil {
		t.Fatalf("lockProcess on a symlink = %v, %v; want no lock and no error", lock, err)
	}
}

func TestOpenLockFileRejectsSpecialFiles(t *testing.T) {
	for _, kind := range []string{"fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock")
			if kind == "fifo" {
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				file, err := openLockFile(path)
				if file != nil {
					_ = file.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("accepted a non-regular lock file")
				}
			case <-time.After(2 * time.Second):
				// Unblock a regressed FIFO open before failing the test.
				writer, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				_ = writer.Close()
				<-done
				t.Fatal("opening a non-regular lock file blocked")
			}
		})
	}
}
