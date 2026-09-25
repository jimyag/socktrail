package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// networkNamespace keeps the namespace file open while its capture sockets
// are created. The inode distinguishes interfaces with the same name.
type networkNamespace struct {
	name  string
	file  *os.File
	inode uint64
}

type captureTarget struct {
	name   string
	device string
	ns     *networkNamespace
}

func resolveCaptureTargets(specs, selected interfaceFlags) ([]captureTarget, []*networkNamespace, error) {
	if len(specs) == 0 {
		specs = interfaceFlags{""}
	}
	var targets []captureTarget
	var namespaces []*networkNamespace
	closeNamespaces := func() {
		for _, ns := range namespaces {
			_ = ns.file.Close()
		}
	}
	seen := make(map[uint64]bool)
	for _, spec := range specs {
		ns, err := openNetworkNamespace(spec)
		if err != nil {
			closeNamespaces()
			return nil, nil, err
		}
		if seen[ns.inode] {
			_ = ns.file.Close()
			continue
		}
		seen[ns.inode] = true
		namespaces = append(namespaces, ns)
		err = ns.do(func() error {
			devices, err := resolveInterfaces(selected)
			if err != nil {
				return err
			}
			for _, device := range devices {
				name := device
				if spec != "" {
					name = ns.name + ":" + device
				}
				targets = append(targets, captureTarget{name: name, device: device, ns: ns})
			}
			return nil
		})
		if err != nil {
			closeNamespaces()
			return nil, nil, fmt.Errorf("list interfaces in %s: %w", ns.name, err)
		}
	}
	return targets, namespaces, nil
}

func openNetworkNamespace(spec string) (*networkNamespace, error) {
	path, name := spec, spec
	switch {
	case spec == "":
		path, name = "/proc/self/ns/net", "current"
	case strings.HasPrefix(spec, "pid:"):
		pid, err := strconv.Atoi(strings.TrimPrefix(spec, "pid:"))
		if err != nil || pid < 1 {
			return nil, fmt.Errorf("invalid network namespace %q", spec)
		}
		path, name = fmt.Sprintf("/proc/%d/ns/net", pid), fmt.Sprintf("pid:%d", pid)
	case strings.HasPrefix(spec, "container:"):
		pid, err := findContainerPID(strings.TrimPrefix(spec, "container:"))
		if err != nil {
			return nil, err
		}
		path, name = fmt.Sprintf("/proc/%d/ns/net", pid), spec
	case !strings.Contains(spec, "/"):
		path = filepath.Join("/run/netns", spec)
	}
	//nolint:gosec // G304: --netns explicitly selects the namespace file to open.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open network namespace %q: %w", spec, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat network namespace %q: %w", spec, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return nil, fmt.Errorf("network namespace %q has no inode", spec)
	}
	return &networkNamespace{name: name, file: file, inode: stat.Ino}, nil
}

func findContainerPID(prefix string) (int, error) {
	if len(prefix) < 12 || len(prefix) > 64 || strings.IndexFunc(prefix, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) >= 0 {
		return 0, fmt.Errorf("container ID %q must be at least 12 hex characters", prefix)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if id, _ := containerIdentity(line); strings.HasPrefix(id, prefix) {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("container %q has no visible process", prefix)
}

// do enters the namespace on one OS thread and always restores that thread.
// This follows ptcpdump's NetNs.Do pattern; the callback opens namespace-bound
// sockets before control returns to the caller's network namespace.
func (ns *networkNamespace) do(fn func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer func() { _ = original.Close() }()
	if info, statErr := original.Stat(); statErr == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Ino == ns.inode {
			return fn()
		}
	}
	if err = unix.Setns(int(ns.file.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter network namespace %s: %w", ns.name, err)
	}
	defer func() {
		if restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			// Returning on this thread would run unrelated work in the target namespace.
			panic(fmt.Sprintf("restore network namespace: %v", restoreErr))
		}
	}()
	return fn()
}
