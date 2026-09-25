package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// configNone is the --config value that skips the configuration file.
const configNone = "none"

// Flags a configuration file cannot set: they choose the file, or run a
// one-off action and exit.
var unconfigurable = map[string]bool{"config": true, "completion": true, "man": true, "version": true, "download-geoip-db": true, "help": true, "h": true}

// defaultConfigPath is $XDG_CONFIG_HOME/socktrail/config, or
// ~/.config/socktrail/config. Under sudo it is the invoking user's file, as
// the GeoIP directory is.
func defaultConfigPath() (string, error) {
	if os.Geteuid() != 0 {
		if base := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(base) {
			return filepath.Join(base, "socktrail", "config"), nil
		}
	}
	var home string
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		u, err := user.Lookup(os.Getenv("SUDO_USER"))
		if err != nil {
			return "", fmt.Errorf("find sudo user home: %w", err)
		}
		home = u.HomeDir
	} else {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			return "", err
		}
	}
	return filepath.Join(home, ".config", "socktrail", "config"), nil
}

// applyConfig sets the flags the command line left unset from a
// configuration file. path is the --config value: empty for the default
// file, which may be missing, or configNone to read nothing.
func applyConfig(flags *flag.FlagSet, path string) error {
	if path == configNone {
		return nil
	}
	explicit := path != ""
	if !explicit {
		var err error
		if path, err = defaultConfigPath(); err != nil {
			return nil // No home directory, so no default file.
		}
	}
	//nolint:gosec // G304: the path is the user's own --config or default configuration file.
	file, err := os.Open(path)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("config: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := checkConfigOwner(path, info); err != nil {
		return err
	}
	settings, err := parseConfig(bufio.NewScanner(file), path, flags)
	if err != nil {
		return err
	}
	fromCommandLine := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { fromCommandLine[f.Name] = true })
	for _, s := range settings {
		if fromCommandLine[s.name] {
			continue // The command line wins, and replaces repeatable values.
		}
		if err := flags.Set(s.name, s.value); err != nil {
			return fmt.Errorf("%s:%d: %s: %w", path, s.line, s.name, err)
		}
	}
	return nil
}

// checkConfigOwner refuses a file someone else could have written: socktrail
// often runs as root, and the file chooses what it reads and writes.
func checkConfigOwner(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config: %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config: %s is writable by group or others; run chmod go-w on it", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	owners := []uint32{uint32(os.Geteuid()), 0} //nolint:gosec // G115: a UID fits in 32 bits.
	if uid, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32); err == nil && os.Geteuid() == 0 {
		owners = append(owners, uint32(uid))
	}
	if slices.Contains(owners, stat.Uid) {
		return nil
	}
	return fmt.Errorf("config: %s belongs to UID %d, not to you or root", path, stat.Uid)
}

type configSetting struct {
	name, value string
	line        int
}

// parseConfig reads one flag per line: "name value" or "name = value", with
// or without leading dashes, and "name" alone for a true boolean. Blank
// lines and lines starting with # are skipped; a value may be quoted.
// Repeating a repeatable flag, such as interface, adds values.
func parseConfig(scanner *bufio.Scanner, path string, flags *flag.FlagSet) ([]configSetting, error) {
	var settings []configSetting
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimLeft(line, "-")
		name, value, hasValue := strings.Cut(line, "=")
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name, value, hasValue = line[:i], line[i+1:], true
			value = strings.TrimPrefix(strings.TrimSpace(value), "=")
		}
		name, value = strings.TrimSpace(name), unquote(strings.TrimSpace(value))
		f := flags.Lookup(name)
		switch {
		case f == nil:
			return nil, fmt.Errorf("%s:%d: unknown flag %q", path, n, name)
		case unconfigurable[name]:
			return nil, fmt.Errorf("%s:%d: %s cannot be set in a configuration file", path, n, name)
		case !hasValue && !isBoolFlag(f):
			return nil, fmt.Errorf("%s:%d: %s needs a value", path, n, name)
		case !hasValue:
			value = "true"
		}
		settings = append(settings, configSetting{name: name, value: value, line: n})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return settings, nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}
