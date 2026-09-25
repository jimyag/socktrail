package app

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testFlags struct {
	set       *flag.FlagSet
	ifaces    interfaceFlags
	duration  *time.Duration
	filter    *string
	drops     *bool
	sniff     *bool
	limit     *int
	configArg *string
}

func newTestFlags() *testFlags {
	f := &testFlags{set: flag.NewFlagSet("socktrail", flag.ContinueOnError)}
	f.set.Var(&f.ifaces, "interface", "network interfaces to observe (repeatable)")
	f.duration = f.set.Duration("duration", 0, "stop after this duration")
	f.filter = f.set.String("filter", "", "filter displayed flows")
	f.drops = f.set.Bool("drops", false, "aggregate kernel packet drop reasons")
	f.sniff = f.set.Bool("socket-sniff", true, "read first bytes")
	f.limit = f.set.Int("limit", 30, "number of flows to print")
	f.configArg = f.set.String("config", "", "configuration file")
	f.set.String("output", "text", "output format")
	f.set.String("read", "", "read a recording")
	return f
}

func writeConfig(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// The file fills in what the command line left unset; the command line
// replaces, not extends, a repeatable flag the file also sets.
func TestConfigDefaultsYieldToCommandLine(t *testing.T) {
	path := writeConfig(t, `# socktrail defaults
interface eth0
--interface=lo
duration = 30s
filter 'port:443 dir:outbound'
drops
socket-sniff=false
limit 50

`, 0o600)
	f := newTestFlags()
	if err := f.set.Parse([]string{"--limit", "5"}); err != nil {
		t.Fatal(err)
	}
	if err := applyConfig(f.set, path); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.ifaces, ",") != "eth0,lo" || *f.duration != 30*time.Second || *f.filter != "port:443 dir:outbound" || !*f.drops || *f.sniff || *f.limit != 5 {
		t.Fatalf("interfaces %v duration %v filter %q drops %v sniff %v limit %d", f.ifaces, *f.duration, *f.filter, *f.drops, *f.sniff, *f.limit)
	}

	f = newTestFlags()
	if err := f.set.Parse([]string{"--interface", "wlan0"}); err != nil {
		t.Fatal(err)
	}
	if err := applyConfig(f.set, path); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.ifaces, ",") != "wlan0" || *f.limit != 50 {
		t.Fatalf("command-line interfaces %v limit %d", f.ifaces, *f.limit)
	}
}

func TestConfigErrors(t *testing.T) {
	for content, want := range map[string]string{
		"bogus 1\n":             `:1: unknown flag "bogus"`,
		"\n# ok\nduration\n":    ":3: duration needs a value",
		"config /etc/other\n":   ":1: config cannot be set",
		"duration forever\n":    ":1: duration: ",
		"drops = maybe\n":       ":1: drops: ",
		"completion bash\n":     ":1: unknown flag", // Not defined in this set.
		"filter port:[\n":       "",                 // The filter is checked later, by Run.
		"interface eth0 eth1\n": "",
	} {
		f := newTestFlags()
		err := applyConfig(f.set, writeConfig(t, content, 0o600))
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: error %v, want %q", content, err, want)
		}
	}
	if err := applyConfig(newTestFlags().set, writeConfig(t, "drops\n", 0o622)); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("group-writable file: %v", err)
	}
	if err := applyConfig(newTestFlags().set, t.TempDir()); err == nil {
		t.Error("directory accepted as a configuration file")
	}
	if err := applyConfig(newTestFlags().set, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing --config file accepted")
	}
	f := newTestFlags()
	if err := applyConfig(f.set, configNone); err != nil || *f.drops {
		t.Errorf("--config none: %v", err)
	}
}

// Without --config the default file is optional, and found under
// XDG_CONFIG_HOME or the home directory.
func TestDefaultConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_USER", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	f := newTestFlags()
	if err := applyConfig(f.set, ""); err != nil {
		t.Fatalf("missing default file: %v", err)
	}
	dir := filepath.Join(home, ".config", "socktrail")
	if os.Geteuid() != 0 {
		xdg := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", xdg)
		dir = filepath.Join(xdg, "socktrail")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("drops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyConfig(f.set, ""); err != nil || !*f.drops {
		t.Fatalf("default file: drops %v, error %v", *f.drops, err)
	}
}

// Each script names every flag, offers the fixed values, and parses in the
// shells that are installed.
func TestCompletionScripts(t *testing.T) {
	f := newTestFlags()
	for _, shell := range []string{"bash", "zsh", "fish"} {
		var script strings.Builder
		if err := writeCompletion(&script, shell, f.set); err != nil {
			t.Fatal(err)
		}
		f.set.VisitAll(func(fl *flag.Flag) {
			if !strings.Contains(script.String(), fl.Name) {
				t.Errorf("%s script lacks %s", shell, fl.Name)
			}
		})
		if !strings.Contains(script.String(), "text json ndjson") || !strings.Contains(script.String(), "/sys/class/net") && !strings.Contains(script.String(), "_net_interfaces") || !strings.Contains(script.String(), "true false") && shell != "fish" {
			t.Errorf("%s script lacks value completions:\n%s", shell, script.String())
		}
		if _, err := exec.LookPath(shell); err != nil {
			continue
		}
		path := filepath.Join(t.TempDir(), "socktrail."+shell)
		if err := os.WriteFile(path, []byte(script.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.CommandContext(t.Context(), shell, "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", shell, err, output)
		}
	}
	if err := writeCompletion(&strings.Builder{}, "tcsh", f.set); err == nil {
		t.Error("tcsh accepted")
	}
}
