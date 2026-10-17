package main

// The install script must locate its sources relative to itself, work from any
// working directory and only reach the system through the tools it finds. In
// these tests every tool that could change the machine is replaced by a fake
// that only logs its arguments, so a run under root installs nothing.

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const installScriptName = "install-service.sh"

// installScriptFixture is a copy of the release layout the script expects, plus
// a working directory that holds none of it and a PATH full of fake tools.
type installScriptFixture struct {
	t   *testing.T
	dir string // Holds install-service.sh, packaging/socktrail.service, socktrail.
	cwd string // A different, empty directory to run the script from.
	bin string // Fakes for id, install, sudo and systemctl.
	log string // One line per faked call.
	env []string
}

func newInstallScriptFixture(t *testing.T) *installScriptFixture {
	t.Helper()
	dir := t.TempDir()
	copyInstallFixtureFile(t, installScriptName, filepath.Join(dir, installScriptName), 0o755)
	if err := os.MkdirAll(filepath.Join(dir, "packaging"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyInstallFixtureFile(t, filepath.Join("packaging", "socktrail.service"),
		filepath.Join(dir, "packaging", "socktrail.service"), 0o644)
	writeInstallFixtureFile(t, filepath.Join(dir, "socktrail"), "#!/bin/sh\nexit 0\n", 0o755)

	bin := t.TempDir()
	writeInstallFixtureFile(t, filepath.Join(bin, "id"), "#!/bin/sh\necho \"${FAKE_UID:-1000}\"\n", 0o755)
	// None of the fakes resolves or writes a real path: they append their argv
	// to the log and leave the machine alone, root or not.
	for _, name := range []string{"install", "sudo", "systemctl"} {
		body := "#!/bin/sh\nprintf '" + name + " %s\\n' \"$*\" >> \"$FAKE_LOG\"\n"
		if name == "sudo" {
			body += "if [ \"$1\" = install ]; then [ \"$#\" -eq 9 ] && [ -f \"$8\" ] || exit 64; fi\n"
		} else if name == "install" {
			body += "[ \"$#\" -eq 8 ] && [ -f \"$7\" ] || exit 64\n"
		}
		if name == "systemctl" {
			// A stopped unit unless the test says otherwise; is-active is a
			// query, not a change.
			body += "if [ \"$1\" = is-active ]; then\n"
			body += "  [ \"${FAKE_ACTIVE:-0}\" = 1 ] && exit 0\n"
			body += "  exit 3\nfi\n"
		}
		body += "exit 0\n"
		writeInstallFixtureFile(t, filepath.Join(bin, name), body, 0o755)
	}
	return &installScriptFixture{
		t:   t,
		dir: dir,
		cwd: t.TempDir(),
		bin: bin,
		log: filepath.Join(t.TempDir(), "calls.log"),
	}
}

// run executes the script from the fixture's own working directory.
func (f *installScriptFixture) run(args ...string) (stdout, stderr string, code int) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(f.dir, installScriptName))
	cmd.Args = append(cmd.Args, args...)
	cmd.Dir = f.cwd
	cmd.Env = f.withFakePath()
	cmd.Env = append(cmd.Env, f.env...)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		f.t.Fatalf("%s timed out; stderr:\n%s", installScriptName, errBuf.String())
	}
	if err == nil {
		return out.String(), errBuf.String(), 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		f.t.Fatalf("run %s: %v; stderr:\n%s", installScriptName, err, errBuf.String())
	}
	return out.String(), errBuf.String(), exit.ExitCode()
}

// withFakePath puts the fake tools first. It rebuilds the environment instead of
// appending to os.Environ, where a duplicate PATH or FAKE_LOG would otherwise
// win over the values this fixture needs.
func (f *installScriptFixture) withFakePath() []string {
	env := []string{
		"PATH=" + f.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_LOG=" + f.log,
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "FAKE_") {
			continue
		}
		env = append(env, entry)
	}
	return env
}

// calls returns the faked calls, one per line. A rejected run makes none.
func (f *installScriptFixture) calls() []string {
	f.t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		f.t.Fatal(err)
	}
	log := strings.TrimSpace(string(data))
	if log == "" {
		return nil
	}
	return strings.Split(log, "\n")
}

// wantCall fails unless the script made exactly this call.
func (f *installScriptFixture) wantCall(want string) {
	f.t.Helper()
	for _, call := range f.calls() {
		if call == want {
			return
		}
	}
	f.t.Errorf("missing call %q in:\n%s", want, strings.Join(f.calls(), "\n"))
}

func (f *installScriptFixture) wantNoCall(substr string) {
	f.t.Helper()
	for _, call := range f.calls() {
		if strings.Contains(call, substr) {
			f.t.Errorf("unexpected call %q, wanted none matching %q", call, substr)
		}
	}
}

func TestInstallServiceRunsFromAnotherDirectory(t *testing.T) {
	f := newInstallScriptFixture(t)
	// The script must use its own directory: the working directory holds none
	// of the sources, so a cwd-relative script would find nothing.
	if _, err := os.Stat(filepath.Join(f.cwd, "packaging")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the working directory is not empty: %v", err)
	}

	stdout, stderr, code := f.run()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	f.wantCall("sudo install -o root -g root -m 0755 " +
		filepath.Join(f.dir, "socktrail") + " /usr/local/bin/socktrail")
	f.wantCall("sudo install -o root -g root -m 0644 " +
		filepath.Join(f.dir, "packaging", "socktrail.service") +
		" /etc/systemd/system/socktrail.service")
	f.wantCall("sudo systemctl daemon-reload")
	f.wantCall("sudo systemctl enable --now socktrail.service")
	if !strings.Contains(stdout, "enabled and started") {
		t.Errorf("stdout does not report a start:\n%s", stdout)
	}
	// The fixture reports uid 1000, so everything privileged goes through sudo.
	for _, call := range f.calls() {
		if strings.Contains(call, "is-active") {
			continue // A query, deliberately unprivileged.
		}
		if !strings.HasPrefix(call, "sudo ") {
			t.Errorf("call %q skipped sudo for a non-root caller", call)
		}
	}
}

func TestInstallServiceAcceptsBinaryWithSpaces(t *testing.T) {
	f := newInstallScriptFixture(t)
	binary := filepath.Join(t.TempDir(), "my socktrail")
	writeInstallFixtureFile(t, binary, "#!/bin/sh\nexit 0\n", 0o755)

	stdout, stderr, code := f.run("--binary", binary)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	f.wantCall("sudo install -o root -g root -m 0755 " + binary + " /usr/local/bin/socktrail")
	// The default binary next to the script is not involved.
	f.wantNoCall(filepath.Join(f.dir, "socktrail"))
	if !strings.Contains(stdout, "enabled and started") {
		t.Errorf("stdout does not report a start:\n%s", stdout)
	}
}

func TestInstallServiceSkipsSudoWhenRoot(t *testing.T) {
	f := newInstallScriptFixture(t)
	f.env = append(f.env, "FAKE_UID=0")

	_, stderr, code := f.run()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	f.wantCall("install -o root -g root -m 0755 " +
		filepath.Join(f.dir, "socktrail") + " /usr/local/bin/socktrail")
	f.wantCall("systemctl enable --now socktrail.service")
	f.wantNoCall("sudo")
}

func TestInstallServiceNoEnableDoesNotStart(t *testing.T) {
	f := newInstallScriptFixture(t)
	stdout, stderr, code := f.run("--no-enable")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	f.wantCall("sudo systemctl daemon-reload")
	f.wantNoCall("enable")
	if !strings.Contains(stdout, "installed without enabling") {
		t.Errorf("stdout does not report an install-only run:\n%s", stdout)
	}
}

func TestInstallServiceLeavesRunningServiceAlone(t *testing.T) {
	f := newInstallScriptFixture(t)
	f.env = append(f.env, "FAKE_ACTIVE=1")

	stdout, stderr, code := f.run()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr)
	}
	f.wantCall("systemctl is-active --quiet socktrail.service")
	f.wantCall("sudo systemctl enable socktrail.service")
	f.wantNoCall("restart")
	if !strings.Contains(stdout, "sudo systemctl restart socktrail.service") {
		t.Errorf("stdout does not point at the restart the user has to run:\n%s", stdout)
	}
}

func TestInstallServiceRejectsUnusableInput(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(t *testing.T, dir string)
		args     []string
		exit     int
		stderrIn string
	}{
		{
			name: "missing binary",
			prepare: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "socktrail")); err != nil {
					t.Fatal(err)
				}
			},
			exit: 1, stderrIn: "no executable at",
		},
		{
			// -x alone accepts a directory, so the script has to reject it.
			name: "binary is a directory",
			prepare: func(t *testing.T, dir string) {
				path := filepath.Join(dir, "socktrail")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			exit: 1, stderrIn: "no executable at",
		},
		{
			name: "binary is not executable",
			prepare: func(t *testing.T, dir string) {
				if err := os.Chmod(filepath.Join(dir, "socktrail"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			exit: 1, stderrIn: "no executable at",
		},
		{
			name: "missing service template",
			prepare: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "packaging", "socktrail.service")); err != nil {
					t.Fatal(err)
				}
			},
			exit: 1, stderrIn: "no service template at",
		},
		{
			name: "binary flag without a value",
			args: []string{"--binary"},
			exit: 2, stderrIn: "missing value for --binary",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallScriptFixture(t)
			if tc.prepare != nil {
				tc.prepare(t, f.dir)
			}
			_, stderr, code := f.run(tc.args...)
			if code != tc.exit {
				t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, tc.exit, stderr)
			}
			if !strings.Contains(stderr, tc.stderrIn) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tc.stderrIn)
			}
			if calls := f.calls(); len(calls) != 0 {
				t.Errorf("a rejected run still called %v", calls)
			}
		})
	}
}

func copyInstallFixtureFile(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	writeInstallFixtureFile(t, target, string(data), mode)
}

// writeInstallFixtureFile writes content and forces the mode, so a restrictive
// umask cannot turn the fakes into files the script may not execute.
func writeInstallFixtureFile(t *testing.T, target, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(target, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", target, err)
	}
	if err := os.Chmod(target, mode); err != nil {
		t.Fatalf("chmod %s: %v", target, err)
	}
}
