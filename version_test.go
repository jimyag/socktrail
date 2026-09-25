package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionDoesNotStartCapture(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "socktrail")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}

	command := exec.CommandContext(t.Context(), binary, "--version")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v\n%s", err, output)
	}
	for _, field := range []string{`"gitTag":`, `"buildTime":`, `"goVersion":`} {
		if !strings.Contains(string(output), field) {
			t.Fatalf("version output %q lacks %s", output, field)
		}
	}
}
