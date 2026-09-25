package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerNamesFromLocalMetadata(t *testing.T) {
	root := t.TempDir()
	dockerID, podID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	configDir := filepath.Join(root, "docker", "containers", dockerID)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := `{"Name":"/web","Config":{"Labels":{"com.docker.compose.project":"demo","com.docker.compose.service":"api"}}}`
	if err := os.WriteFile(filepath.Join(configDir, "config.v2.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/unused", filepath.Join(logs, "site_default_sidecar-"+podID+".log")); err != nil {
		t.Fatal(err)
	}
	r := &containerNames{dockerRoot: filepath.Join(root, "docker"), podLogDir: logs, entries: make(map[string]containerEntry)}
	table := newProcessTable(t.TempDir())
	table.containers = r
	dockerPath := "/system.slice/docker-" + dockerID + ".scope"
	key, label, info := table.serviceFor(dockerPath)
	if key != dockerPath || label != "web (compose demo/api)" || info == nil || info.Name != "web" || info.ComposeService != "api" {
		t.Fatalf("Docker service = %q, %+v", label, info)
	}
	podPath := "/kubepods/besteffort/pod123/cri-containerd-" + podID + ".scope"
	_, label, info = table.serviceFor(podPath)
	if label != "sidecar (pod default/site)" || info == nil || info.Namespace != "default" || info.Runtime != "containerd" {
		t.Fatalf("Pod service = %q, %+v", label, info)
	}
	missingID := strings.Repeat("c", 64)
	missingPath := "/system.slice/docker-" + missingID + ".scope"
	_, label, info = table.serviceFor(missingPath)
	if label != "docker-"+missingID[:12]+".scope" || info == nil || info.Name != missingID[:12] {
		t.Fatalf("unreadable Docker metadata = %q, %+v", label, info)
	}
	missingDir := filepath.Join(root, "docker", "containers", missingID)
	if err := os.MkdirAll(missingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missingDir, "config.v2.json"), []byte(`{"Name":"/late"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := r.entries["docker:"+missingID]
	entry.checked = time.Now().Add(-31 * time.Second)
	r.entries["docker:"+missingID] = entry
	_, label, _ = table.serviceFor(missingPath)
	if label != "late (docker)" {
		t.Fatalf("metadata retry = %q", label)
	}
	process := participant{PID: 123, StartNS: 456, Name: "httpd"}
	table.procs[process.id()] = &processMeta{Cgroup: dockerPath}
	if row := processJSON(process, table); row.Container == nil || row.Container.Name != "web" || row.Service != "web (compose demo/api)" {
		t.Fatalf("process JSON = %+v", row)
	}
}
