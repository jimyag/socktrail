package app

import (
	jsonv2 "encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type containerInfo struct {
	Name           string `json:"name"`
	Runtime        string `json:"runtime"`
	Pod            string `json:"pod,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ComposeProject string `json:"compose_project,omitempty"`
	ComposeService string `json:"compose_service,omitempty"`
}

func (c containerInfo) label() string {
	if c.Pod != "" {
		return c.Name + " (pod " + c.Namespace + "/" + c.Pod + ")"
	}
	if c.ComposeService != "" {
		return c.Name + " (compose " + c.ComposeProject + "/" + c.ComposeService + ")"
	}
	return c.Name + " (" + c.Runtime + ")"
}

type containerEntry struct {
	info     containerInfo
	resolved bool
	checked  time.Time
}

type containerNames struct {
	dockerRoot, podLogDir string
	entries               map[string]containerEntry
	pods                  map[string]containerInfo
	podDirMod             time.Time
}

func newContainerNames() *containerNames {
	return &containerNames{dockerRoot: dockerDataRoot(), podLogDir: "/var/log/containers", entries: make(map[string]containerEntry)}
}

func dockerDataRoot() string {
	var config struct {
		DataRoot string `json:"data-root"`
	}
	if data, err := os.ReadFile("/etc/docker/daemon.json"); err == nil && jsonv2.Unmarshal(data, &config) == nil && config.DataRoot != "" {
		return config.DataRoot
	}
	return "/var/lib/docker"
}

func containerIdentity(cgroup string) (string, string) {
	var foundID, foundRuntime string
	for part := range strings.SplitSeq(strings.Trim(cgroup, "/"), "/") {
		for _, prefix := range []struct{ prefix, runtime string }{
			{"docker-", "docker"}, {"cri-containerd-", "containerd"}, {"libpod-", "podman"},
		} {
			if id, ok := strings.CutPrefix(part, prefix.prefix); ok {
				if id, ok = strings.CutSuffix(id, ".scope"); ok && len(id) == 64 && containerID.MatchString(id) {
					foundID, foundRuntime = id, prefix.runtime
				}
			}
		}
		if len(part) == 64 && containerID.MatchString(part) && (strings.Contains(cgroup, "/docker/") || strings.Contains(cgroup, "/kubepods/")) {
			if strings.Contains(cgroup, "/docker/") {
				foundID, foundRuntime = part, "docker"
			} else {
				foundID, foundRuntime = part, "containerd"
			}
		}
	}
	return foundID, foundRuntime
}

func (r *containerNames) lookup(cgroup string) (*containerInfo, bool) {
	id, runtime := containerIdentity(cgroup)
	if id == "" {
		return nil, false
	}
	fallback := containerInfo{Name: id[:12], Runtime: runtime}
	if runtime == "podman" {
		return &fallback, false
	}
	key := runtime + ":" + id
	if entry, ok := r.entries[key]; ok && (entry.resolved || time.Since(entry.checked) < 30*time.Second) {
		return &entry.info, entry.resolved
	}
	if len(r.entries) >= 4096 {
		return &fallback, false
	}
	info, ok := r.read(id, runtime)
	if !ok {
		info = fallback
	}
	r.entries[key] = containerEntry{info: info, resolved: ok, checked: time.Now()}
	return &info, ok
}

func (r *containerNames) read(id, runtime string) (containerInfo, bool) {
	if runtime == "containerd" {
		r.refreshPods()
		info, ok := r.pods[id]
		return info, ok
	}
	//nolint:gosec // G304: id is exactly 64 hex digits; the root is the local Docker data directory.
	file, err := os.Open(filepath.Join(r.dockerRoot, "containers", id, "config.v2.json"))
	if err != nil {
		return containerInfo{}, false
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return containerInfo{}, false
	}
	var config struct {
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if jsonv2.Unmarshal(data, &config) != nil {
		return containerInfo{}, false
	}
	name := strings.TrimPrefix(config.Name, "/")
	if name == "" {
		return containerInfo{}, false
	}
	return containerInfo{
		Name: name, Runtime: "docker", ComposeProject: config.Config.Labels["com.docker.compose.project"],
		ComposeService: config.Config.Labels["com.docker.compose.service"],
	}, true
}

func (r *containerNames) refreshPods() {
	stat, err := os.Stat(r.podLogDir)
	if err != nil || r.pods != nil && stat.ModTime().Equal(r.podDirMod) {
		return
	}
	entries, err := os.ReadDir(r.podLogDir)
	if err != nil {
		return
	}
	r.podDirMod = stat.ModTime()
	r.pods = make(map[string]containerInfo)
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".log")
		if !ok {
			continue
		}
		prefix, id, ok := strings.CutLast(name, "-")
		if !ok || len(id) != 64 || !containerID.MatchString(id) {
			continue
		}
		parts := strings.Split(prefix, "_")
		if len(parts) == 3 && len(r.pods) < 4096 {
			r.pods[id] = containerInfo{Name: parts[2], Runtime: "containerd", Namespace: parts[1], Pod: parts[0]}
		}
	}
}
