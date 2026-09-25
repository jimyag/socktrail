package app

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every documented key parses, and every key the filter accepts is
// documented: the switch in keyedCondition and filterKeys stay in step.
func TestFilterKeysMatchParser(t *testing.T) {
	samples := map[string]string{"N": "443", "ADDR|CIDR": "10.0.0.0/8", "true|false": "true"}
	for _, k := range filterKeys {
		value := samples[k.value]
		if value == "" {
			value = "x"
		}
		if _, err := parseFilter(k.name + ":" + value); err != nil {
			t.Errorf("documented key %s rejected: %v", k.name, err)
		}
		for _, v := range k.values {
			if _, err := parseFilter(k.name + ":" + v); err != nil {
				t.Errorf("completed value %s:%s rejected: %v", k.name, v, err)
			}
		}
	}
	source, err := os.ReadFile("filter.go")
	if err != nil {
		t.Fatal(err)
	}
	_, body, found := strings.Cut(string(source), "func keyedCondition")
	body, _, closed := strings.Cut(body, "\n}\n")
	if !found || !closed {
		t.Fatal("keyedCondition not found in filter.go")
	}
	for _, match := range regexp.MustCompile(`case ([^:]+):`).FindAllStringSubmatch(body, -1) {
		for quoted := range strings.SplitSeq(match[1], ",") {
			if name := strings.Trim(strings.TrimSpace(quoted), `"`); lookupFilterKey(name) == nil {
				t.Errorf("filter key %s is not in filterKeys", name)
			}
		}
	}
	if _, err := parseFilter("usr:alice"); err == nil || !strings.Contains(err.Error(), "user") {
		t.Errorf("unknown key error does not list the keys: %v", err)
	}
}

func TestCompleteFilter(t *testing.T) {
	values := map[string][]string{"user": {"alice", "root"}, "proc": {"curl", "curl-helper"}}
	for _, tc := range []struct {
		input, want string
		candidates  int
	}{
		{"us", "user:", 1},
		{"port:443 !us", "port:443 !user:", 1},
		{"user:a", "user:alice ", 1},
		{"user:", "user:", 2},
		{"proc:c", "proc:curl", 2},
		{"dir:o", "dir:outbound ", 1},
		{"DIR:IN", "DIR:inbound ", 1},
		{"s", "s", 3}, // sport, state, svc.
		{"zz", "zz", 0},
		{"nokey:x", "nokey:x", 0},
		{"", "", len(filterKeys)},
	} {
		got, candidates := completeFilter(tc.input, values)
		if got != tc.want || len(candidates) != tc.candidates {
			t.Errorf("completeFilter(%q) = %q %v, want %q with %d candidates", tc.input, got, candidates, tc.want, tc.candidates)
		}
	}
	for input, want := range map[string]string{
		"":             "port:N  sport:N",
		"us":           "user:NAME|UID effective user of a process",
		"user:":        "user:NAME|UID  effective user of a process  Tab: alice root",
		"x usr:":       `unknown key "usr"; keys: port`,
		"qq":           `no key starts with "qq"`,
		"dir:outbound": "Tab: outbound",
	} {
		if hint := filterHint(input, values, 200); !strings.Contains(hint, want) {
			t.Errorf("filterHint(%q) = %q, want it to contain %q", input, hint, want)
		}
	}
}

// Tab on the filter prompt completes from the values the screen collected.
func TestFilterPromptTab(t *testing.T) {
	u := &terminalUI{filterValues: map[string][]string{"user": {"www-data"}}}
	u.handleKey("/")
	for _, key := range []string{"u", "s", "tab", "w", "tab"} {
		u.handleKey(key)
	}
	if u.filter != "user:www-data " || !u.filtering {
		t.Fatalf("filter %q filtering %v", u.filter, u.filtering)
	}
}

// The manual and -h name every flag and filter key; groff renders the
// manual without warnings when it is installed.
func TestManualAndUsage(t *testing.T) {
	flags := newTestFlags().set
	var manual, usage strings.Builder
	if err := writeManual(&manual, flags); err != nil {
		t.Fatal(err)
	}
	writeUsage(&usage, flags)
	for _, text := range []string{manual.String(), usage.String()} {
		flags.VisitAll(func(f *flag.Flag) {
			if !strings.Contains(strings.ReplaceAll(text, `\-`, "-"), f.Name) {
				t.Errorf("flag %s missing", f.Name)
			}
		})
		for _, k := range filterKeys {
			if !strings.Contains(text, k.name) {
				t.Errorf("filter key %s missing", k.name)
			}
		}
	}
	if !slices.ContainsFunc(strings.Split(manual.String(), "\n"), func(l string) bool { return l == ".SH SCREEN KEYS" }) {
		t.Error("manual lacks the screen keys")
	}
	if _, err := exec.LookPath("groff"); err != nil {
		return
	}
	path := filepath.Join(t.TempDir(), "socktrail.1")
	if err := os.WriteFile(path, []byte(manual.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), "groff", "-man", "-Tutf8", "-ww", "-z", path).CombinedOutput()
	if err != nil || len(output) > 0 {
		t.Fatalf("groff: %v\n%s", err, output)
	}
}
