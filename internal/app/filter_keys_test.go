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

func TestFilterMenu(t *testing.T) {
	values := map[string][]filterValue{
		"user": {{"root", 7}, {"alice", 2}},
		"dir":  {{"outbound", 5}, {"inbound", 0}, {"local", 0}},
	}
	words := func(items []filterItem) []string {
		var out []string
		for _, item := range items {
			out = append(out, item.word)
		}
		return out
	}
	for _, tc := range []struct {
		input, title string
		words        []string
	}{
		{"us", `keys starting with "us"`, []string{"user:"}},
		{"port:443 !s", `keys starting with "s"`, []string{"sport:", "state:", "svc:"}},
		{"user:", "user:NAME|UID  effective user of a process", []string{"user:root", "user:alice"}},
		{"USER:A", "user:NAME|UID  effective user of a process", []string{"USER:alice"}},
		{"dir:", "dir:NAME  direction of the connection", []string{"dir:outbound", "dir:inbound", "dir:local"}},
		{"host:", "host:NAME  Host, SNI, proxy target or DNS name; no values seen yet, type one", nil},
		{"usr:", `unknown key "usr"; keys: port`, nil},
		{"qq", `no key starts with "qq"`, nil},
	} {
		items, title := filterMenu(tc.input, values)
		if !strings.HasPrefix(title, tc.title) || !slices.Equal(words(items), tc.words) {
			t.Errorf("filterMenu(%q) = %q %v, want %q %v", tc.input, title, words(items), tc.title, tc.words)
		}
	}
	if items, title := filterMenu("", values); title != filterMenuTitle || len(items) != len(filterKeys) || items[0].label != "port:N" || !strings.Contains(items[7].detail, "outbound") {
		t.Errorf("empty input menu: %q %+v", title, items)
	}
	if items, _ := filterMenu("user:", values); items[0].detail != "7 connections" {
		t.Errorf("value detail %q", items[0].detail)
	}
	if items, _ := filterMenu("dir:", values); items[1].detail != "not on current connections" {
		t.Errorf("unseen fixed value detail %q", items[1].detail)
	}
	for input, want := range map[string]string{
		"port:443 !us": "port:443 !user:",
		"user:a":       "user:alice ",
	} {
		items, _ := filterMenu(input, values)
		if got := acceptFilterItem(input, items[len(items)-1]); got != want {
			t.Errorf("accept on %q = %q, want %q", input, got, want)
		}
	}
}

// / opens the menu of every key; ↑↓ move the highlight, Tab takes it, and
// typing narrows the list again from its top.
func TestFilterPromptMenu(t *testing.T) {
	u := &terminalUI{filterValues: map[string][]filterValue{"user": {{"root", 3}, {"www-data", 1}}}}
	u.handleKey("/")
	lines := u.filterMenuLines(120, 60)
	if len(lines) != len(filterKeys)+3 || !strings.Contains(lines[1], filterMenuTitle) || !strings.Contains(lines[2], "port:N") {
		t.Fatalf("menu on /:\n%s", strings.Join(lines, "\n"))
	}
	for _, key := range []string{"u", "s", "tab", "down", "tab"} {
		u.handleKey(key)
	}
	if u.filter != "user:www-data " || !u.filtering {
		t.Fatalf("filter %q filtering %v", u.filter, u.filtering)
	}
	u.handleKey("up")
	if u.filterMenuIndex != len(filterKeys)-1 {
		t.Fatalf("up from the top did not wrap: %d", u.filterMenuIndex)
	}
	u.handleKey("p")
	if u.filterMenuIndex != 0 {
		t.Fatal("typing did not reset the highlight")
	}
	if short := u.filterMenuLines(120, 14); !strings.Contains(short[len(short)-1], "3 of 4 shown") {
		t.Fatalf("small screen footer: %q", short[len(short)-1])
	}
	u.filter = "port:x"
	u.handleKey("enter")
	if !u.filtering || !u.filterSubmitted || u.filterError == "" {
		t.Fatalf("invalid filter applied: %+v", u.filterError)
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
