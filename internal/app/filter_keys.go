package app

import (
	"slices"
	"strconv"
	"strings"
)

// filterKey documents one key of the structured filter. Help, the manual,
// shell completion and the filter prompt all read this list, so a new key
// appears everywhere once it is added here and to keyedCondition.
type filterKey struct {
	name   string
	value  string   // What the value is, for help.
	usage  string   // What it matches.
	values []string // Fixed values to complete; others come from the connections.
}

var filterKeys = []filterKey{
	{"port", "N", "port of either endpoint", nil},
	{"sport", "N", "port of the initiator", nil},
	{"dport", "N", "port of the target", nil},
	{"ip", "ADDR|CIDR", "address of either endpoint", nil},
	{"proto", "NAME", "IP protocol or EtherType", []string{"tcp", "udp", "icmpv4", "icmpv6", "arp"}},
	{"app", "NAME", "application protocol hint", nil},
	{"state", "NAME", "TCP state, connect error or ICMP error", []string{"syn", "established", "closing", "midstream"}},
	{"dir", "NAME", "direction of the connection", []string{"outbound", "inbound", "local"}},
	{"iface", "NAME", "capture interface", nil},
	{"proc", "NAME", "process name", nil},
	{"pid", "N", "process ID", nil},
	{"svc", "NAME", "service or container of a process", nil},
	{"user", "NAME|UID", "effective user of a process", nil},
	{"host", "NAME", "Host, SNI, proxy target or DNS name", nil},
	{"ja4", "FINGERPRINT", "JA4 fingerprint of the TLS client", nil},
	{"asn", "N", "ASN of either endpoint (needs GeoIP)", nil},
	{"cc", "CODE", "country code of either endpoint (needs GeoIP)", nil},
	{"fail", "true|false", "connect failed or drew an ICMP error", []string{"true", "false"}},
}

func lookupFilterKey(name string) *filterKey {
	for i := range filterKeys {
		if filterKeys[i].name == name {
			return &filterKeys[i]
		}
	}
	return nil
}

func filterKeyNames() string {
	names := make([]string, len(filterKeys))
	for i, k := range filterKeys {
		names[i] = k.name
	}
	return strings.Join(names, " ")
}

// filterSyntax is the one-line summary of the filter language.
const filterSyntax = "space-separated conditions must all match; key:value, !key:value negates, * and ? glob; a word without a key searches text"

// filterValues collects the values the connections offer for keys without
// a fixed list, so the prompt can complete what is actually on screen.
func filterValues(c *collector, processes *processTable) map[string][]string {
	sets := make(map[string]map[string]bool)
	add := func(key, value string) {
		if value == "" || strings.ContainsAny(value, " \t") {
			return // A value with a space cannot be written in a filter.
		}
		if sets[key] == nil {
			sets[key] = make(map[string]bool)
		}
		if len(sets[key]) < 500 {
			sets[key][value] = true
		}
	}
	if c != nil {
		for _, f := range c.allFlows() {
			add("app", strings.ToLower(f.AppProtocol))
			for _, name := range interfacesOf(f.Interfaces) {
				add("iface", name)
			}
			if f.Domain != nil {
				e := f.Domain.Evidence()
				add("host", e.SNI)
				add("host", e.Proxy)
				add("host", e.DNS)
				if e.JA4 != nil {
					add("ja4", *e.JA4)
				}
			}
			for _, p := range flowProcesses(f, c) {
				add("proc", p.Name)
				if processes != nil && p.PID > 0 {
					if uid, name := processes.user(p.id()); uid >= 0 {
						add("user", name)
					}
					_, service := processes.group(p.id(), p.Name, byService)
					add("svc", service)
				}
			}
		}
	}
	values := make(map[string][]string, len(sets))
	for key, set := range sets {
		for value := range set {
			values[key] = append(values[key], value)
		}
		slices.Sort(values[key])
	}
	return values
}

// completeFilter completes the last word of a filter: a key, or a value of
// a known key. It returns the new input, the candidates for that word, and
// a one-line hint about it.
func completeFilter(input string, values map[string][]string) (string, []string) {
	start := strings.LastIndexAny(input, " \t") + 1
	word := input[start:]
	prefix := ""
	if strings.HasPrefix(word, "!") {
		prefix, word = "!", word[1:]
	}
	var candidates []string
	key, value, keyed := strings.Cut(word, ":")
	if !keyed {
		for _, k := range filterKeys {
			if strings.HasPrefix(k.name, strings.ToLower(word)) {
				candidates = append(candidates, k.name+":")
			}
		}
	} else if k := lookupFilterKey(strings.ToLower(key)); k != nil {
		for _, v := range slices.Concat(k.values, values[k.name]) {
			if strings.HasPrefix(strings.ToLower(v), strings.ToLower(value)) && !slices.Contains(candidates, key+":"+v) {
				candidates = append(candidates, key+":"+v)
			}
		}
	}
	switch len(candidates) {
	case 0:
		return input, nil
	case 1:
		completed := candidates[0]
		if !strings.HasSuffix(completed, ":") {
			completed += " "
		}
		return input[:start] + prefix + completed, candidates
	}
	common := candidates[0]
	for _, c := range candidates[1:] {
		for !strings.HasPrefix(strings.ToLower(c), strings.ToLower(common)) {
			common = common[:len(common)-1]
		}
	}
	if len(common) > len(word) {
		return input[:start] + prefix + common, candidates
	}
	return input, candidates
}

// filterHint explains the word being typed: the keys it could start, or
// the key it names and the values seen for it.
func filterHint(input string, values map[string][]string, width int) string {
	word := strings.TrimPrefix(input[strings.LastIndexAny(input, " \t")+1:], "!")
	key, _, keyed := strings.Cut(word, ":")
	var hint strings.Builder
	if keyed {
		k := lookupFilterKey(strings.ToLower(key))
		if k == nil {
			return "unknown key " + strconv.Quote(key) + "; keys: " + filterKeyNames()
		}
		hint.WriteString(k.name + ":" + k.value + "  " + k.usage)
		if _, candidates := completeFilter(input, values); len(candidates) > 0 {
			hint.WriteString("  Tab: ")
			for i, c := range candidates {
				_, v, _ := strings.Cut(c, ":")
				if i > 0 {
					hint.WriteString(" ")
				}
				hint.WriteString(v)
				if hint.Len() > width {
					break
				}
			}
		}
		return hint.String()
	}
	for _, k := range filterKeys {
		if !strings.HasPrefix(k.name, strings.ToLower(word)) {
			continue
		}
		if hint.Len() > 0 {
			hint.WriteString("  ")
		}
		hint.WriteString(k.name + ":" + k.value)
		if word != "" {
			hint.WriteString(" " + k.usage)
		}
	}
	if hint.Len() == 0 {
		return "no key starts with " + strconv.Quote(word) + "; a word without a key searches connection text"
	}
	return hint.String()
}
