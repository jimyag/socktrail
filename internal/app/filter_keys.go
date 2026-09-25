package app

import (
	"cmp"
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
// filterMenuTitle heads the filter menu before a word is typed; its footer
// gives the rest of the syntax.
const filterMenuTitle = "filter by key:value, or type any word to search connection text"

const filterSyntax = "space-separated conditions must all match; key:value, !key:value negates, * and ? glob; a word without a key searches text"

// filterValue is a value seen for a filter key and how many connections
// carry it.
type filterValue struct {
	value string
	count int
}

// filterValues collects the values the connections offer for each key, and
// how many connections have each, so the filter menu shows what is on
// screen. Keys with a fixed list keep it, with zero counts for unseen values.
func filterValues(c *collector, processes *processTable) map[string][]filterValue {
	counts := make(map[string]map[string]int)
	var seen map[string]bool // Values already counted for this connection.
	add := func(key, value string) {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, " \t") || seen[key+":"+value] {
			return // A value with a space cannot be written in a filter.
		}
		seen[key+":"+value] = true
		if counts[key] == nil {
			counts[key] = make(map[string]int)
		}
		if _, ok := counts[key][value]; ok || len(counts[key]) < 500 {
			counts[key][value]++
		}
	}
	if c != nil {
		for _, f := range c.allFlows() {
			seen = make(map[string]bool)
			add("proto", strings.ToLower(flowProtocol(f)))
			add("app", strings.ToLower(f.AppProtocol))
			add("state", f.TCPState)
			add("dir", f.Direction)
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
			add("fail", strconv.FormatBool(f.Health.ConnectResult != 0 || f.ICMPError != ""))
		}
	}
	values := make(map[string][]filterValue)
	for _, k := range filterKeys {
		for _, v := range k.values {
			if _, ok := counts[k.name][v]; !ok {
				values[k.name] = append(values[k.name], filterValue{value: v})
			}
		}
	}
	for key, set := range counts {
		for value, count := range set {
			values[key] = append(values[key], filterValue{value, count})
		}
		slices.SortFunc(values[key], func(a, b filterValue) int {
			return cmp.Or(cmp.Compare(b.count, a.count), cmp.Compare(a.value, b.value))
		})
	}
	return values
}

// filterItem is one line of the filter menu: the word it completes to, and
// what it means.
type filterItem struct {
	word   string // Replaces the word being typed, such as user: or user:alice.
	label  string
	detail string
}

// filterWord splits the input at its last word, and that word's negation.
func filterWord(input string) (before, negation, word string) {
	start := strings.LastIndexAny(input, " \t") + 1
	before, word = input[:start], input[start:]
	if strings.HasPrefix(word, "!") {
		negation, word = "!", word[1:]
	}
	return before, negation, word
}

// filterMenu lists what the word being typed can become: the keys it
// starts, or the values of the key it names. title explains the list.
func filterMenu(input string, values map[string][]filterValue) (items []filterItem, title string) {
	_, _, word := filterWord(input)
	key, value, keyed := strings.Cut(word, ":")
	if !keyed {
		for _, k := range filterKeys {
			if !strings.HasPrefix(k.name, strings.ToLower(word)) {
				continue
			}
			detail := k.usage
			if len(k.values) > 0 {
				detail += " (" + strings.Join(k.values, ", ") + ")"
			}
			items = append(items, filterItem{word: k.name + ":", label: k.name + ":" + k.value, detail: detail})
		}
		if word == "" {
			return items, filterMenuTitle
		}
		if len(items) == 0 {
			return nil, "no key starts with " + strconv.Quote(word) + "; the word searches connection text"
		}
		return items, "keys starting with " + strconv.Quote(word)
	}
	k := lookupFilterKey(strings.ToLower(key))
	if k == nil {
		return nil, "unknown key " + strconv.Quote(key) + "; keys: " + filterKeyNames()
	}
	for _, v := range values[k.name] {
		if !strings.HasPrefix(strings.ToLower(v.value), strings.ToLower(value)) {
			continue
		}
		detail := "not on current connections"
		if v.count == 1 {
			detail = "1 connection"
		} else if v.count > 1 {
			detail = strconv.Itoa(v.count) + " connections"
		}
		items = append(items, filterItem{word: key + ":" + v.value, label: v.value, detail: detail})
	}
	title = k.name + ":" + k.value + "  " + k.usage
	if len(items) == 0 && value == "" {
		title += "; no values seen yet, type one"
	}
	return items, title
}

// acceptFilterItem replaces the word being typed with a menu item, keeping
// its negation; a value is followed by a space for the next condition.
func acceptFilterItem(input string, item filterItem) string {
	before, negation, _ := filterWord(input)
	if !strings.HasSuffix(item.word, ":") {
		return before + negation + item.word + " "
	}
	return before + negation + item.word
}
