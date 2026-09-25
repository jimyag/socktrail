package app

import (
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"

	"github.com/jimyag/socktrail/internal/geoip"
)

type condition func(*flow, *collector, *processTable, *geoip.DB, string) bool

// parseFilter compiles the interactive and command-line filter once, rather
// than splitting and interpreting it for every connection on every redraw.
func parseFilter(input string) ([]condition, error) {
	var conditions []condition
	for token := range strings.FieldsSeq(input) {
		negated := strings.HasPrefix(token, "!")
		if negated {
			token = token[1:]
		}
		if token == "" {
			return nil, fmt.Errorf("empty filter condition")
		}
		key, value, keyed := strings.Cut(token, ":")
		var match condition
		if !keyed {
			needle := strings.ToLower(token)
			match = func(f *flow, _ *collector, _ *processTable, _ *geoip.DB, label string) bool {
				return strings.Contains(strings.ToLower(label), needle) || f != nil && flowTextMatches(f, needle)
			}
		} else {
			if value == "" {
				return nil, fmt.Errorf("%s needs a value", key)
			}
			var err error
			match, err = keyedCondition(strings.ToLower(key), value)
			if err != nil {
				return nil, err
			}
		}
		if negated {
			positive := match
			match = func(f *flow, c *collector, p *processTable, g *geoip.DB, label string) bool {
				return !positive(f, c, p, g, label)
			}
		}
		conditions = append(conditions, match)
	}
	return conditions, nil
}

func matchesFilter(conditions []condition, f *flow, c *collector, p *processTable, geo *geoip.DB, label string) bool {
	for _, match := range conditions {
		if !match(f, c, p, geo, label) {
			return false
		}
	}
	return true
}

func filterString(value string) (func(string) bool, error) {
	value = strings.ToLower(value)
	if strings.ContainsAny(value, "*?[") {
		if _, err := path.Match(value, ""); err != nil {
			return nil, fmt.Errorf("invalid filter pattern %q: %w", value, err)
		}
		return func(s string) bool {
			matched, _ := path.Match(value, strings.ToLower(s))
			return matched
		}, nil
	}
	return func(s string) bool { return strings.Contains(strings.ToLower(s), value) }, nil
}

func keyedCondition(key, value string) (condition, error) {
	switch key {
	case "port", "sport", "dport", "pid", "asn":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || key != "asn" && n > 65535 && key != "pid" {
			return nil, fmt.Errorf("invalid %s: %q", key, value)
		}
		return numericCondition(key, n), nil
	case "ip":
		if prefix, err := netip.ParsePrefix(value); err == nil {
			return func(f *flow, _ *collector, _ *processTable, _ *geoip.DB, _ string) bool {
				return prefix.Contains(f.Key.A.Addr().Unmap()) || prefix.Contains(f.Key.B.Addr().Unmap())
			}, nil
		}
		if addr, err := netip.ParseAddr(value); err == nil {
			return func(f *flow, _ *collector, _ *processTable, _ *geoip.DB, _ string) bool {
				return f.Key.A.Addr().Unmap() == addr.Unmap() || f.Key.B.Addr().Unmap() == addr.Unmap()
			}, nil
		}
		return nil, fmt.Errorf("invalid IP or CIDR: %q", value)
	case "fail":
		if value != "true" && value != "false" {
			return nil, fmt.Errorf("fail accepts true or false")
		}
		want := value == "true"
		return func(f *flow, _ *collector, _ *processTable, _ *geoip.DB, _ string) bool {
			return (f.Health.ConnectResult != 0 || f.ICMPError != "") == want
		}, nil
	case "proto", "app", "state", "dir", "iface", "proc", "svc", "host", "cc":
		match, err := filterString(value)
		if err != nil {
			return nil, err
		}
		return stringCondition(key, match), nil
	default:
		return nil, fmt.Errorf("unknown filter key %q", key)
	}
}

func numericCondition(key string, want uint64) condition {
	return func(f *flow, c *collector, _ *processTable, geo *geoip.DB, _ string) bool {
		switch key {
		case "port":
			return uint64(f.Key.A.Port()) == want || uint64(f.Key.B.Port()) == want
		case "sport":
			return uint64(f.Initiator.Port()) == want
		case "dport":
			return uint64(f.Target.Port()) == want
		case "pid":
			for _, p := range flowProcesses(f, c) {
				if uint64(p.PID) == want {
					return true
				}
			}
		case "asn":
			for _, addr := range []netip.Addr{f.Key.A.Addr(), f.Key.B.Addr()} {
				if loc := geo.Lookup(addr); loc != nil && uint64(loc.ASN) == want {
					return true
				}
			}
		}
		return false
	}
}

func stringCondition(key string, match func(string) bool) condition {
	return func(f *flow, c *collector, processes *processTable, geo *geoip.DB, _ string) bool {
		switch key {
		case "proto":
			return match(flowProtocol(f))
		case "app":
			return match(f.AppProtocol)
		case "state":
			return match(flowState(f))
		case "dir":
			return match(f.Direction)
		case "iface":
			for _, name := range interfacesOf(f.Interfaces) {
				if match(name) {
					return true
				}
			}
		case "proc", "svc":
			for _, p := range flowProcesses(f, c) {
				if key == "proc" && match(p.Name) {
					return true
				}
				if key == "svc" && processes != nil {
					_, name := processes.group(p.id(), p.Name, byService)
					if match(name) {
						return true
					}
				}
			}
		case "host":
			if f.Domain != nil {
				e := f.Domain.Evidence()
				return match(e.Label()) || match(e.SNI) || match(e.Proxy) || match(e.DNS)
			}
		case "cc":
			for _, addr := range []netip.Addr{f.Key.A.Addr(), f.Key.B.Addr()} {
				if loc := geo.Lookup(addr); loc != nil && match(loc.CountryCode) {
					return true
				}
			}
		}
		return false
	}
}

func flowTextMatches(f *flow, needle string) bool {
	search := fmt.Sprintf("%s %s %s %s %d %s %d %s %s", f.Key.A, f.Key.B, f.Initiator, f.Target, f.Client.PID, f.Client.Name, f.Server.PID, f.Server.Name, f.AppProtocol)
	if f.Domain != nil {
		e := f.Domain.Evidence()
		search += " " + e.Label() + " " + e.SNI + " " + e.Proxy + " " + e.DNS
	}
	if f.NAT != nil {
		search += " " + f.NAT.String()
	}
	return strings.Contains(strings.ToLower(search), needle)
}
