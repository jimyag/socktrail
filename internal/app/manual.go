package app

import (
	"cmp"
	"flag"
	"fmt"
	"io"
	"strings"
)

// screenKeys are the interactive screen's keys, for the manual.
var screenKeys = [][2]string{
	{"1 2 3 4", "PID, source IP, target IP and protocol pages"},
	{"5", "process groups; b cycles service, cgroup, process tree, executable name and user"},
	{"6", "LOG of connection changes; b cycles change type, process and failure groups"},
	{"7", "listening ports and accept queues"},
	{"d", "domains"},
	{"0", "interfaces; Enter opens the selected one, i cycles them"},
	{"a", "overview of all interfaces merged"},
	{"/", "filter; a menu lists every key, then the values seen for the typed key with their connection counts; Up and Down select, Tab accepts, Enter applies, Esc clears"},
	{"s", "sort by total bytes or by rate"},
	{"g", "show or hide GeoIP, or download it when missing"},
	{"c", "start or stop a PCAPNG recording of the selected connection or PID"},
	{"E", "reveal or hide credential-like environment values in process details"},
	{"Enter", "move focus between the page and the details below it"},
	{"Tab, Shift+Tab", "next or previous page; in the details, the conns and process tabs"},
	{"Up, Down, j, k, PgUp, PgDn", "select rows"},
	{"Left, Right, h, l", "scroll columns"},
	{"?", "help"},
	{"!", "status of probes, capture and GeoIP"},
	{"q, Ctrl-C", "quit"},
}

// roff escapes text for a man page line.
func roff(s string) string {
	s = strings.NewReplacer(`\`, `\e`, "-", `\-`).Replace(s)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// writeManual prints the socktrail(1) manual page, built from the flags and
// filter keys so that it follows them.
func writeManual(w io.Writer, flags *flag.FlagSet) error {
	var m strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&m, format+"\n", args...) }
	line(`.TH SOCKTRAIL 1 "" "socktrail" "User Commands"`)
	line(".nh") // Keep values such as local and midstream whole.
	line(".ad l")
	line(".SH NAME")
	line(`socktrail \- see Linux network traffic, connections, processes and visible domains in one terminal`)
	line(".SH SYNOPSIS")
	line(`.B socktrail`)
	line(`[\fIflags\fR]`)
	line(".SH DESCRIPTION")
	line("socktrail captures packets from selected interfaces with AF_PACKET and uses eBPF socket probes and the kernel socket table to associate local traffic with processes.")
	line("It shows connections, IP traffic, application protocols, and domain names found in observable HTTP, TLS, QUIC, proxy and DNS data.")
	line("Without \\fB\\-\\-duration\\fR or \\fB\\-\\-output ndjson\\fR it runs an interactive screen; see \\fBSCREEN KEYS\\fR.")
	line("Capture and the probes need root, or the file capabilities that \\fBtask install\\fR sets.")

	line(".SH OPTIONS")
	flags.VisitAll(func(f *flag.Flag) {
		name, usage := flag.UnquoteUsage(f)
		line(".TP")
		if isBoolFlag(f) {
			line(`.B \-\-%s`, roff(f.Name))
		} else {
			line(`.BI \-\-%s " %s"`, roff(f.Name), roff(cmp.Or(name, "value")))
		}
		text := roff(usage)
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" && !strings.Contains(usage, "default") {
			text += " (default: " + roff(f.DefValue) + ")"
		}
		line("%s", text)
	})

	line(".SH FILTER")
	line("\\fB\\-\\-filter\\fR and \\fB/\\fR on the screen take the same conditions: %s.", roff(filterSyntax))
	line("Keys and values are matched case-insensitively; a value without a glob matches as a substring.")
	for _, k := range filterKeys {
		line(".TP")
		line(`.BI %s: %s`, roff(k.name), roff(k.value))
		text := roff(k.usage)
		if len(k.values) > 0 {
			text += "; for example " + roff(strings.Join(k.values, ", "))
		}
		line("%s", text)
	}
	line(".PP")
	line("Examples: \\fBport:443 dir:outbound proc:curl\\fR, \\fB!iface:lo user:www\\-data\\fR, \\fBhost:*.example.com ja4:t13d*\\fR.")

	line(".SH SCREEN KEYS")
	for _, k := range screenKeys {
		line(".TP")
		line(".B %s", roff(k[0]))
		line("%s", roff(k[1]))
	}

	line(".SH FILES")
	for _, f := range [][2]string{
		{"$XDG_CONFIG_HOME/socktrail/config", "default flags, one per line, as on the command line without the dashes; see \\fB\\-\\-config\\fR. Under sudo, the invoking user's ~/.config/socktrail/config"},
		{"$XDG_STATE_HOME/socktrail/captures", "PCAPNG recordings made with c; see \\fB\\-\\-capture\\-dir\\fR"},
		{"$XDG_DATA_HOME/socktrail/geoip", "optional DB\\-IP Lite country and ASN databases; see \\fB\\-\\-geoip\\-dir\\fR"},
	} {
		line(".TP")
		line(".I %s", roff(f[0]))
		line("%s", f[1])
	}
	line(".SH ENVIRONMENT")
	line(".TP")
	line(".B NO_COLOR")
	line("turns off colors on the interactive screen.")

	line(".SH EXAMPLES")
	for _, e := range [][2]string{
		{"sudo socktrail", "watch up to eight active interfaces"},
		{"sudo socktrail --interface lo --filter 'user:www-data'", "only the connections of processes running as www-data on loopback"},
		{"sudo socktrail --netns container:0123456789ab --interface eth0", "capture inside a container's network namespace"},
		{"sudo socktrail --duration 30s --output json", "print a 30-second JSON snapshot"},
		{"source <(socktrail --completion bash)", "load bash completion"},
		{"socktrail --man | man -l -", "read this page"},
	} {
		line(".TP")
		line(".B %s", roff(e[0]))
		line("%s", roff(e[1]))
	}
	line(".SH SEE ALSO")
	line(`\fBss\fR(8), \fBtcpdump\fR(1), https://github.com/jimyag/socktrail`)
	_, err := io.WriteString(w, m.String())
	return err
}

// writeUsage is the -h text: the flags, then the filter keys, which a flag
// list cannot show.
func writeUsage(w io.Writer, flags *flag.FlagSet) {
	var u strings.Builder
	u.WriteString("Usage: socktrail [flags]\n\nFlags:\n")
	output := flags.Output()
	flags.SetOutput(&u)
	flags.PrintDefaults()
	flags.SetOutput(output)
	fmt.Fprintf(&u, "\nFilter (--filter, or / on the screen, where Tab completes):\n  %s\n", filterSyntax)
	for _, k := range filterKeys {
		fmt.Fprintf(&u, "  %-26s %s\n", k.name+":"+k.value, k.usage)
	}
	u.WriteString("\nFull manual: socktrail --man | man -l -\n")
	_, _ = io.WriteString(w, u.String())
}
