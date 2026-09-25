package app

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
)

// completionArgs says how to complete a flag's value: from a fixed list, or
// with one of the kinds file, dir, interface and netns.
var completionArgs = map[string][]string{
	"interface":    {"interface"},
	"filter":       {"filter"},
	"netns":        {"netns"},
	"read":         {"file"},
	"log-file":     {"file"},
	"config":       {"file"},
	"capture-dir":  {"dir"},
	"geoip-dir":    {"dir"},
	"output":       {"text", "json", "ndjson"},
	"memory-limit": {"auto", "none", "512MiB", "1GiB"},
	"completion":   {"bash", "zsh", "fish"},
}

// Flags that take one value per occurrence and may repeat.
var repeatableFlags = map[string]bool{"interface": true, "netns": true, "process": true, "pid": true, "cgroup": true, "container": true}

type completionFlag struct {
	name, usage string
	boolean     bool
	values      []string // Fixed values, or a single kind.
}

func completionFlags(flags *flag.FlagSet) []completionFlag {
	var list []completionFlag
	flags.VisitAll(func(f *flag.Flag) {
		usage, _, _ := strings.Cut(f.Usage, " (")
		list = append(list, completionFlag{name: f.Name, usage: usage, boolean: isBoolFlag(f), values: completionArgs[f.Name]})
	})
	slices.SortFunc(list, func(a, b completionFlag) int { return strings.Compare(a.name, b.name) })
	return list
}

func (f completionFlag) kind() string {
	if len(f.values) == 1 {
		return f.values[0]
	}
	return ""
}

// writeCompletion prints a completion script for shell, built from the
// flags themselves so that it follows them.
func writeCompletion(w io.Writer, shell string, flags *flag.FlagSet) error {
	list := completionFlags(flags)
	var script strings.Builder
	switch shell {
	case "bash":
		writeBashCompletion(&script, list)
	case "zsh":
		writeZshCompletion(&script, list)
	case "fish":
		writeFishCompletion(&script, list)
	default:
		return fmt.Errorf("--completion accepts bash, zsh or fish, not %q", shell)
	}
	_, err := io.WriteString(w, script.String())
	return err
}

// filterWords are the filter conditions a shell can complete without the
// live connections: each key, and each fixed value.
func filterWords() []string {
	var words []string
	for _, k := range filterKeys {
		words = append(words, k.name+":")
		for _, v := range k.values {
			words = append(words, k.name+":"+v)
		}
	}
	return words
}

// Shell commands that list completion candidates of a kind.
const (
	listInterfaces = "ls /sys/class/net 2>/dev/null"
	listNetNS      = "ls /run/netns 2>/dev/null; echo pid:; echo container:"
)

func writeBashCompletion(w *strings.Builder, list []completionFlag) {
	fmt.Fprintln(w, "# bash completion for socktrail; load with: source <(socktrail --completion bash)")
	// bash-completion keeps a colon inside the word; readline replaces only
	// the part after it, so candidates lose what comes before it.
	fmt.Fprintln(w, `_socktrail_colon() { declare -F __ltrim_colon_completions >/dev/null && __ltrim_colon_completions "$cur"; }`)
	fmt.Fprintln(w, "_socktrail() {")
	fmt.Fprintln(w, `	local cur prev words cword`)
	fmt.Fprintln(w, `	_init_completion -n =: 2>/dev/null || { cur=${COMP_WORDS[COMP_CWORD]}; prev=${COMP_WORDS[COMP_CWORD-1]}; }`)
	var booleans []string
	for _, f := range list {
		if f.boolean {
			booleans = append(booleans, f.name, "-"+f.name)
		}
	}
	fmt.Fprintln(w, `	local inline=`)
	fmt.Fprintln(w, `	if [[ $cur == -*=* ]]; then prev=${cur%%=*}; cur=${cur#*=}; inline=1; fi`)
	fmt.Fprintln(w, `	if [[ $prev == = && $COMP_CWORD -ge 2 ]]; then prev=${COMP_WORDS[COMP_CWORD-2]}; inline=1; fi`)
	fmt.Fprintln(w, `	case ${prev#--} in`)
	// A boolean takes a value only after =, as in --socket-sniff=false.
	fmt.Fprintf(w, "\t%s) if [[ $inline ]]; then COMPREPLY=($(compgen -W \"true false\" -- \"$cur\")); return; fi ;;\n", strings.Join(booleans, "|"))
	for _, f := range list {
		if f.values == nil {
			continue
		}
		var reply string
		switch f.kind() {
		case "file":
			reply = `compgen -f -- "$cur"`
		case "dir":
			reply = `compgen -d -- "$cur"`
		case "interface":
			reply = `compgen -W "$(` + listInterfaces + `)" -- "$cur"`
		case "netns":
			reply = `compgen -W "$(` + listNetNS + `)" -- "$cur"`
		case "filter":
			// The word keeps its colon, and completing a key leaves room for its value.
			fmt.Fprintf(w, "\t%s|-%s) compopt -o nospace 2>/dev/null; COMPREPLY=($(compgen -W \"%s\" -- \"$cur\")); _socktrail_colon; return ;;\n", f.name, f.name, strings.Join(filterWords(), " "))
			continue
		default:
			reply = `compgen -W "` + strings.Join(f.values, " ") + `" -- "$cur"`
		}
		fmt.Fprintf(w, "\t%s|-%s) COMPREPLY=($(%s)); _socktrail_colon; return ;;\n", f.name, f.name, reply)
	}
	var names []string
	for _, f := range list {
		names = append(names, "--"+f.name)
	}
	fmt.Fprintln(w, "\tesac")
	fmt.Fprintf(w, "\tCOMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n", strings.Join(names, " "))
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w, "complete -o default -F _socktrail socktrail")
}

// zshQuote escapes a description for an _arguments spec in single quotes.
func zshQuote(s string) string {
	return strings.NewReplacer("'", `'\''`, "[", `\[`, "]", `\]`, ":", `\:`).Replace(s)
}

func writeZshCompletion(w *strings.Builder, list []completionFlag) {
	fmt.Fprintln(w, "#compdef socktrail")
	fmt.Fprintln(w, "# zsh completion for socktrail; save as _socktrail in a directory of $fpath")
	fmt.Fprintln(w, "_arguments -S \\")
	for _, f := range list {
		prefix := ""
		if repeatableFlags[f.name] {
			prefix = "*"
		}
		if f.boolean { // A value, if any, must follow = in the same word.
			fmt.Fprintf(w, "\t'%s--%s=-[%s]::%s:(true false)' \\\n", prefix, f.name, zshQuote(f.usage), f.name)
			continue
		}
		action := " "
		switch f.kind() {
		case "file":
			action = "_files"
		case "dir":
			action = "_files -/"
		case "interface":
			action = "_net_interfaces"
		case "netns":
			action = "{compadd -- $(" + listNetNS + ")}"
		case "filter":
			action = "{compadd -S '' -- " + strings.Join(filterWords(), " ") + "}"
		default:
			if f.values != nil {
				action = "(" + strings.Join(f.values, " ") + ")"
			}
		}
		fmt.Fprintf(w, "\t'%s--%s=[%s]:%s:%s' \\\n", prefix, f.name, zshQuote(f.usage), f.name, zshQuote(action))
	}
	fmt.Fprintln(w, "\t&& return 0")
}

func writeFishCompletion(w *strings.Builder, list []completionFlag) {
	fmt.Fprintln(w, "# fish completion for socktrail; save as ~/.config/fish/completions/socktrail.fish")
	fmt.Fprintln(w, "complete -c socktrail -f")
	quote := strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace
	for _, f := range list {
		line := fmt.Sprintf("complete -c socktrail -l %s -d '%s'", f.name, quote(f.usage))
		switch {
		case f.kind() == "file":
			line += " -r -F"
		case !f.boolean:
			line += " -x" // A value, but not a file name.
		}
		switch f.kind() {
		case "file":
		case "dir":
			line += " -a '(__fish_complete_directories)'"
		case "interface":
			line += " -a '(" + listInterfaces + ")'"
		case "netns":
			line += " -a '(" + quote(listNetNS) + ")'"
		case "filter": // One line per candidate, each with its own description.
			for _, k := range filterKeys {
				fmt.Fprintf(w, "complete -c socktrail -l filter -x -a '%s:' -d '%s'\n", k.name, quote(k.usage))
				for _, v := range k.values {
					fmt.Fprintf(w, "complete -c socktrail -l filter -x -a '%s:%s' -d '%s'\n", k.name, v, quote(k.usage))
				}
			}
		default:
			if f.values != nil {
				line += " -a '" + strings.Join(f.values, " ") + "'"
			}
		}
		fmt.Fprintln(w, line)
	}
}
