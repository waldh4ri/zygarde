package hooks

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// hook is one function patched by ftrace, as listed in
// <tracefs>/enabled_functions (t_show() in kernel/trace/ftrace.c):
//
//	func (refcnt) R I D O M \ttramp: <tramp> (<handler>) ->...\tops: <ops> (<handler>)
//	\tdirect-->sym
//
// Flags: R saves registers, I may modify the instruction pointer (redirects
// execution), D has a direct call (BPF trampolines), O calls a single ops,
// M was modified.
type hook struct {
	Function string
	Flags    map[byte]bool
	Handlers []string // ftrace handlers: "(...)" after tramp:/ops:, and "->..." targets
	Direct   []string // direct-call targets (BPF trampolines)
}

var (
	headRe    = regexp.MustCompile(`^(\S+(?: \[[^\]]+\])?) \((\d+)\)([ RIDOM]*)`)
	handlerRe = regexp.MustCompile(`(?:tramp|ops): .*? \(([^()]+)\)`)
	arrowRe   = regexp.MustCompile(`->(\S+(?: \[[^\]]+\])?)`)
	directRe  = regexp.MustCompile(`direct(?:\(jmp\))?-->(\S+(?: \[[^\]]+\])?)`)
	hexRe     = regexp.MustCompile(`^(0x)?[0-9a-f]{8,16}$`)
)

func parseEnabledFunctions(r io.Reader) ([]hook, error) {
	var hooks []hook
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] == '\t' || line[0] == ' ' {
			// Continuation line ("\tdirect-->...") of the previous entry.
			if len(hooks) > 0 {
				for _, m := range directRe.FindAllStringSubmatch(line, -1) {
					hooks[len(hooks)-1].Direct = append(hooks[len(hooks)-1].Direct, m[1])
				}
			}
			continue
		}
		m := headRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		h := hook{Function: m[1], Flags: map[byte]bool{}}
		for _, f := range []byte(m[3]) {
			if f != ' ' {
				h.Flags[f] = true
			}
		}
		rest := line[len(m[0]):]
		for _, hm := range handlerRe.FindAllStringSubmatch(rest, -1) {
			h.Handlers = append(h.Handlers, hm[1])
		}
		for _, am := range arrowRe.FindAllStringSubmatch(rest, -1) {
			h.Handlers = append(h.Handlers, am[1])
		}
		for _, dm := range directRe.FindAllStringSubmatch(rest, -1) {
			h.Direct = append(h.Direct, dm[1])
		}
		hooks = append(hooks, h)
	}
	return hooks, sc.Err()
}

// unresolved reports whether a %pS-formatted address has no symbol: the code
// is not in the core kernel, a visible module or a named BPF program.
func unresolved(sym string) bool {
	return hexRe.MatchString(sym)
}

// owner describes where a handler lives: "module foo", "BPF" or "kernel".
func owner(sym string) string {
	if i := strings.LastIndex(sym, " ["); i >= 0 && strings.HasSuffix(sym, "]") {
		return "module " + sym[i+2:len(sym)-1]
	}
	if strings.HasPrefix(sym, "bpf_trampoline_") || strings.HasPrefix(sym, "bpf_prog_") {
		return "BPF"
	}
	return "kernel"
}

// baseName strips the "+0x0/0x10" offset and " [module]" suffix.
func baseName(sym string) string {
	if i := strings.IndexAny(sym, "+ "); i >= 0 {
		return sym[:i]
	}
	return sym
}

var syscallPrefixes = []string{"__x64_sys_", "__ia32_sys_", "__x32_compat_sys_", "__arm64_sys_", "__se_sys_", "__do_sys_", "sys_"}

func isSyscall(fn string) bool {
	fn = baseName(fn)
	for _, p := range syscallPrefixes {
		if strings.HasPrefix(fn, p) {
			return true
		}
	}
	return fn == "x64_sys_call" || fn == "do_syscall_64"
}
