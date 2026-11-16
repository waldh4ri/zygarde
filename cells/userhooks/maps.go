// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package userhooks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// checkLdSoCache inspects binary /etc/ld.so.cache string entries so poisoned
// library paths baked into the linker cache via ldconfig are caught even if
// /etc/ld.so.conf was restored afterwards.
func (c *Cell) checkLdSoCache(rec *core.Recorder) int {
	const cachePath = "/etc/ld.so.cache"
	data, err := fsutil.ReadFileNoAtime(c.path(cachePath))
	if err != nil {
		return 0
	}
	seenDirs := map[string]bool{}
	n := 0
	for _, entry := range parseLdSoCachePaths(data) {
		dir := filepath.ToSlash(filepath.Dir(entry))
		if seenDirs[dir] {
			continue
		}
		why := c.unusualDir(dir, "")
		if why == "" {
			continue
		}
		seenDirs[dir] = true
		n++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("/etc/ld.so.cache resolves shared libraries from %s (%s), e.g. %s", dir, why, entry),
			Details:     map[string]string{"cache": cachePath, "directory": dir, "example_library": entry, "reason": why},
			Why: "Dynamic binaries consult /etc/ld.so.cache directly without re-reading /etc/ld.so.conf. Attackers can " +
				"add a directory to ld.so.conf, run ldconfig, and delete the ld.so.conf line so the poisoned cache persists.",
			Benign: "Unusual local software registered with ldconfig; rebuild with ldconfig after verifying ld.so.conf.",
		})
	}
	return n
}

// parseLdSoCachePaths extracts NUL-terminated absolute shared-library paths
// ("/.../*.so*") from glibc's binary ld.so.cache string table.
func parseLdSoCachePaths(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, tok := range bytes.Split(data, []byte{0}) {
		if len(tok) < 6 || len(tok) > 512 || tok[0] != '/' {
			continue
		}
		valid := true
		for _, b := range tok {
			if b < 0x20 || b == 0x7f {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		s := string(tok)
		base := filepath.Base(s)
		if !strings.Contains(base, ".so") || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// checkProcessMaps scans /proc/<pid>/maps for executable shared libraries
// loaded from memory-backed, temporary, or hidden directories—catching
// ptrace/dlopen injection and LD_PRELOAD implants that scrubbed /proc/<pid>/environ.
func (c *Cell) checkProcessMaps(ctx context.Context, rec *core.Recorder) (int, error) {
	entries, err := fsutil.ReadDirNoAtime(c.proc)
	if err != nil {
		return 0, nil
	}
	selfPID := strconv.Itoa(os.Getpid())
	type mappedLib struct {
		path, reason string
	}
	holders := map[mappedLib][]string{}
	trusted := map[mappedLib][]string{} // mapped by a verified JVM from files it extracted itself
	suspicious := 0

	for _, e := range entries {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		pid := e.Name()
		if pid == selfPID {
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		f, err := fsutil.OpenNoAtime(filepath.Join(c.proc, pid, "maps"))
		if err != nil {
			continue
		}
		exe, _ := os.Readlink(filepath.Join(c.proc, pid, "exe"))
		procRoot := filepath.Join(c.proc, pid, "root")
		if _, err := os.Stat(procRoot); err != nil {
			procRoot = ""
		}

		type candidate struct {
			lib  mappedLib
			file string // the mapping's /proc/<pid>/map_files entry
		}
		var lines []string
		var cands []candidate
		var anonStarts []anonExec
		var prev mapLine
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			lines = append(lines, line)
			if libPath, reason := classifyExecMapLine(c, line, exe, procRoot); reason != "" {
				rng, _, _ := strings.Cut(line, " ")
				cands = append(cands, candidate{mappedLib{libPath, reason}, filepath.Join(c.proc, pid, "map_files", rng)})
			}
			cur, ok := parseMapLine(line)
			if ok && cur.anon && strings.Contains(cur.perms, "x") {
				// A loaded ELF image starts with its header, in the executable
				// segment or in the read-only one right before it.
				anonStarts = append(anonStarts, anonExec{cur, cur.start})
				if prev.anon && prev.end == cur.start {
					anonStarts = append(anonStarts, anonExec{cur, prev.start})
				}
			}
			prev = cur
		}
		f.Close()
		if len(anonStarts) > 0 {
			suspicious += c.checkAnonELF(rec, pid, exe, anonStarts)
		}

		uid, gid := c.procOwner(pid)
		var jvmInfo jvm
		checked := false
		seenForPID := map[mappedLib]bool{}
		for _, cd := range cands {
			if seenForPID[cd.lib] {
				continue
			}
			seenForPID[cd.lib] = true
			// A JVM unpacks native libraries to temporary and cache directories, never to a memfd.
			if !strings.Contains(cd.lib.reason, "memfd") {
				if !checked {
					jvmInfo, checked = c.attestJVM(pid, exe, lines, procRoot), true
				}
				if jvmInfo.ok && jvmOwnLibrary(cd.lib.path, cd.file, uid, gid) {
					trusted[cd.lib] = append(trusted[cd.lib], pid)
					continue
				}
			}
			holders[cd.lib] = append(holders[cd.lib], pid)
		}
	}

	keys := make([]mappedLib, 0, len(holders))
	for k := range holders {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].path < keys[j].path })

	for k, pids := range trusted {
		rec.Observe(fmt.Sprintf("Library %s (%s) is mapped by %d verified Java process(es), which extract native libraries themselves", k.path, k.reason, len(pids)), map[string]string{
			"library": k.path, "reason": k.reason, "pids": strings.Join(pids, ", "),
		})
	}

	for _, k := range keys {
		pids := holders[k]
		sort.Slice(pids, func(i, j int) bool { a, _ := strconv.Atoi(pids[i]); b, _ := strconv.Atoi(pids[j]); return a < b })
		shown := pids
		if len(shown) > 20 {
			shown = append(shown[:20:20], fmt.Sprintf("… (%d more)", len(pids)-20))
		}
		suspicious++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Executable library %s (%s) is mapped into %d process(es)", k.path, k.reason, len(pids)),
			Details: map[string]string{
				"library": k.path,
				"reason":  k.reason,
				"pids":    strings.Join(shown, ", "),
			},
			Why: "Inspecting /proc/<pid>/maps found executable code mapped from a memory-backed, temporary or hidden " +
				"location. This catches libraries injected at runtime (ptrace/dlopen) or preloaded libraries whose LD_PRELOAD variable was scrubbed.",
			Benign: "JIT or FFI runtimes mapping generated code from temporary files. Check the owning process and package.",
		})
	}
	return suspicious, nil
}

// classifyExecMapLine parses one /proc/<pid>/maps line and returns (path, reason)
// if it maps an executable shared object (other than the process's main exe)
// from a memfd, /dev/shm, /tmp or hidden directory.
func classifyExecMapLine(c *Cell, line, mainExe, procRoot string) (string, string) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return "", ""
	}
	perms, inode := fields[1], fields[4]
	if !strings.Contains(perms, "x") || inode == "0" {
		return "", ""
	}
	idx := strings.Index(line, fields[5])
	if idx < 0 {
		return "", ""
	}
	mapped := strings.TrimSpace(line[idx:])
	if mapped == "" || mapped[0] != '/' || mapped == mainExe {
		return "", ""
	}
	clean := strings.TrimSuffix(mapped, " (deleted)")
	// Ignore kernel/SysV anonymous shared memory and libffi 1-page trampolines.
	if clean == "/dev/zero" || strings.HasPrefix(clean, "/SYSV") || strings.HasPrefix(filepath.Base(clean), "ffi") {
		return "", ""
	}
	if strings.HasPrefix(clean, "/memfd:") {
		// Common Wayland/JIT memfd names without .so are non-library buffers; still
		// flag memfd executable mappings unless clearly JIT-named (v8/jit/mesa).
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "jit") || strings.Contains(lower, "mesa") {
			return "", ""
		}
		return mapped, "mapped from a memfd"
	}
	if why := c.unusualDir(filepath.ToSlash(filepath.Dir(clean)), procRoot); why != "" {
		return mapped, "mapped from " + why
	}
	return "", ""
}

// mapLine is one parsed /proc/<pid>/maps line.
type mapLine struct {
	start, end uint64
	perms      string
	name       string
	anon       bool // no file: anonymous memory (or named with PR_SET_VMA_ANON_NAME)
}

// parseMapLine parses "start-end perms offset dev inode [name]".
func parseMapLine(line string) (mapLine, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return mapLine{}, false
	}
	lo, hi, ok := strings.Cut(fields[0], "-")
	if !ok {
		return mapLine{}, false
	}
	start, err1 := strconv.ParseUint(lo, 16, 64)
	end, err2 := strconv.ParseUint(hi, 16, 64)
	if err1 != nil || err2 != nil {
		return mapLine{}, false
	}
	m := mapLine{start: start, end: end, perms: fields[1]}
	if len(fields) > 5 {
		m.name = strings.Join(fields[5:], " ")
	}
	// [heap], [stack], [vdso] (an ELF image the kernel provides), [vvar] and
	// [vsyscall] are the kernel's own; only unnamed or user-named anonymous
	// memory counts.
	m.anon = fields[4] == "0" && (m.name == "" || strings.HasPrefix(m.name, "[anon:"))
	return m, true
}

// anonExec is an address to check for an ELF header, for an anonymous
// executable mapping.
type anonExec struct {
	m    mapLine
	addr uint64
}

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// checkAnonELF reads the first bytes of anonymous executable mappings (and of
// the anonymous mapping just before each) and reports ELF images found there.
func (c *Cell) checkAnonELF(rec *core.Recorder, pid, exe string, cands []anonExec) int {
	mem, err := os.Open(filepath.Join(c.proc, pid, "mem"))
	if err != nil {
		rec.Log().Debug("process memory not readable", "pid", pid, "err", err)
		return 0
	}
	defer mem.Close()
	head := make([]byte, len(elfMagic))
	for _, cd := range cands {
		if n, err := mem.ReadAt(head, int64(cd.addr)); err != nil || n != len(head) || !bytes.Equal(head, elfMagic) {
			continue
		}
		comm, _ := fsutil.ReadFileNoAtime(filepath.Join(c.proc, pid, "comm"))
		cmdline, _ := fsutil.ReadFileNoAtime(filepath.Join(c.proc, pid, "cmdline"))
		d := map[string]string{
			"pid":            pid,
			"comm":           strings.TrimSpace(string(comm)),
			"exe":            exe,
			"cmdline":        strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " ")),
			"elf_header_at":  fmt.Sprintf("%#x", cd.addr),
			"executable_map": fmt.Sprintf("%x-%x %s %s", cd.m.start, cd.m.end, cd.m.perms, cd.m.name),
		}
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Process %s (%s) runs an ELF image loaded into anonymous memory at %#x", pid, d["comm"], cd.addr),
			Details:     d,
			Why: "Programs and libraries are mapped from files, so their ELF header sits in a file-backed mapping. An ELF " +
				"header at the start of anonymous executable memory means a program was copied into memory and run " +
				"from there by hand (reflective or \"userland exec\" loading), which leaves no file behind: a way " +
				"fileless implants run. The kernel's own ELF image ([vdso]) and JIT-compiled code never look like this.",
			Benign: "Programs packed with UPX unpack themselves into anonymous memory. Check the executable (exe above) " +
				"and its package.",
		})
		return 1 // one finding per process
	}
	return 0
}

// procOwner returns the user and group owning /proc/<pid>, the process's effective ones.
func (c *Cell) procOwner(pid string) (uid, gid uint32) {
	var st unix.Stat_t
	if unix.Stat(filepath.Join(c.proc, pid), &st) != nil {
		return ^uint32(0), ^uint32(0)
	}
	return st.Uid, st.Gid
}
