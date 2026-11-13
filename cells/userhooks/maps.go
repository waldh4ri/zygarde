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

		seenForPID := map[mappedLib]bool{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			libPath, reason := classifyExecMapLine(c, sc.Text(), exe, procRoot)
			if reason == "" {
				continue
			}
			key := mappedLib{libPath, reason}
			if !seenForPID[key] {
				seenForPID[key] = true
				holders[key] = append(holders[key], pid)
			}
		}
		f.Close()
	}

	keys := make([]mappedLib, 0, len(holders))
	for k := range holders {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].path < keys[j].path })

	suspicious := 0
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
