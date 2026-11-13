package process

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// pfKthread marks kernel threads (include/linux/sched.h; unchanged since 2.6).
const pfKthread = 0x00200000

// kthreadPrefixes are names of common kernel threads. Userspace programs
// that pick one of these names are imitating a kernel thread.
var kthreadPrefixes = []string{
	"kworker/", "ksoftirqd/", "migration/", "rcu_", "cpuhp/", "watchdog/", "irq/",
	"kthreadd", "kswapd", "kcompactd", "khugepaged", "kauditd", "khungtaskd", "kblockd",
	"jbd2/", "scsi_eh_", "scsi_tmf_", "kdevtmpfs", "oom_reaper", "writeback", "kintegrityd",
	"ksmd", "kthrotld", "kstrp", "ipv6_addrconf", "idle_inject/", "card0-crtc", "card1-crtc", "netns",
	"psimon", "hv_balloon", "ecryptfs-kthread",
}

// looksLikeKthread reports whether a name imitates a kernel thread: a known
// kernel thread name, a bracketed comm (e.g. PR_SET_NAME("[kworker/0:1]")),
// or a bracketed command line like ps prints for kernel threads.
func looksLikeKthread(comm, cmdline string) bool {
	if strings.HasPrefix(cmdline, "[") && strings.Contains(cmdline, "]") {
		return true
	}
	if strings.HasPrefix(comm, "[") && strings.Contains(comm, "]") {
		return true
	}
	cleanComm := strings.Trim(comm, "[]")
	for _, p := range kthreadPrefixes {
		if strings.HasPrefix(cleanComm, p) {
			return true
		}
	}
	return false
}

// exeLocation classifies where a process's executable lives, from the
// /proc/<pid>/exe link target. It returns "" for ordinary locations.
func exeLocation(target string) string {
	deleted := strings.HasSuffix(target, " (deleted)")
	path := strings.TrimSuffix(target, " (deleted)")
	switch {
	case strings.HasPrefix(path, "/memfd:"):
		return "memfd"
	case under(path, "/dev/shm"), under(path, "/run/shm"):
		return "memory-backed directory"
	case under(path, "/tmp"), under(path, "/var/tmp"):
		return "temporary directory"
	case hiddenDir(path):
		return "hidden directory"
	case deleted:
		return "deleted"
	}
	return ""
}

// suspiciousExe reports whether running from target (classified as loc) should
// escalate to a SUSPICIOUS finding rather than a contextual observation.
// Fileless memfd execution and deleted binaries in temporary, memory-backed or
// hidden directories are suspicious for all users (including web/service users
// such as www-data), whereas deleted package binaries left behind by upgrades
// stay observations.
func suspiciousExe(euid uint32, target, loc string) bool {
	deleted := strings.HasSuffix(target, " (deleted)")
	path := strings.TrimSuffix(target, " (deleted)")
	if loc == "deleted" && packaged(path) {
		return false
	}
	if loc == "memfd" {
		return true
	}
	if deleted && (loc == "memory-backed directory" || loc == "temporary directory" || loc == "hidden directory") {
		return true
	}
	return euid == 0
}

func under(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// hiddenDir reports whether any directory component of path starts with a dot.
func hiddenDir(path string) bool {
	parts := strings.Split(filepath.ToSlash(filepath.Dir(path)), "/")
	for _, p := range parts {
		if strings.HasPrefix(p, ".") && p != "." && p != ".." {
			return true
		}
	}
	return false
}

// packaged reports whether path is in a directory managed by the package
// manager, where an upgrade leaves running processes with a deleted binary.
func packaged(path string) bool {
	for _, d := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/snap", "/nix"} {
		if under(path, d) {
			return true
		}
	}
	return false
}

// paddingRun is the shortest run of spaces or NULs, followed by more
// arguments, treated as padding: enough to push the rest out of ps's view.
const paddingRun = 32

// padded reports whether a raw /proc/<pid>/cmdline hides arguments behind a
// long run of spaces or NULs. Trailing NULs alone are left by programs that
// rewrite their title (setproctitle) and are not counted.
func padded(cmdline []byte) (int, bool) {
	trimmed := bytes.TrimRight(cmdline, "\x00")
	run, longest := 0, 0
	for _, c := range trimmed {
		if c == ' ' || c == 0 {
			run++
			continue
		}
		if run > longest {
			longest = run
		}
		run = 0
	}
	return longest, longest >= paddingRun
}

// checkMasquerade looks for processes disguised as kernel threads or running
// from deleted, memory-backed or out-of-place executables. procs holds the
// processes seen in both kernel snapshots.
func checkMasquerade(env *core.Env, rec *core.Recorder, procs map[uint32]processTaskInfo, skip map[uint32]bool) {
	selfExe, _ := os.Readlink("/proc/self/exe")
	pids := make([]uint32, 0, len(procs))
	for pid := range procs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

	for _, pid := range pids {
		t := procs[pid]
		if skip[pid] || t.Flags&pfKthread != 0 {
			continue
		}
		dir := "/proc/" + strconv.Itoa(int(pid))
		comm := bpfutil.Int8String(t.Comm[:])
		raw, cmdErr := fsutil.ReadFileNoAtime(dir + "/cmdline")
		cmdline := strings.TrimRight(strings.ReplaceAll(string(raw), "\x00", " "), " ")
		exe, exeErr := os.Readlink(dir + "/exe")
		if exeErr == nil && exe == selfExe {
			continue // zygarde itself, its worker and canaries
		}
		details := func(enrich bool) map[string]string {
			d := map[string]string{
				"pid":     strconv.Itoa(int(pid)),
				"comm":    comm,
				"cmdline": truncate(cmdline, 200),
				"uid":     strconv.Itoa(int(t.Uid)),
				"euid":    strconv.Itoa(int(t.Euid)),
				"ppid":    strconv.Itoa(int(t.Ppid)),
				"exe":     exe,
			}
			if env != nil {
				if ts := env.FormatBootOffset(t.StartBoottime); ts != "" {
					d["started_at"] = ts
				}
			}
			if enrich {
				enrichProcFiles(env, int(pid), comm, d)
			}
			return d
		}

		if looksLikeKthread(comm, cmdline) {
			d := details(true)
			d["has_user_address_space"] = strconv.FormatBool(t.HasMm != 0)
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Process %d (%s) poses as a kernel thread but is a user process", pid, firstNonEmpty(cmdline, comm)),
				Details:     d,
				Why: "Its name imitates a kernel thread, but the kernel does not flag it as one (no PF_KTHREAD) and " +
					"it runs a user program. Malware renames itself this way to blend into ps output.",
				Benign: "Rare. Check the executable (exe above) and its package; some tools rename worker processes.",
			})
		} else if cmdErr == nil && len(bytes.TrimRight(raw, "\x00")) == 0 && t.HasMm != 0 {
			// User process with wiped/empty argv: ps prints [comm] in brackets like a kernel thread.
			rec.Observe(fmt.Sprintf("User process %d (%s) has an empty command line (shown as [%s] in ps)", pid, comm, comm), details(false))
		}

		if exeErr == nil {
			if loc := exeLocation(exe); loc != "" {
				desc := fmt.Sprintf("Process %d (%s) runs from a %s executable: %s", pid, comm, loc, exe)
				if loc == "deleted" {
					desc = fmt.Sprintf("Process %d (%s) runs from a deleted executable: %s", pid, comm, exe)
				}
				susp := suspiciousExe(t.Euid, exe, loc)
				d := details(susp)
				d["location"] = loc
				if susp {
					rec.Suspicious(core.Finding{
						Description: desc,
						Details:     d,
						Why: "A process whose program lives only in memory (memfd), was deleted from a temporary or " +
							"memory-backed directory after starting, or runs as root from an unusual path leaves " +
							"little on disk to inspect: a common way to run fileless implants. The binary can still be recovered from /proc/<pid>/exe.",
						Benign: "Software updated in place outside the package manager, installers running from /tmp, " +
							"or container runtimes (e.g. runc) briefly executing from a memfd.",
					})
				} else {
					rec.Observe(desc, d)
				}
			}
		}

		if n, ok := padded(raw); ok {
			d := details(false)
			d["padding"] = strconv.Itoa(n)
			rec.Observe(fmt.Sprintf("Process %d (%s) pads its command line with %d blank characters", pid, comm, n), d)
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
