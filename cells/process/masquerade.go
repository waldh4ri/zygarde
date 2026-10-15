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
)

// pfKthread marks kernel threads (include/linux/sched.h; unchanged since 2.6).
const pfKthread = 0x00200000

// kthreadPrefixes are names of common kernel threads. Userspace programs
// that pick one of these names are imitating a kernel thread.
var kthreadPrefixes = []string{
	"kworker/", "ksoftirqd/", "migration/", "rcu_", "cpuhp/", "watchdog/", "irq/",
	"kthreadd", "kswapd", "kcompactd", "khugepaged", "kauditd", "khungtaskd", "kblockd",
	"jbd2/", "scsi_eh_", "scsi_tmf_", "kdevtmpfs", "oom_reaper", "writeback", "kintegrityd",
	"ksmd", "kthrotld", "kstrp", "ipv6_addrconf", "idle_inject/", "card0-crtc", "netns",
}

// looksLikeKthread reports whether a name imitates a kernel thread: a known
// kernel thread name, or a bracketed command line like ps prints for them.
func looksLikeKthread(comm, cmdline string) bool {
	if strings.HasPrefix(cmdline, "[") && strings.Contains(cmdline, "]") {
		return true
	}
	for _, p := range kthreadPrefixes {
		if strings.HasPrefix(comm, p) {
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

func under(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// hiddenDir reports whether any directory component of path starts with a dot.
func hiddenDir(path string) bool {
	parts := strings.Split(filepath.Dir(path), "/")
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
// processes seen in both kernel snapshots. alive returns the start time of
// every process in a kernel snapshot taken after the /proc reads: a PID
// reused while /proc was being read is not judged on the new process's files.
func checkMasquerade(rec *core.Recorder, procs map[uint32]processTaskInfo, skip map[uint32]bool, alive func() (map[uint32]uint64, error)) error {
	selfExe, _ := os.Readlink("/proc/self/exe")
	pids := make([]uint32, 0, len(procs))
	for pid := range procs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

	// Results are recorded once the kernel confirms each process outlived
	// the reads of its /proc files.
	type pending struct {
		pid   uint32
		start uint64
		emit  func()
	}
	var queue []pending

	for _, pid := range pids {
		t := procs[pid]
		if skip[pid] || t.Flags&pfKthread != 0 {
			continue
		}
		dir := "/proc/" + strconv.Itoa(int(pid))
		comm := bpfutil.Int8String(t.Comm[:])
		raw, _ := os.ReadFile(dir + "/cmdline")
		cmdline := strings.TrimRight(strings.ReplaceAll(string(raw), "\x00", " "), " ")
		exe, exeErr := os.Readlink(dir + "/exe")
		if exeErr == nil && exe == selfExe {
			continue // zygarde itself, its worker and canaries
		}
		details := func() map[string]string {
			return map[string]string{
				"pid":     strconv.Itoa(int(pid)),
				"comm":    comm,
				"cmdline": truncate(cmdline, 200),
				"euid":    strconv.Itoa(int(t.Euid)),
				"ppid":    strconv.Itoa(int(t.Ppid)),
				"exe":     exe,
			}
		}

		queue = append(queue, pending{pid, t.StartTime, func() {
			if looksLikeKthread(comm, cmdline) {
				d := details()
				d["has_user_address_space"] = strconv.FormatBool(t.HasMm != 0)
				rec.Suspicious(core.Finding{
					Description: fmt.Sprintf("Process %d (%s) poses as a kernel thread but is a user process", pid, firstNonEmpty(cmdline, comm)),
					Details:     d,
					Why: "Its name imitates a kernel thread, but the kernel does not flag it as one (no PF_KTHREAD) and " +
						"it runs a user program. Malware renames itself this way to blend into ps output.",
					Benign: "Rare. Check the executable (exe above) and its package; some tools rename worker processes.",
				})
			}

			if exeErr == nil {
				if loc := exeLocation(exe); loc != "" {
					path := strings.TrimSuffix(exe, " (deleted)")
					desc := fmt.Sprintf("Process %d (%s) runs from a %s executable: %s", pid, comm, loc, exe)
					if loc == "deleted" {
						desc = fmt.Sprintf("Process %d (%s) runs from a deleted executable: %s", pid, comm, exe)
					}
					d := details()
					d["location"] = loc
					// Package upgrades leave daemons running from deleted
					// binaries in system directories: not worth a finding.
					upgraded := loc == "deleted" && packaged(path)
					if t.Euid == 0 && !upgraded {
						rec.Suspicious(core.Finding{
							Description: desc,
							Details:     d,
							Why: "A root process whose program lives only in memory, in a temporary directory or a hidden one, " +
								"or was deleted after starting, leaves nothing on disk to inspect: a common way to run " +
								"implants. The binary can still be recovered from /proc/<pid>/exe.",
							Benign: "Software updated in place outside the package manager, installers running from /tmp, " +
								"or tools that execute from a memfd (e.g. runc while starting a container).",
						})
					} else {
						rec.Observe(desc, d)
					}
				}
			}

			if n, ok := padded(raw); ok {
				d := details()
				d["padding"] = strconv.Itoa(n)
				rec.Observe(fmt.Sprintf("Process %d (%s) pads its command line with %d blank characters", pid, comm, n), d)
			}
		}})
	}

	if len(queue) == 0 {
		return nil
	}
	starts, err := alive()
	if err != nil {
		return err
	}
	for _, p := range queue {
		if starts[p.pid] == p.start {
			p.emit()
		}
	}
	return nil
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
