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

func exeLocation(target string) string {
	deleted := strings.HasSuffix(target, " (deleted)")
	path := strings.TrimSuffix(target, " (deleted)")
	switch {
	case strings.HasPrefix(path, "/memfd:"):
		return "memfd"
	case under(path, "/dev/shm"), under(path, "/run") && !nixRun(path):
		// /run (and /var/run, its symlink) is a tmpfs: BPFDoor variants run
		// from /var/run/gdm/auth-session or /var/run/haldrund.
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

// nixRun reports NixOS paths under /run that hold legitimate executables:
// setuid wrappers (a tmpfs) and links into /nix/store.
func nixRun(path string) bool {
	for _, d := range []string{"/run/wrappers", "/run/current-system", "/run/booted-system", "/run/opengl-driver"} {
		if under(path, d) {
			return true
		}
	}
	return false
}

func under(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

func hiddenDir(path string) bool {
	parts := strings.Split(filepath.ToSlash(filepath.Dir(path)), "/")
	for _, p := range parts {
		if strings.HasPrefix(p, ".") && p != "." && p != ".." {
			return true
		}
	}
	return false
}

func packaged(path string) bool {
	for _, d := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/snap", "/nix"} {
		if under(path, d) {
			return true
		}
	}
	return false
}

const paddingRun = 32

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
// from deleted, memory-backed or out-of-place executables. Findings are only
// emitted once alive() confirms each process outlived the reads of its /proc
// files (same start_time), so a PID reused mid-read is never misjudged.
func checkMasquerade(env *core.Env, rec *core.Recorder, procs map[uint32]processTaskInfo, skip map[uint32]bool, alive func() (map[uint32]uint64, error)) error {
	selfExe, _ := os.Readlink("/proc/self/exe")
	pids := make([]uint32, 0, len(procs))
	for pid := range procs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

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
		raw, cmdErr := fsutil.ReadFileNoAtime(dir + "/cmdline")
		cmdline := strings.TrimRight(strings.ReplaceAll(string(raw), "\x00", " "), " ")
		exe, exeErr := os.Readlink(dir + "/exe")
		if exeErr == nil && exe == selfExe {
			continue
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
				if ts := env.FormatBootOffset(t.StartTime); ts != "" {
					d["started_at"] = ts
				}
			}
			if enrich {
				enrichProcFiles(env, int(pid), comm, d)
			}
			return d
		}

		isKthreadMask := looksLikeKthread(comm, cmdline)
		emptyCmd := !isKthreadMask && cmdErr == nil && len(bytes.TrimRight(raw, "\x00")) == 0 && t.HasMm != 0
		var loc string
		if exeErr == nil {
			loc = exeLocation(exe)
		}
		padLen, isPadded := padded(raw)
		if !isKthreadMask && !emptyCmd && loc == "" && !isPadded {
			continue
		}

		queue = append(queue, pending{pid, t.StartTime, func() {
			if isKthreadMask {
				d := details(true)
				d["has_user_address_space"] = strconv.FormatBool(t.HasMm != 0)
				rec.Suspicious(core.Finding{
					Description: fmt.Sprintf("Process %d (%s) poses as a kernel thread but is a user process", pid, firstNonEmpty(cmdline, comm)),
					Details:     d,
					Why: "Its name imitates a kernel thread, but the kernel does not flag it as one (no PF_KTHREAD) and " +
						"it runs a user program. Malware renames itself this way to blend into ps output.",
					Benign: "Rare. Check the executable (exe above) and its package; some tools rename worker processes.",
				})
			} else if emptyCmd {
				rec.Observe(fmt.Sprintf("User process %d (%s) has an empty command line (shown as [%s] in ps)", pid, comm, comm), details(false))
			}

			if loc != "" {
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

			if isPadded {
				d := details(false)
				d["padding"] = strconv.Itoa(padLen)
				rec.Observe(fmt.Sprintf("Process %d (%s) pads its command line with %d blank characters", pid, comm, padLen), d)
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
