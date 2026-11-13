package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kmsg"
)

// readKmsg reads the kernel log (replaced in tests).
var readKmsg = kmsg.Read

// oopsMark returns the newest kernel log sequence number before a worker
// starts, so oopses logged while it runs can be told apart from older ones.
// ok is false when the kernel log cannot be read.
func oopsMark() (mark uint64, ok bool) {
	recs, err := readKmsg()
	if err != nil {
		return 0, false
	}
	return kmsg.LastSeq(recs), true
}

// suspectFiles lists the kernel-backed files a worker was working on: the
// descriptors its threads are blocked in a syscall on, then any other sysfs,
// procfs or device file it holds open. After a kernel oops while reading a
// file, the faulting thread never returns from that read, so its descriptor
// names the file whose backing kernel object is corrupt or dangling.
func suspectFiles(procDir string, pid int) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] && len(out) < 8 && (strings.HasPrefix(p, "/sys/") || strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/dev/")) {
			seen[p] = true
			out = append(out, p)
		}
	}
	base := filepath.Join(procDir, strconv.Itoa(pid))
	if tasks, err := os.ReadDir(filepath.Join(base, "task")); err == nil {
		for _, t := range tasks {
			// "<nr> <arg0> <arg1> ...": the first argument of read, pread64,
			// getdents64 and friends is the descriptor.
			b, err := os.ReadFile(filepath.Join(base, "task", t.Name(), "syscall"))
			if err != nil {
				continue
			}
			f := strings.Fields(string(b))
			if len(f) < 2 {
				continue
			}
			fd, err := strconv.ParseUint(strings.TrimPrefix(f[1], "0x"), 16, 32)
			if err != nil {
				continue
			}
			if p, err := os.Readlink(filepath.Join(base, "fd", strconv.FormatUint(fd, 10))); err == nil {
				add(p)
			}
		}
	}
	if fds, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		for _, fd := range fds {
			if p, err := os.Readlink(filepath.Join(base, "fd", fd.Name())); err == nil {
				add(p)
			}
		}
	}
	return out
}

// scannerComms are the names the scanner's own processes have in an oops
// report ("exe": the worker, re-executed from /proc/self/exe).
var scannerComms = map[string]bool{"exe": true, "zygarde": true}

// attachOops turns a failed Cell into a finding when the kernel oopsed while
// the worker ran. A healthy kernel does not oops because root reads sysfs or
// procfs files: it means the kernel followed a corrupt or dangling pointer
// behind a file the Cell read, which is what a rootkit leaves when it frees
// or overwrites kernel objects to hide.
func attachOops(r *core.Result, mark uint64, markOK bool, files []string) *core.Result {
	if r == nil || !markOK {
		return r
	}
	recs, err := readKmsg()
	if err != nil {
		return r
	}
	oopses := kmsg.Oopses(recs, mark)
	if len(oopses) == 0 {
		return r
	}
	for _, o := range oopses {
		d := map[string]string{
			"cell":     r.Cell,
			"oops":     o.Headline,
			"function": o.IP,
		}
		if o.Comm != "" {
			d["faulting_task"] = fmt.Sprintf("%s (%d)", o.Comm, o.PID)
			d["faulting_task_is_scanner"] = strconv.FormatBool(scannerComms[o.Comm])
		}
		if len(o.Trace) > 0 {
			d["call_trace"] = strings.Join(o.Trace, " < ")
		}
		if len(files) > 0 {
			d["files_being_read"] = strings.Join(files, ", ")
		}
		r.Findings = append(r.Findings, core.Finding{
			Description: fmt.Sprintf("The kernel oopsed (%s) while Zygarde was running the %q check", o.Summary(), r.Name),
			Details:     d,
			Why: "A healthy kernel does not oops because root reads sysfs or procfs files. It means the kernel followed " +
				"a corrupt or dangling pointer behind a file the check was reading: a kernel module freed or overwrote " +
				"the object that backs it. Rootkits do this when they hide (Diamorphine frees its module's section " +
				"attributes and leaves /sys/module/<name>/sections/* pointing at them). The files under " +
				"files_being_read name the likely culprit.",
			Benign: "A bug in a driver or in the kernel triggered by that file. Compare the call trace with known bug " +
				"reports and check whether a module the path belongs to is expected on this host.",
		})
	}
	if r.Error != "" {
		r.Limitations = append(r.Limitations, "This check did not complete: "+r.Error)
		r.Error = ""
	}
	r.Message = fmt.Sprintf("the kernel oopsed (%s) while this check ran, so it could not finish", oopses[0].Summary())
	r.SetStatus(core.StatusSuspicious)
	return r
}
