package userhooks

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type vma_rec vma vma.bpf.c -- -I../../bpf/include

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// vmaKey identifies one executable mapping of one process instance.
type vmaKey struct {
	tgid       uint32
	startTime  uint64
	start, end uint64
}

// kernelExecVMAs reads every process's executable mappings from the kernel.
func kernelExecVMAs(prog *ebpf.Program) (map[vmaKey]vmaVmaRec, error) {
	data, err := bpfutil.ReadIter(prog)
	if err != nil {
		return nil, err
	}
	recs, err := bpfutil.Decode[vmaVmaRec](data)
	if err != nil {
		return nil, err
	}
	out := make(map[vmaKey]vmaVmaRec, len(recs))
	for _, r := range recs {
		// Only file-backed code: JIT compilers flip anonymous code between
		// writable and executable (W^X), so a read of maps can catch it
		// writable while every kernel snapshot sees it executable.
		if r.File == 0 {
			continue
		}
		out[vmaKey{r.Tgid, r.StartTime, r.Start, r.End}] = r
	}
	return out, nil
}

// execRanges returns the executable ranges /proc/<pid>/maps shows.
func (c *Cell) execRanges(pid uint32) ([][2]uint64, error) {
	var out [][2]uint64
	err := fsutil.WithComm("cat", func() error {
		f, err := fsutil.OpenNoAtime(filepath.Join(c.proc, strconv.Itoa(int(pid)), "maps"))
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if m, ok := parseMapLine(sc.Text()); ok && strings.Contains(m.perms, "x") {
				out = append(out, [2]uint64{m.start, m.end})
			}
		}
		return sc.Err()
	})
	return out, err
}

func overlaps(ranges [][2]uint64, start, end uint64) bool {
	for _, r := range ranges {
		if r[0] < end && start < r[1] {
			return true
		}
	}
	return false
}

// checkHiddenMappings compares the executable mappings in the kernel's VMA
// tree with /proc/<pid>/maps, which pmap, lsof, memory scanners and EDR agents
// read. A rootkit that injects a library into a process and filters its lines
// out of maps (by hooking the seq_file show function, or the read in libc)
// leaves the VMA in the kernel.
func (c *Cell) checkHiddenMappings(ctx context.Context, env *core.Env, rec *core.Recorder) (int, error) {
	n, err := c.compareMappings(ctx, env, rec)
	if err != nil && ctx.Err() == nil {
		// The rest of the Cell needs no BPF: keep it running.
		rec.Limit("Executable mappings not compared with the kernel's: %v", err)
		return n, nil
	}
	return n, err
}

func (c *Cell) compareMappings(ctx context.Context, env *core.Env, rec *core.Recorder) (int, error) {
	if err := env.RequireBTFType("bpf_iter__task_vma", "the BPF task VMA iterator (Linux 5.12+)"); err != nil {
		rec.Limit("Executable mappings not compared with the kernel's: %v", err)
		return 0, nil
	}
	if env.Lockdown == "confidentiality" {
		rec.Limit("Executable mappings not compared with the kernel's: kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
		return 0, nil
	}
	if self, err := os.Readlink(filepath.Join(c.proc, "self")); err != nil || self != strconv.Itoa(os.Getpid()) {
		rec.Limit("Executable mappings not compared with the kernel's: /proc belongs to another PID namespace")
		return 0, nil
	}
	spec, err := loadVma()
	if err != nil {
		return 0, err
	}
	var objs vmaObjects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return 0, err
	}
	defer objs.Close()
	if id, err := bpfutil.ProgramID(objs.DumpVma); err == nil {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}

	before, err := kernelExecVMAs(objs.DumpVma)
	if err != nil {
		return 0, err
	}
	pids := map[uint32]bool{}
	for k := range before {
		pids[k.tgid] = true
	}
	shown := make(map[uint32][][2]uint64, len(pids))
	for pid := range pids {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if r, err := c.execRanges(pid); err == nil {
			shown[pid] = r
		}
	}
	after, err := kernelExecVMAs(objs.DumpVma)
	if err != nil {
		return 0, err
	}

	// Canary: zygarde's own mappings are in both views.
	self := uint32(os.Getpid())
	selfKernel := 0
	for k := range before {
		if k.tgid == self {
			selfKernel++
		}
	}
	rec.Canary(fmt.Sprintf("executable mappings of zygarde (process %d)", self), "BPF task VMA iterator", selfKernel > 0)
	rec.Canary(fmt.Sprintf("executable mappings of zygarde (process %d)", self), "/proc/self/maps", len(shown[self]) > 0)

	// A mapping counts when it was in the kernel before and after maps was
	// read (same process instance, same range) and maps showed nothing executable over it.
	var cands []vmaKey
	for k := range before {
		if _, ok := after[k]; !ok {
			continue
		}
		r, read := shown[k.tgid]
		if !read || overlaps(r, k.start, k.end) {
			continue
		}
		cands = append(cands, k)
	}
	if len(cands) == 0 {
		rec.Observe(fmt.Sprintf("%d executable mappings of %d processes in the kernel are all shown in /proc/<pid>/maps", len(before), len(shown)), nil)
		return 0, nil
	}
	// Confirm: a second read of maps, then a third kernel snapshot.
	again := map[uint32][][2]uint64{}
	for _, k := range cands {
		if _, done := again[k.tgid]; done {
			continue
		}
		if r, err := c.execRanges(k.tgid); err == nil {
			again[k.tgid] = r
		}
	}
	last, err := kernelExecVMAs(objs.DumpVma)
	if err != nil {
		return 0, err
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].tgid != cands[j].tgid {
			return cands[i].tgid < cands[j].tgid
		}
		return cands[i].start < cands[j].start
	})
	n := 0
	for _, k := range cands {
		r, read := again[k.tgid]
		if _, ok := last[k]; !ok || !read || overlaps(r, k.start, k.end) {
			continue
		}
		v := before[k]
		pid := strconv.Itoa(int(k.tgid))
		rng := fmt.Sprintf("%x-%x", k.start, k.end)
		comm, _ := fsutil.ReadFileNoAtime(filepath.Join(c.proc, pid, "comm"))
		exe, _ := os.Readlink(filepath.Join(c.proc, pid, "exe"))
		d := map[string]string{
			"pid":      pid,
			"comm":     strings.TrimSpace(string(comm)),
			"exe":      exe,
			"range":    rng,
			"vm_flags": fmt.Sprintf("%#x", v.Flags),
		}
		what := "a file"
		d["inode"] = strconv.FormatUint(v.Ino, 10)
		// map_files is a separate view, looked up by the range itself.
		if target, err := os.Readlink(filepath.Join(c.proc, pid, "map_files", rng)); err == nil {
			d["file"] = target
			what = target
		}
		n++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Executable mapping %s of process %s (%s), from %s, is hidden from /proc/%s/maps", rng, pid, d["comm"], what, pid),
			Details:     d,
			Why: "The kernel's memory map of this process has executable code mapped from a file at this address, seen in three snapshots, " +
				"but /proc/" + pid + "/maps, read twice in between, shows nothing executable there. maps is rendered from that " +
				"same memory map, so a missing line means its output is filtered: rootkits hide a library they injected " +
				"into a process this way, from pmap, lsof and memory scanners.",
			Benign: "None expected: mappings that changed during the check are excluded.",
		})
	}
	return n, nil
}
