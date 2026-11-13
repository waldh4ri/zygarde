// Package file detects directory entries hidden from userspace, VFS
// iterate_shared function-pointer swaps, and executable dot-entries stashed in
// system binary and library directories.
package file

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type dirent_event file file.bpf.c -- -I../../bpf/include

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// Cell lists sensitive directories (under comm "ls" and with O_NOATIME),
// comparing entries produced by filldir64 with what getdents64 returns, while
// also verifying VFS iterate_shared pointers and checking system directories
// for hidden dot-executables.
type Cell struct{}

// New returns the hidden directory entry Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hidden_file" }
func (*Cell) Name() string           { return "Hidden File Detection" }
func (*Cell) Timeout() time.Duration { return 60 * time.Second }
func (*Cell) Description() string {
	return "Lists sensitive directories and /proc, comparing entries produced by the filesystem (kprobe on filldir64) with what getdents64 returns and verifying VFS directory handlers"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_ringbuf", "BPF ring buffers (Linux 5.8+)"); err != nil {
		return err
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
	return nil
}

type objects struct {
	filePrograms
	fileMaps
}

func (o *objects) Close() {
	o.filePrograms.Close()
	o.fileMaps.Close()
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	ks, err := env.Kallsyms()
	if err != nil {
		return fmt.Errorf("reading /proc/kallsyms: %w", err)
	}
	symbol, ok := filldirSymbol(ks)
	if !ok {
		return core.Skip("filldir64 not found in /proc/kallsyms")
	}

	spec, err := loadFile()
	if err != nil {
		return err
	}
	if err := bpfutil.SetTarget(env, spec); err != nil {
		return err
	}
	var objs objects
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return err
	}
	defer objs.Close()
	for _, p := range []*ebpf.Program{objs.OnFilldir64, objs.OnIterateDir} {
		if id, err := bpfutil.ProgramID(p); err == nil {
			rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
		}
	}

	kp, err := link.Kprobe(symbol, objs.OnFilldir64, nil)
	if err != nil {
		return core.WrapBPF("attach kprobe "+symbol, err)
	}
	defer kp.Close()

	// Optional VFS f_op->iterate_shared pointer check via iterate_dir.
	haveIterCheck := false
	if iterSym, ok := iterDirSymbol(ks); ok {
		if ikp, err := link.Kprobe(iterSym, objs.OnIterateDir, nil); err == nil {
			defer ikp.Close()
			haveIterCheck = true
		}
	}
	stext, _ := ks.Addr("_stext")
	etext, _ := ks.Addr("_etext")
	haveTextBounds := stext != 0 && etext > stext

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return core.WrapBPF("open ring buffer", err)
	}
	defer rd.Close()

	cf, err := canary.CreateFile(canary.ActiveFileDir())
	if err != nil {
		cf, err = canary.CreateFile(canary.FileDir)
		if err != nil {
			return fmt.Errorf("creating canary file: %w", err)
		}
	}
	defer cf.Remove()
	rec.Footprint("canary_file", cf.Path)

	system := map[string]bool{}
	for _, d := range systemDirs() {
		system[d] = true
	}
	seenSystem := map[string]bool{}
	checkedFops := map[uint64]bool{}

	listed, hidden, stashed, fopHooks := 0, 0, 0, 0
	for _, dir := range scanDirs() {
		if err := ctx.Err(); err != nil {
			return err
		}
		produced, returned, drops, err := listDir(rd, objs.DropCnt, dir)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
		}
		if err != nil {
			return err
		}
		listed++

		if haveIterCheck && haveTextBounds {
			fopHooks += checkDirFop(rec, ks, objs.DirFops, dir, stext, etext, checkedFops)
		}

		if system[dir] {
			all := map[string]bool{}
			for n := range produced {
				all[n] = true
			}
			for n := range returned {
				all[n] = true
			}
			stashed += dotEntries(rec, dir, all, seenSystem)
		}

		if drops > 0 {
			rec.Limit("Ring buffer dropped %d directory entries while listing %s; partial comparison skipped for that directory", drops, dir)
			continue
		}

		if dir == cf.Dir {
			name := filepath.Base(cf.Path)
			rec.Canary(cf.Path, "filesystem (filldir64)", produced[name])
			rec.Canary(cf.Path, "getdents64 result", returned[name])
		}

		missing := diff(produced, returned)
		if len(missing) == 0 {
			continue
		}
		// An entry deleted between two getdents64 calls can be produced once
		// (when it didn't fit in the buffer) and never returned: list again
		// and keep only entries missing both times.
		produced2, returned2, drops2, err := listDir(rd, objs.DropCnt, dir)
		if err != nil || drops2 > 0 {
			continue
		}
		for _, name := range intersect(missing, diff(produced2, returned2)) {
			hidden++
			path := filepath.Join(dir, name)
			details := map[string]string{"path": path, "directory": dir}
			fsutil.MergeMetadata(details, "", fsutil.FileMetadata(path))
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s exists but is filtered out of directory listings", path),
				Details:     details,
				Why: "The filesystem returned this entry, but it was removed before the listing reached " +
					"userspace, so ls, find and file managers can't see it. Under /proc this hides a process.",
				Benign: "Rare: some security products hide their own files this way. Identify what owns the entry " +
					"(open it by name: hidden entries usually remain accessible).",
			})
		}
	}

	switch {
	case hidden+fopHooks > 0 && stashed > 0:
		rec.Message("%d hidden entries/VFS hooks and %d executable dot-entries in system directories (%d directories)", hidden+fopHooks, stashed, listed)
	case hidden+fopHooks > 0:
		rec.Message("%d hidden directory entries or VFS hooks in %d directories", hidden+fopHooks, listed)
	case stashed > 0:
		rec.Message("No filtered entries; %d executable dot-entries in system directories (%d directories)", stashed, listed)
	default:
		rec.Message("No hidden entries in %d directories (including /proc)", listed)
	}
	return nil
}

// checkDirFop verifies that the VFS file_operations->iterate_shared handler
// invoked for dir belongs to core kernel text or a visible loaded module.
func checkDirFop(rec *core.Recorder, ks *kernel.Kallsyms, fopMap *ebpf.Map, dir string, stext, etext uint64, seen map[uint64]bool) int {
	st, err := os.Stat(dir)
	if err != nil {
		return 0
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0
	}
	var fnAddr uint64
	if err := fopMap.Lookup(sys.Ino, &fnAddr); err != nil || fnAddr == 0 || seen[fnAddr] {
		return 0
	}
	seen[fnAddr] = true
	if fnAddr >= stext && fnAddr < etext {
		return 0
	}
	if _, _, _, ok := ks.LookupModule(fnAddr); ok {
		return 0
	}
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("Directory %s uses an unattributed VFS iterate_shared handler at %#x", dir, fnAddr),
		Details: map[string]string{
			"directory":      dir,
			"iterate_shared": fmt.Sprintf("%#x", fnAddr),
		},
		Why: "file->f_op->iterate_shared produces directory entries before filldir64 runs. An address outside core " +
			"kernel text and every visible module points to a hidden kernel module hooking VFS directory iteration.",
		Benign: "None expected: standard filesystems live in the kernel or a visible loaded module.",
	})
	return 1
}

// filldirSymbol finds filldir64 in kallsyms; LTO builds may suffix it.
func filldirSymbol(ks *kernel.Kallsyms) (string, bool) {
	if ks.Has("filldir64") {
		return "filldir64", true
	}
	return ks.FirstWithPrefix("filldir64.")
}

func iterDirSymbol(ks *kernel.Kallsyms) (string, bool) {
	if ks.Has("iterate_dir") {
		return "iterate_dir", true
	}
	return ks.FirstWithPrefix("iterate_dir.")
}

func readDrops(m *ebpf.Map) uint64 {
	var zero uint32
	var v uint64
	if m != nil {
		_ = m.Lookup(zero, &v)
	}
	return v
}

// listDir lists dir with getdents64 (using O_NOATIME and comm "ls") while a
// background goroutine drains the BPF ring buffer concurrently, preventing
// ring-buffer saturation on large directories.
func listDir(rd *ringbuf.Reader, dropMap *ebpf.Map, dir string) (produced, returned map[string]bool, drops uint64, err error) {
	if _, err := drainAvailable(rd); err != nil { // discard anything unrelated
		return nil, nil, 0, err
	}
	dropsBefore := readDrops(dropMap)

	var (
		names   []string
		readErr error
		wg      sync.WaitGroup
	)
	rd.SetDeadline(time.Time{}) // block until listing finishes and sets a deadline
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			record, rerr := rd.Read()
			if errors.Is(rerr, os.ErrDeadlineExceeded) {
				return
			}
			if rerr != nil {
				readErr = fmt.Errorf("reading ring buffer: %w", rerr)
				return
			}
			if name, ok, derr := decodeDirent(record.RawSample); derr != nil {
				readErr = derr
				return
			} else if ok {
				names = append(names, name)
			}
		}
	}()

	entries, dirErr := fsutil.WithCommVal("ls", func() ([]os.DirEntry, error) {
		return fsutil.ReadDirNoAtime(dir)
	})
	// Events were submitted synchronously inside getdents64; expire the reader
	// now so the goroutine drains remaining queued events and returns.
	rd.SetDeadline(time.Now())
	wg.Wait()

	if dirErr != nil {
		return nil, nil, 0, dirErr
	}
	if readErr != nil {
		return nil, nil, 0, readErr
	}
	tail, err := drainAvailable(rd)
	if err != nil {
		return nil, nil, 0, err
	}
	names = append(names, tail...)
	dropsAfter := readDrops(dropMap)

	produced = make(map[string]bool, len(names))
	for _, n := range names {
		if n != "." && n != ".." {
			produced[n] = true
		}
	}
	returned = make(map[string]bool, len(entries))
	for _, e := range entries {
		returned[e.Name()] = true
	}
	return produced, returned, dropsAfter - dropsBefore, nil
}

func drainAvailable(rd *ringbuf.Reader) ([]string, error) {
	var names []string
	rd.SetDeadline(time.Now())
	for {
		record, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return names, nil
		}
		if err != nil {
			return names, fmt.Errorf("reading ring buffer: %w", err)
		}
		name, ok, derr := decodeDirent(record.RawSample)
		if derr != nil {
			return names, derr
		}
		if ok {
			names = append(names, name)
		}
	}
}

func decodeDirent(raw []byte) (string, bool, error) {
	evs, err := bpfutil.Decode[fileDirentEvent](raw)
	if err != nil || len(evs) != 1 {
		return "", false, fmt.Errorf("decoding dirent event: %v", err)
	}
	n := int(evs[0].Namlen)
	if n <= 0 || n > len(evs[0].Name) {
		return "", false, nil
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(evs[0].Name[i])
	}
	return string(b), true, nil
}

// scanDirs returns the directories to check: where binaries, libraries,
// persistence and staging usually live, plus /proc (hidden processes) and
// /sys/module (hidden modules).
func scanDirs() []string {
	dirs := []string{
		canary.ActiveFileDir(), canary.FileDir, "/", "/proc", "/sys/module",
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib",
		"/etc", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/init.d",
		"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
		"/etc/profile.d", "/etc/ld.so.conf.d", "/etc/modules-load.d", "/etc/udev/rules.d",
		"/var/spool/cron", "/var/spool/cron/crontabs",
		"/root", "/root/.ssh", "/home", "/opt", "/srv",
		"/var/tmp", "/dev/shm", "/dev", "/run",
	}
	dirs = append(dirs, systemDirs()...)
	if rel := kernel.Release(); rel != "unknown" {
		dirs = append(dirs, "/lib/modules/"+rel, "/lib/modules/"+rel+"/extra", "/lib/modules/"+rel+"/updates")
	}
	for _, p := range strings.Split(os.Getenv("PATH"), ":") {
		if filepath.IsAbs(p) {
			dirs = append(dirs, filepath.Clean(p))
		}
	}
	if homes, err := fsutil.ReadDirNoAtime("/home"); err == nil {
		for _, h := range homes {
			if h.IsDir() {
				dirs = append(dirs, filepath.Join("/home", h.Name()), filepath.Join("/home", h.Name(), ".ssh"))
			}
		}
	}
	return dedupe(dirs)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// diff returns names in a but not in b, sorted.
func diff(a, b map[string]bool) []string {
	var out []string
	for n := range a {
		if !b[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range b {
		set[s] = true
	}
	var out []string
	for _, s := range a {
		if set[s] {
			out = append(out, s)
		}
	}
	return out
}
