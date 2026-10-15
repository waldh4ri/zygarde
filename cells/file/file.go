// Package file detects directory entries hidden from userspace, such as
// files, directories and /proc process entries filtered out of getdents64().
package file

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type dirent_event file file.bpf.c -- -I../../bpf/include

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// Cell lists a set of directories itself and compares, for each listing, the
// entries the filesystem produced (seen by a kprobe on filldir64, the
// callback that copies each entry into the getdents64 buffer) with the
// entries the syscall actually returned. An entry produced but not returned
// was filtered between the two: by a hooked getdents64, or by a program that
// rewrote the result buffer.
//
// Hiding done inside the filesystem itself (before filldir64) is not covered;
// hook_inventory reports hooks on the functions involved.
//
// It also flags dot-entries in binary and library directories, where stock
// installs have none and rootkits stash trojaned tools.
type Cell struct{}

// New returns the hidden directory entry Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "hidden_file" }
func (*Cell) Name() string           { return "Hidden File Detection" }
func (*Cell) Timeout() time.Duration { return 60 * time.Second }
func (*Cell) Description() string {
	return "Lists sensitive directories and /proc, comparing entries produced by the filesystem (kprobe on filldir64) with what getdents64 returns"
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

	kp, err := link.Kprobe(symbol, objs.OnFilldir64, nil)
	if err != nil {
		return core.WrapBPF("attach kprobe "+symbol, err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return core.WrapBPF("open ring buffer", err)
	}
	defer rd.Close()

	cf, err := canary.CreateFile(canary.FileDir)
	if err != nil {
		return fmt.Errorf("creating canary file: %w", err)
	}
	defer cf.Remove()

	system := map[string]bool{}
	for _, d := range systemDirs() {
		system[d] = true
	}
	seenSystem := map[string]bool{}

	listed, hidden, stashed := 0, 0, 0
	for _, dir := range scanDirs() {
		if err := ctx.Err(); err != nil {
			return err
		}
		produced, returned, err := listDir(rd, dir)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
		}
		if err != nil {
			return err
		}
		listed++

		if dir == canary.FileDir {
			name := filepath.Base(cf.Path)
			rec.Canary(cf.Path, "filesystem (filldir64)", produced[name])
			rec.Canary(cf.Path, "getdents64 result", returned[name])
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

		missing := diff(produced, returned)
		if len(missing) == 0 {
			continue
		}
		// An entry deleted between two getdents64 calls can be produced once
		// (when it didn't fit in the buffer) and never returned: list again
		// and keep only entries missing both times.
		produced2, returned2, err := listDir(rd, dir)
		if err != nil {
			return err
		}
		for _, name := range intersect(missing, diff(produced2, returned2)) {
			hidden++
			path := filepath.Join(dir, name)
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("%s exists but is filtered out of directory listings", path),
				Details:     map[string]string{"path": path, "directory": dir},
				Why: "The filesystem returned this entry, but it was removed before the listing reached " +
					"userspace, so ls, find and file managers can't see it. Under /proc this hides a process.",
				Benign: "Rare: some security products hide their own files this way. Identify what owns the entry " +
					"(open it by name: hidden entries usually remain accessible).",
			})
		}
	}

	switch {
	case hidden > 0 && stashed > 0:
		rec.Message("%d hidden directory entries and %d executable dot-entries in system directories (%d directories)", hidden, stashed, listed)
	case hidden > 0:
		rec.Message("%d hidden directory entries in %d directories", hidden, listed)
	case stashed > 0:
		rec.Message("No filtered entries; %d executable dot-entries in system directories (%d directories)", stashed, listed)
	default:
		rec.Message("No hidden entries in %d directories (including /proc)", listed)
	}
	return nil
}

// filldirSymbol finds filldir64 in kallsyms; LTO builds may suffix it.
func filldirSymbol(ks *kernel.Kallsyms) (string, bool) {
	if ks.Has("filldir64") {
		return "filldir64", true
	}
	return ks.FirstWithPrefix("filldir64.")
}

// listDir lists dir with getdents64 and returns the entry names the
// filesystem produced and the names the syscall returned.
func listDir(rd *ringbuf.Reader, dir string) (produced, returned map[string]bool, err error) {
	if _, err := drain(rd); err != nil { // discard anything unrelated
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	names, err := drain(rd)
	if err != nil {
		return nil, nil, err
	}
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
	return produced, returned, nil
}

// drain returns the names of all buffered events. Events are written
// synchronously during getdents64, so they are all present once it returns.
func drain(rd *ringbuf.Reader) ([]string, error) {
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
		evs, err := bpfutil.Decode[fileDirentEvent](record.RawSample)
		if err != nil || len(evs) != 1 {
			return names, fmt.Errorf("decoding dirent event: %v", err)
		}
		n := int(evs[0].Namlen)
		if n > len(evs[0].Name) {
			continue
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(evs[0].Name[i])
		}
		names = append(names, string(b))
	}
}

// scanDirs returns the directories to check: where binaries, libraries,
// persistence and staging usually live, plus /proc (hidden processes) and
// /sys/module (hidden modules).
func scanDirs() []string {
	dirs := []string{
		canary.FileDir, "/proc", "/sys/module",
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
	if homes, err := os.ReadDir("/home"); err == nil {
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
	set := make(map[string]bool, len(b))
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
