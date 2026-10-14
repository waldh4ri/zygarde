package core

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/waldh4ri/zygarde/internal/kernel"
)

// Settings are user-provided options that Cells may read.
type Settings struct {
	// BTFPath points to an external BTF file for kernels without
	// /sys/kernel/btf/vmlinux. Empty means use the kernel's own BTF.
	BTFPath string
}

// Env describes the system Zygarde runs on. It is probed once per worker and
// shared by all Cells. Everything here comes from sources other than bpf(),
// so it stays meaningful even when bpf() is being tampered with.
type Env struct {
	Settings Settings
	Log      *slog.Logger

	Arch     string // runtime.GOARCH
	Kernel   string // uname -r
	EUID     int
	Status   kernel.ProcStatus
	Lockdown string // "none", "integrity", "confidentiality" or "" if unknown

	// BTF is the kernel type information used for CO-RE, or nil if
	// unavailable (see BTFErr).
	BTF    *btf.Spec
	BTFErr error

	// MemlockErr is set if RLIMIT_MEMLOCK could not be lifted. Kernels before
	// 5.11 charge BPF memory to it, so bpf() may then fail with EPERM.
	MemlockErr error

	btfCache *btf.Cache

	kallsymsOnce sync.Once
	kallsyms     *kernel.Kallsyms
	kallsymsErr  error
}

// ProbeEnv gathers facts about the running system.
func ProbeEnv(settings Settings, log *slog.Logger) *Env {
	env := &Env{
		Settings: settings,
		Log:      log,
		Arch:     runtime.GOARCH,
		Kernel:   kernel.Release(),
		EUID:     os.Geteuid(),
		Lockdown: kernel.Lockdown(),
		btfCache: btf.NewCache(),
	}

	// No-op on kernels that account BPF memory to cgroups (5.11+).
	env.MemlockErr = rlimit.RemoveMemlock()

	st, err := kernel.SelfStatus()
	if err != nil {
		log.Debug("reading /proc/self/status failed", "err", err)
	}
	env.Status = st

	if settings.BTFPath != "" {
		env.BTF, env.BTFErr = btf.LoadSpec(settings.BTFPath)
	} else {
		env.BTF, env.BTFErr = btf.LoadKernelSpec()
	}

	log.Debug("environment",
		"arch", env.Arch, "kernel", env.Kernel, "euid", env.EUID,
		"capeff", fmt.Sprintf("%#x", st.CapEff), "seccomp", st.Seccomp,
		"lockdown", env.Lockdown, "btf", env.BTF != nil, "btf_err", env.BTFErr,
		"memlock_err", env.MemlockErr)
	return env
}

// Privileged reports whether the process has the privileges eBPF needs.
func (e *Env) Privileged() bool {
	return e.EUID == 0 || e.Status.HasCap(kernel.CapSysAdmin) || e.Status.HasCap(kernel.CapBPF)
}

// BPFExpected reports whether, judging only from non-bpf() sources, this
// process should be allowed to use eBPF. If it should, a permission error from
// bpf() is anomalous. The reason explains the verdict either way.
func (e *Env) BPFExpected() (bool, string) {
	switch {
	case !e.Privileged():
		return false, "process lacks CAP_BPF/CAP_SYS_ADMIN"
	case e.MemlockErr != nil:
		return false, fmt.Sprintf("RLIMIT_MEMLOCK could not be raised (%v); bpf() may fail on kernels before 5.11", e.MemlockErr)
	case e.Status.Seccomp != 0:
		return false, fmt.Sprintf("a seccomp filter is active (mode %d) and may deny bpf()", e.Status.Seccomp)
	default:
		lockdown := e.Lockdown
		if lockdown == "" {
			lockdown = "unavailable"
		}
		return true, fmt.Sprintf("running as root, no seccomp filter, lockdown=%s", lockdown)
	}
}

// RequireBTF returns a Skip error if kernel BTF is unavailable.
func (e *Env) RequireBTF() error {
	if e.BTF == nil {
		return Skip("kernel BTF unavailable (%v); a BTF-enabled kernel or --btf is required", e.BTFErr)
	}
	return nil
}

// RequireBTFType returns a Skip error if the kernel BTF lacks the named type.
// Checking types instead of version numbers follows distribution backports.
func (e *Env) RequireBTFType(name, feature string) error {
	if err := e.RequireBTF(); err != nil {
		return err
	}
	if _, err := e.BTF.AnyTypeByName(name); err != nil {
		return Skip("kernel lacks %s (no %q in BTF)", feature, name)
	}
	return nil
}

// RequireUserMemoryReads returns a Skip error if BPF programs that read user
// memory can't load. Under lockdown=confidentiality the kernel still allows
// bpf_probe_read_user(), but cilium/ebpf detects helper support by probing
// bpf_probe_read_kernel(), which lockdown denies; it then rewrites the calls
// to the legacy bpf_probe_read(), which lockdown denies too.
func (e *Env) RequireUserMemoryReads() error {
	if e.Lockdown == "confidentiality" {
		return Skip("kernel lockdown (confidentiality): cilium/ebpf downgrades bpf_probe_read_user() to bpf_probe_read(), which lockdown forbids")
	}
	return nil
}

// CollectionOptions returns the options Cells must use to load BPF objects.
func (e *Env) CollectionOptions() *ebpf.CollectionOptions {
	opts := &ebpf.CollectionOptions{Cache: e.btfCache}
	if e.Settings.BTFPath != "" {
		opts.Programs.KernelTypes = e.BTF
	}
	return opts
}

// Kallsyms returns the parsed /proc/kallsyms, loading it on first use.
func (e *Env) Kallsyms() (*kernel.Kallsyms, error) {
	e.kallsymsOnce.Do(func() {
		e.kallsyms, e.kallsymsErr = kernel.LoadKallsyms()
	})
	return e.kallsyms, e.kallsymsErr
}
