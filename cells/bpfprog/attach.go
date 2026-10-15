package bpfprog

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// attachment is one place a BPF program is attached.
type attachment struct {
	ProgID uint32
	Where  string // e.g. "tracepoint syscalls/sys_enter_getdents64"
	Via    string // e.g. "link #12", "perf event (fd 5 of process 1234)"
	// Name is the bare kernel function or tracepoint, used to recognise
	// sensitive attach points.
	Name string
	// Link is the link ID, if the attachment is a BPF link.
	Link uint32
	// Net is set for XDP and tc attachments. The kernel holds these
	// programs through the interface, so no process needs to.
	Net bool
	// TCName is the tc filter's own name (TCA_BPF_NAME), for tc filters.
	TCName string
}

// sensitive returns what a sensitive attach point controls, or "".
//
// Hiding rootkits attach to directory enumeration (to drop entries), bpf()
// (to hide their own programs), and kill/ptrace (to protect their processes).
// sys_enter/sys_exit see every syscall, including those.
func sensitive(name string) string {
	n := name
	if i := strings.LastIndexAny(n, "/:"); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSuffix(n, "]")
	switch {
	case strings.Contains(n, "getdents"), strings.Contains(n, "filldir"),
		strings.Contains(n, "fillonedir"), n == "iterate_dir":
		return "directory listing (getdents)"
	case syscallNamed(n, "bpf"):
		return "the bpf() syscall"
	case syscallNamed(n, "kill"), syscallNamed(n, "tkill"), syscallNamed(n, "tgkill"):
		return "signal delivery (kill)"
	case syscallNamed(n, "ptrace"):
		return "ptrace()"
	case n == "sys_enter" || n == "sys_exit":
		return "every syscall (raw sys_enter/sys_exit)"
	}
	return ""
}

// syscallNamed matches a syscall's handlers and tracepoints: __x64_sys_kill,
// __arm64_sys_kill, __do_sys_kill, __se_sys_kill, sys_kill, sys_enter_kill...
func syscallNamed(n, sc string) bool {
	return strings.HasSuffix(n, "sys_"+sc) || n == "sys_enter_"+sc || n == "sys_exit_"+sc
}

// linkAttachments lists every BPF link with its attach point. It returns
// how many links were found and whether their info could be read.
func linkAttachments(env *core.Env, ks *kernel.Kallsyms, ifnames map[uint32]string) ([]attachment, []uint32, error) {
	var out []attachment
	var ids []uint32
	var it link.Iterator
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			continue
		}
		id := uint32(info.ID)
		ids = append(ids, id)
		a := attachment{ProgID: uint32(info.Program), Via: fmt.Sprintf("link #%d", id), Link: id}
		a.Where, a.Name = describeLink(env, ks, info, ifnames)
		a.Net = info.Type == link.XDPType || info.Type == link.TCXType || info.Type == link.NetkitType
		out = append(out, a)
	}
	if err := it.Err(); err != nil {
		return out, ids, core.WrapBPF("BPF_LINK_GET_NEXT_ID", err)
	}
	return out, ids, nil
}

func describeLink(env *core.Env, ks *kernel.Kallsyms, info *link.Info, ifnames map[uint32]string) (where, name string) {
	ifname := func(i uint32) string {
		if n, ok := ifnames[i]; ok {
			return n
		}
		return fmt.Sprintf("ifindex %d", i)
	}
	switch info.Type {
	case link.RawTracepointType:
		if rt := info.RawTracepoint(); rt != nil {
			return "raw tracepoint " + rt.Name, rt.Name
		}
		return "raw tracepoint", ""
	case link.TracingType:
		if tr := info.Tracing(); tr != nil {
			fn := btfName(env, tr.TargetObjectId, tr.TargetBtfId)
			return fmt.Sprintf("%s %s", attachTypeName(uint32(tr.AttachType)), fn), fn
		}
		return "tracing", ""
	case link.PerfEventType:
		if pe := info.PerfEvent(); pe != nil {
			switch {
			case pe.Kprobe() != nil:
				fn := pe.Kprobe().Function
				if fn == "" && ks != nil {
					fn, _ = ks.Name(pe.Kprobe().Address)
				}
				return "kprobe " + fn, fn
			case pe.Tracepoint() != nil:
				return "tracepoint " + pe.Tracepoint().Tracepoint, pe.Tracepoint().Tracepoint
			case pe.Uprobe() != nil:
				return "uprobe " + pe.Uprobe().File, ""
			}
		}
		return "perf event", ""
	case link.KprobeMultiType:
		if km := info.KprobeMulti(); km != nil {
			if addrs, ok := km.Addresses(); ok && ks != nil {
				var names []string
				for _, a := range addrs {
					if n, ok := ks.Name(a.Address); ok {
						names = append(names, n)
					}
				}
				return fmt.Sprintf("kprobe_multi on %d function(s): %s", km.Count, truncateList(names, 8)), strings.Join(names, " ")
			}
			return fmt.Sprintf("kprobe_multi on %d function(s)", km.Count), ""
		}
		return "kprobe_multi", ""
	case link.CgroupType:
		if cg := info.Cgroup(); cg != nil {
			return fmt.Sprintf("cgroup %d (%s)", cg.CgroupId, attachTypeName(uint32(cg.AttachType))), ""
		}
		return "cgroup", ""
	case link.XDPType:
		if x := info.XDP(); x != nil {
			return "XDP on " + ifname(x.Ifindex), ""
		}
		return "XDP", ""
	case link.TCXType:
		if t := info.TCX(); t != nil {
			return fmt.Sprintf("%s on %s", attachTypeName(uint32(t.AttachType)), ifname(t.Ifindex)), ""
		}
		return "tcx", ""
	case link.NetkitType:
		if n := info.Netkit(); n != nil {
			return fmt.Sprintf("%s on %s", attachTypeName(uint32(n.AttachType)), ifname(n.Ifindex)), ""
		}
		return "netkit", ""
	case link.NetNsType:
		if n := info.NetNs(); n != nil {
			return fmt.Sprintf("network namespace %d (%s)", n.NetnsInode, attachTypeName(uint32(n.AttachType))), ""
		}
		return "network namespace", ""
	case link.NetfilterType:
		if nf := info.Netfilter(); nf != nil {
			return fmt.Sprintf("netfilter (family %d, hook %d, priority %d)", nf.ProtocolFamily, nf.Hook, nf.Priority), ""
		}
		return "netfilter", ""
	case link.IterType:
		return "iterator", ""
	case link.StructOpsType:
		return "struct_ops", ""
	case link.UprobeMultiType:
		if um := info.UprobeMulti(); um != nil {
			return "uprobe_multi on " + um.File, ""
		}
		return "uprobe_multi", ""
	}
	return fmt.Sprintf("link type %d", info.Type), ""
}

// btfName resolves the function a tracing link (fentry, fexit, LSM...) is
// attached to. objID is a BTF object ID for kernel targets.
func btfName(env *core.Env, objID uint32, typeID btf.TypeID) string {
	fallback := fmt.Sprintf("BTF object %d type %d", objID, typeID)
	h, err := btf.NewHandleFromID(btf.ID(objID))
	if err != nil {
		return fallback
	}
	defer h.Close()
	var spec *btf.Spec
	if info, err := h.Info(); err == nil && info.IsVmlinux() && env.BTF != nil {
		spec = env.BTF
	} else if env.BTF != nil {
		if spec, err = h.Spec(env.BTF); err != nil {
			return fallback
		}
	} else {
		return fallback
	}
	t, err := spec.TypeByID(typeID)
	if err != nil || t.TypeName() == "" {
		return fallback
	}
	return t.TypeName()
}

// attachTypeName names a bpf_attach_type (include/uapi/linux/bpf.h).
func attachTypeName(t uint32) string {
	names := map[uint32]string{
		0: "cgroup ingress", 1: "cgroup egress", 2: "cgroup sock create", 3: "cgroup sock ops",
		6: "cgroup device", 8: "cgroup connect4", 9: "cgroup connect6", 17: "cgroup sysctl",
		18: "cgroup udp4 sendmsg", 19: "cgroup udp6 sendmsg", 21: "cgroup getsockopt", 22: "cgroup setsockopt",
		24: "fentry", 25: "fexit", 26: "fmod_ret", 27: "lsm", 28: "freplace", 29: "iterator",
		38: "netns sk_lookup", 40: "lsm cgroup", 46: "tcx ingress", 47: "tcx egress",
		50: "netkit primary", 51: "netkit peer",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("attach type %d", t)
}

func truncateList(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(", … (%d more)", len(s)-n)
}

// perfAttachments queries what each BPF-running perf event found in the
// kernel's file tables is attached to (BPF_TASK_FD_QUERY, as bpftool perf
// does). This covers programs attached through perf events without a BPF
// link (perf_event_open + PERF_EVENT_IOC_SET_BPF), invisible to link
// enumeration.
func perfAttachments(table *fdowner.Table, ks *kernel.Kallsyms) []attachment {
	var out []attachment
	for _, f := range table.Of(fdowner.Perf) {
		q, err := taskFDQuery(f.TGID, f.FD)
		a := attachment{ProgID: f.ProgID, Via: fmt.Sprintf("perf event (fd %d of process %d)", f.FD, f.TGID)}
		if err != nil {
			a.Where = "perf event"
			out = append(out, a)
			continue
		}
		name := q.name
		if name == "" && q.addr != 0 && ks != nil {
			name, _ = ks.Name(q.addr)
		}
		kinds := []string{"raw tracepoint", "tracepoint", "kprobe", "kretprobe", "uprobe", "uretprobe"}
		kind := "perf event"
		if int(q.fdType) < len(kinds) {
			kind = kinds[q.fdType]
		}
		if q.progID != 0 {
			a.ProgID = q.progID
		}
		a.Where = strings.TrimSpace(kind + " " + name)
		if q.fdType <= 3 { // not uprobes, whose name is a file path
			a.Name = name
		}
		out = append(out, a)
	}
	return out
}

type fdQuery struct {
	progID, fdType uint32
	name           string
	addr           uint64
}

// taskFDQuery calls BPF_TASK_FD_QUERY on another process's descriptor.
func taskFDQuery(pid, fd uint32) (fdQuery, error) {
	buf := make([]byte, 256)
	attr := struct {
		Pid, Fd, Flags, BufLen uint32
		Buf                    uint64
		ProgID, FdType         uint32
		ProbeOffset, ProbeAddr uint64
	}{Pid: pid, Fd: fd, BufLen: uint32(len(buf)), Buf: uint64(uintptr(unsafe.Pointer(&buf[0])))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_TASK_FD_QUERY, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(buf)
	if errno != 0 {
		if errors.Is(errno, unix.ENOENT) || errors.Is(errno, unix.EBADF) {
			return fdQuery{}, os.ErrNotExist
		}
		return fdQuery{}, errno
	}
	n := int(attr.BufLen)
	if n > len(buf) {
		n = len(buf)
	}
	return fdQuery{progID: attr.ProgID, fdType: attr.FdType, name: strings.TrimRight(string(buf[:n]), "\x00"), addr: attr.ProbeAddr}, nil
}
