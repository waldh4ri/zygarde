package bpfprog

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// attachment is one place a BPF program is attached.
type attachment struct {
	ProgID     uint32
	Where      string // e.g. "tracepoint syscalls/sys_enter_getdents64"
	Via        string // e.g. "link #12", "perf event (fd 5 of process 1234)"
	Name       string // bare kernel function or tracepoint, used to recognise sensitive attach points
	AttachType ebpf.AttachType
	Link       uint32
	Net        bool   // XDP, tc, tcx, netkit
	TCName     string // TCA_BPF_NAME for tc filters
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
	case syscallNamed(n, "bpf") || n == "bpf_lsm_bpf":
		return "the bpf() syscall"
	case syscallNamed(n, "kill"), syscallNamed(n, "tkill"), syscallNamed(n, "tgkill"), n == "bpf_lsm_task_kill":
		return "signal delivery (kill)"
	case syscallNamed(n, "ptrace") || n == "bpf_lsm_ptrace_access_check":
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

// linkAttachments lists every BPF link with its attach point.
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
		a.Where, a.Name, a.AttachType = describeLink(env, ks, info, ifnames)
		a.Net = info.Type == link.XDPType || info.Type == link.TCXType || info.Type == link.NetkitType
		out = append(out, a)
	}
	if err := it.Err(); err != nil {
		return out, ids, core.WrapBPF("BPF_LINK_GET_NEXT_ID", err)
	}
	return out, ids, nil
}

func describeLink(env *core.Env, ks *kernel.Kallsyms, info *link.Info, ifnames map[uint32]string) (where, name string, at ebpf.AttachType) {
	ifname := func(i uint32) string {
		if n, ok := ifnames[i]; ok {
			return n
		}
		return fmt.Sprintf("ifindex %d", i)
	}
	switch info.Type {
	case link.RawTracepointType:
		if rt := info.RawTracepoint(); rt != nil {
			return "raw tracepoint " + rt.Name, rt.Name, ebpf.AttachTraceRawTp
		}
		return "raw tracepoint", "", ebpf.AttachTraceRawTp
	case link.TracingType:
		if tr := info.Tracing(); tr != nil {
			at := ebpf.AttachType(tr.AttachType)
			fn := btfName(env, tr.TargetObjectId, tr.TargetBtfId)
			return fmt.Sprintf("%s %s", attachTypeName(at), fn), fn, at
		}
		return "tracing", "", 0
	case link.PerfEventType:
		if pe := info.PerfEvent(); pe != nil {
			switch {
			case pe.Kprobe() != nil:
				fn := pe.Kprobe().Function
				if fn == "" && ks != nil {
					fn, _ = ks.Name(pe.Kprobe().Address)
				}
				return "kprobe " + fn, fn, ebpf.AttachPerfEvent
			case pe.Tracepoint() != nil:
				return "tracepoint " + pe.Tracepoint().Tracepoint, pe.Tracepoint().Tracepoint, ebpf.AttachPerfEvent
			case pe.Uprobe() != nil:
				return "uprobe " + pe.Uprobe().File, "", ebpf.AttachPerfEvent
			}
		}
		return "perf event", "", ebpf.AttachPerfEvent
	case link.KprobeMultiType:
		if km := info.KprobeMulti(); km != nil {
			if addrs, ok := km.Addresses(); ok && ks != nil {
				var names []string
				for _, a := range addrs {
					if n, ok := ks.Name(a.Address); ok {
						names = append(names, n)
					}
				}
				return fmt.Sprintf("kprobe_multi on %d function(s): %s", km.Count, truncateList(names, 8)), strings.Join(names, " "), ebpf.AttachTraceKprobeMulti
			}
			return fmt.Sprintf("kprobe_multi on %d function(s)", km.Count), "", ebpf.AttachTraceKprobeMulti
		}
		return "kprobe_multi", "", ebpf.AttachTraceKprobeMulti
	case link.CgroupType:
		if cg := info.Cgroup(); cg != nil {
			at := ebpf.AttachType(cg.AttachType)
			return fmt.Sprintf("cgroup %d (%s)", cg.CgroupId, attachTypeName(at)), "", at
		}
		return "cgroup", "", 0
	case link.XDPType:
		if x := info.XDP(); x != nil {
			return "XDP on " + ifname(x.Ifindex), "", ebpf.AttachXDP
		}
		return "XDP", "", ebpf.AttachXDP
	case link.TCXType:
		if t := info.TCX(); t != nil {
			at := ebpf.AttachType(t.AttachType)
			return fmt.Sprintf("%s on %s", attachTypeName(at), ifname(t.Ifindex)), "", at
		}
		return "tcx", "", 0
	case link.NetkitType:
		if n := info.Netkit(); n != nil {
			at := ebpf.AttachType(n.AttachType)
			return fmt.Sprintf("%s on %s", attachTypeName(at), ifname(n.Ifindex)), "", at
		}
		return "netkit", "", 0
	case link.NetNsType:
		if n := info.NetNs(); n != nil {
			at := ebpf.AttachType(n.AttachType)
			return fmt.Sprintf("network namespace %d (%s)", n.NetnsInode, attachTypeName(at)), "", at
		}
		return "network namespace", "", 0
	case link.NetfilterType:
		if nf := info.Netfilter(); nf != nil {
			return fmt.Sprintf("netfilter (family %d, hook %d, priority %d)", nf.ProtocolFamily, nf.Hook, nf.Priority), "", ebpf.AttachNetfilter
		}
		return "netfilter", "", ebpf.AttachNetfilter
	case link.IterType:
		return "iterator", "", ebpf.AttachTraceIter
	case link.StructOpsType:
		return "struct_ops", "", ebpf.AttachStructOps
	case link.UprobeMultiType:
		if um := info.UprobeMulti(); um != nil {
			return "uprobe_multi on " + um.File, "", ebpf.AttachTraceUprobeMulti
		}
		return "uprobe_multi", "", ebpf.AttachTraceUprobeMulti
	}
	return fmt.Sprintf("link type %d", info.Type), "", 0
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

// attachTypeName names an ebpf.AttachType using typed UAPI constants from
// cilium/ebpf (preventing enum-offset drift) and falls back to AttachType.String().
func attachTypeName(t ebpf.AttachType) string {
	names := map[ebpf.AttachType]string{
		ebpf.AttachCGroupInetIngress:      "cgroup ingress",
		ebpf.AttachCGroupInetEgress:       "cgroup egress",
		ebpf.AttachCGroupInetSockCreate:   "cgroup sock create",
		ebpf.AttachCGroupSockOps:          "cgroup sock ops",
		ebpf.AttachSkSKBStreamParser:      "sk_skb stream parser",
		ebpf.AttachSkSKBStreamVerdict:     "sk_skb stream verdict",
		ebpf.AttachCGroupDevice:           "cgroup device",
		ebpf.AttachSkMsgVerdict:           "sk_msg verdict",
		ebpf.AttachCGroupInet4Bind:        "cgroup bind4",
		ebpf.AttachCGroupInet6Bind:        "cgroup bind6",
		ebpf.AttachCGroupInet4Connect:     "cgroup connect4",
		ebpf.AttachCGroupInet6Connect:     "cgroup connect6",
		ebpf.AttachCGroupInet4PostBind:    "cgroup post_bind4",
		ebpf.AttachCGroupInet6PostBind:    "cgroup post_bind6",
		ebpf.AttachCGroupUDP4Sendmsg:      "cgroup udp4 sendmsg",
		ebpf.AttachCGroupUDP6Sendmsg:      "cgroup udp6 sendmsg",
		ebpf.AttachLircMode2:              "lirc mode2",
		ebpf.AttachFlowDissector:          "flow dissector",
		ebpf.AttachCGroupSysctl:           "cgroup sysctl",
		ebpf.AttachCGroupUDP4Recvmsg:      "cgroup udp4 recvmsg",
		ebpf.AttachCGroupUDP6Recvmsg:      "cgroup udp6 recvmsg",
		ebpf.AttachCGroupGetsockopt:       "cgroup getsockopt",
		ebpf.AttachCGroupSetsockopt:       "cgroup setsockopt",
		ebpf.AttachTraceRawTp:             "raw tracepoint",
		ebpf.AttachTraceFEntry:            "fentry",
		ebpf.AttachTraceFExit:             "fexit",
		ebpf.AttachModifyReturn:           "fmod_ret",
		ebpf.AttachLSMMac:                 "lsm",
		ebpf.AttachTraceIter:              "iterator",
		ebpf.AttachCgroupInet4GetPeername: "cgroup getpeername4",
		ebpf.AttachCgroupInet6GetPeername: "cgroup getpeername6",
		ebpf.AttachCgroupInet4GetSockname: "cgroup getsockname4",
		ebpf.AttachCgroupInet6GetSockname: "cgroup getsockname6",
		ebpf.AttachXDPDevMap:              "xdp devmap",
		ebpf.AttachCgroupInetSockRelease:  "cgroup sock release",
		ebpf.AttachXDPCPUMap:              "xdp cpumap",
		ebpf.AttachSkLookup:               "netns sk_lookup",
		ebpf.AttachXDP:                    "xdp",
		ebpf.AttachSkSKBVerdict:           "sk_skb verdict",
		ebpf.AttachSkReuseportSelect:      "sk_reuseport select",
		ebpf.AttachPerfEvent:              "perf event",
		ebpf.AttachTraceKprobeMulti:       "kprobe_multi",
		ebpf.AttachLSMCgroup:              "lsm cgroup",
		ebpf.AttachStructOps:              "struct_ops",
		ebpf.AttachNetfilter:              "netfilter",
		ebpf.AttachTCXIngress:             "tcx ingress",
		ebpf.AttachTCXEgress:              "tcx egress",
		ebpf.AttachTraceUprobeMulti:       "uprobe_multi",
		ebpf.AttachCgroupUnixConnect:      "cgroup unix connect",
		ebpf.AttachCgroupUnixSendmsg:      "cgroup unix sendmsg",
		ebpf.AttachCgroupUnixRecvmsg:      "cgroup unix recvmsg",
		ebpf.AttachCgroupUnixGetpeername:  "cgroup unix getpeername",
		ebpf.AttachCgroupUnixGetsockname:  "cgroup unix getsockname",
		ebpf.AttachNetkitPrimary:          "netkit primary",
		ebpf.AttachNetkitPeer:             "netkit peer",
	}
	if n, ok := names[t]; ok {
		return n
	}
	s := t.String()
	if s != "" && !strings.HasPrefix(s, "AttachType(") {
		return s
	}
	return fmt.Sprintf("attach type %d", uint32(t))
}

func truncateList(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(", … (%d more)", len(s)-n)
}

// perfAttachments queries what each BPF-running perf event found in the
// kernel's file tables is attached to (BPF_TASK_FD_QUERY, as bpftool perf
// does). Uses TID (falling back to TGID) so threads that called
// unshare(CLONE_FILES) have their own FD table queried accurately.
func perfAttachments(table *fdowner.Table, ks *kernel.Kallsyms) []attachment {
	var out []attachment
	for _, f := range table.Of(fdowner.Perf) {
		queryPID := f.TID
		if queryPID == 0 {
			queryPID = f.TGID
		}
		q, err := taskFDQuery(queryPID, f.FD)
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

// taskFDQuery calls BPF_TASK_FD_QUERY on another task's descriptor.
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
