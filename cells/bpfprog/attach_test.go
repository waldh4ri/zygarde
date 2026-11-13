package bpfprog

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestSensitive(t *testing.T) {
	for name, want := range map[string]bool{
		"syscalls/sys_enter_getdents64": true,
		"sys_exit_getdents":             true,
		"__x64_sys_getdents64":          true,
		"filldir64":                     true,
		"sys_enter_bpf":                 true,
		"__arm64_sys_bpf":               true,
		"__x64_sys_kill":                true,
		"sys_enter_tgkill":              true,
		"__x64_sys_ptrace":              true,
		"sys_enter":                     true,
		"bpf_lsm_bpf":                   true,
		"bpf_lsm_file_open":             false,
		"sched_process_exec":            false,
		"__oom_kill_process":            false,
		"bpf_prog_load":                 false,
		"tcp_v4_connect":                false,
	} {
		if got := sensitive(name) != ""; got != want {
			t.Errorf("sensitive(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAttachTypeNameUAPI(t *testing.T) {
	for at, want := range map[ebpf.AttachType]string{
		ebpf.AttachCGroupInet4Bind:    "cgroup bind4",
		ebpf.AttachCGroupInet4Connect: "cgroup connect4",
		ebpf.AttachCGroupUDP4Sendmsg:  "cgroup udp4 sendmsg",
		ebpf.AttachCGroupSysctl:       "cgroup sysctl",
		ebpf.AttachTraceFEntry:        "fentry",
		ebpf.AttachModifyReturn:       "fmod_ret",
		ebpf.AttachLSMMac:             "lsm",
		ebpf.AttachSkLookup:           "netns sk_lookup",
		ebpf.AttachLSMCgroup:          "lsm cgroup",
		ebpf.AttachTCXEgress:          "tcx egress",
		ebpf.AttachNetkitPrimary:      "netkit primary",
	} {
		if got := attachTypeName(at); got != want {
			t.Errorf("attachTypeName(%d) = %q, want %q", uint32(at), got, want)
		}
	}
}

func TestInventoryAddMerges(t *testing.T) {
	inv := &inventory{attach: map[uint32][]attachment{}}
	inv.add(attachment{ProgID: 7, Where: "kprobe f", Via: "link #3", Link: 3})
	inv.add(attachment{ProgID: 7, Where: "kprobe f", Via: "perf event (fd 4 of process 9)"})
	inv.add(attachment{ProgID: 7, Where: "tracepoint t", Via: "link #4", Link: 4})
	inv.add(attachment{ProgID: 0, Where: "ignored"})
	if len(inv.attach[7]) != 2 || inv.attach[7][0].Via != "link #3; perf event (fd 4 of process 9)" {
		t.Errorf("got %+v", inv.attach)
	}
}
