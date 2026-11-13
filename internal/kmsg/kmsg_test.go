package kmsg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The oops Zygarde provoked by reading Diamorphine's dangling section
// attributes on Debian 11 (5.10), as /dev/kmsg shows it.
const dianOops = `6,480,289000000,-;hv_balloon: Max. dynamic memory size: 4096 MB
4,482,290715482,-;general protection fault, probably for non-canonical address 0x7fffffff80000000: 0000 [#1] SMP PTI
4,483,290715578,-;CPU: 0 PID: 1029 Comm: exe Tainted: G           OE     5.10.0-46-amd64 #1 Debian 5.10.262-1
4,484,290715654,-;Hardware name: Microsoft Corporation Virtual Machine/Virtual Machine, BIOS Hyper-V UEFI Release v4.1 09/25/2025
4,485,290715747,-;RIP: 0010:sysfs_kf_bin_read+0x57/0x70
4,486,290715788,-;Code: 29 c2 48 39 c1 4c 0f 47 ca 48 8b 0f 48 8b 51 60 48 8b 42 20 48 85 c0 74 1d 48 8b 49 08
4,487,290715939,-;RSP: 0018:ffffb38800defe10 EFLAGS: 00010206
4,495,290716452,-;Call Trace:
4,496,290716475,-; kernfs_fop_read_iter+0xa3/0x1b0
4,497,290716514,-; ? foo_unreliable+0x1/0x2
4,498,290716553,-; new_sync_read+0x119/0x1b0
4,499,290716586,-; vfs_read+0xf9/0x190
4,500,290716616,-; ksys_read+0x5f/0xe0
4,501,290716647,-; do_syscall_64+0x33/0x80
4,502,290716690,-; entry_SYSCALL_64_after_hwframe+0x67/0xd1
4,503,290716718,-;RIP: 0033:0x403f6e
4,504,290716868,-;RSP: 002b:000000c001f92b18 EFLAGS: 00000202 ORIG_RAX: 0000000000000000
4,520,290717900,-;---[ end trace 9f2b0cf3c7c6e1a1 ]---
6,521,290800000,-;usb 1-1: new high-speed USB device
4,540,332910123,-;general protection fault, probably for non-canonical address 0x7fffffff80000000: 0000 [#2] SMP PTI
4,541,332910472,-;CPU: 1 PID: 1038 Comm: exe Tainted: G      D    OE     5.10.0-46-amd64 #1 Debian 5.10.262-1
4,542,332911123,-;RIP: 0010:sysfs_kf_bin_read+0x57/0x70
`

func parseAll(t *testing.T, s string) []Record {
	t.Helper()
	var recs []Record
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		r, ok := parseRecord(line + "\n")
		if !ok {
			t.Fatalf("unparseable record %q", line)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestOopses(t *testing.T) {
	recs := parseAll(t, dianOops)
	got := Oopses(recs, 0)
	if len(got) != 2 {
		t.Fatalf("got %d oopses, want 2: %+v", len(got), got)
	}
	o := got[0]
	if o.PID != 1029 || o.Comm != "exe" || o.IP != "sysfs_kf_bin_read+0x57/0x70" || o.Seq != 482 {
		t.Errorf("first oops = %+v", o)
	}
	want := []string{"kernfs_fop_read_iter", "new_sync_read", "vfs_read", "ksys_read", "do_syscall_64", "entry_SYSCALL_64_after_hwframe"}
	if strings.Join(o.Trace, ",") != strings.Join(want, ",") { // the "? foo_unreliable" frame is dropped
		t.Errorf("trace = %v, want %v", o.Trace, want)
	}
	if s := o.Summary(); s != "general protection fault in sysfs_kf_bin_read+0x57/0x70" {
		t.Errorf("summary = %q", s)
	}
	if got[1].PID != 1038 || got[1].IP == "" {
		t.Errorf("second oops (cut off by the end of the log) = %+v", got[1])
	}

	// Only records after a mark.
	after := Oopses(recs, 500)
	if len(after) != 1 || after[0].PID != 1038 {
		t.Errorf("after seq 500: %+v", after)
	}
	if LastSeq(recs) != 542 {
		t.Errorf("LastSeq = %d", LastSeq(recs))
	}
	if len(Oopses(parseAll(t, "6,1,1,-;usb 1-1: new device\n6,2,2,-;eth0: link up"), 0)) != 0 {
		t.Error("ordinary log lines were taken for an oops")
	}
}

func TestParseRecord(t *testing.T) {
	r, ok := parseRecord("6,1234,5678901,-;hello world\n SUBSYSTEM=usb\n DEVICE=+usb:1-1\n")
	if !ok || r.Seq != 1234 || r.TimeUS != 5678901 || r.Msg != "hello world" {
		t.Errorf("got %+v %v", r, ok)
	}
	for _, bad := range []string{"", "no separator", "x,y;z", "6,abc,1,-;msg"} {
		if _, ok := parseRecord(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestReadFromMissingDevice(t *testing.T) {
	if _, err := readFrom(filepath.Join(t.TempDir(), "kmsg")); !os.IsNotExist(unwrap(err)) {
		t.Errorf("err = %v", err)
	}
}

func unwrap(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

func TestSummary(t *testing.T) {
	for _, tc := range []struct {
		o    Oops
		want string
	}{
		{Oops{Headline: "general protection fault, probably for non-canonical address 0x7f: 0000 [#1] SMP", IP: "sysfs_kf_bin_read+0x57/0x70"},
			"general protection fault in sysfs_kf_bin_read+0x57/0x70"},
		{Oops{Headline: "BUG: unable to handle page fault for address: ffff8f3a42a88bd8", IP: "0xffff8f3a42a88bd8"},
			"unable to handle page fault jumping to 0xffff8f3a42a88bd8, which is not a kernel symbol"},
		{Oops{Headline: "BUG: kernel NULL pointer dereference, address: 0000000000000008"}, "kernel NULL pointer dereference"},
		{Oops{Headline: "kernel BUG at mm/slub.c:3120!"}, "kernel BUG"},
	} {
		if got := tc.o.Summary(); got != tc.want {
			t.Errorf("Summary() = %q, want %q", got, tc.want)
		}
	}
}
