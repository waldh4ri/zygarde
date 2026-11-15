package orphanns

import (
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/fdowner"
)

func TestParseNSLink(t *testing.T) {
	for in, want := range map[string]string{
		"net:[4026532260]":       "net:[4026532260]",
		"mnt:[4026531841]":       "mnt:[4026531841]",
		"cgroup:[4026531835]":    "cgroup:[4026531835]",
		"time:[4026531834]":      "time:[4026531834]",
		"socket:[123]":           "",
		"anon_inode:[eventpoll]": "",
		"/proc/1/ns/net":         "",
		"net:[abc]":              "",
	} {
		k, ok := parseNSLink(in)
		got := ""
		if ok {
			got = k.String()
		}
		if got != want {
			t.Errorf("parseNSLink(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNSFSMounts(t *testing.T) {
	in := `22 28 0:21 / /proc rw,nosuid shared:12 - proc proc rw
433 391 0:4 net:[4026532260] /run/netns/netns-33309c92 rw shared:347 - nsfs nsfs rw
456 46 0:4 mnt:[4026532150] /run/orph/my\040dir rw shared:348 - nsfs nsfs rw
457 46 0:4 / /nsfs-root rw shared:9 - nsfs nsfs rw
458 46 8:1 net:[1] /not-nsfs rw - ext4 /dev/sda1 rw
`
	got := parseNSFSMounts(in)
	if len(got) != 2 {
		t.Fatalf("got %d pins: %+v", len(got), got)
	}
	if got[0].key != (nsKey{"net", 4026532260}) || got[0].where != "/run/netns/netns-33309c92" || got[0].how != "bind mount" {
		t.Errorf("pin 0 = %+v", got[0])
	}
	if got[1].key != (nsKey{"mnt", 4026532150}) || got[1].where != "/run/orph/my dir" {
		t.Errorf("pin 1 = %+v", got[1])
	}
}

func TestOrphans(t *testing.T) {
	net1, net2, mnt1, usr1 := nsKey{"net", 1}, nsKey{"net", 2}, nsKey{"mnt", 3}, nsKey{"user", 4}
	v := &view{
		members: map[nsKey][]member{net1: {{tgid: 10}}, usr1: nil},
		pins: map[nsKey][]pin{
			net1: {{key: net1, how: "bind mount", where: "/run/netns/live"}}, // a process lives in it
			net2: {{key: net2, how: "bind mount", where: "/run/netns/x"}},
			mnt1: {{key: mnt1, how: "descriptor", pid: 7, comm: "x", fd: 4}},
			usr1: {{key: usr1, how: "bind mount", where: "/run/u"}},
		},
		sockets: map[uint64][]fdowner.FD{
			2: {{TGID: 7, FD: 5, Comm: "x"}}, // same namespace as the pin above
			9: {{TGID: 8, FD: 6, Comm: "y"}}, // held only by a socket
			1: {{TGID: 10, FD: 3}},           // namespace with a process
		},
	}
	got := orphans(v, map[nsKey]bool{usr1: true}) // usr1 owns a live namespace
	if len(got) != 3 {
		t.Fatalf("orphans = %v", sortedKeys(got))
	}
	if got[net1] != nil || got[usr1] != nil {
		t.Error("a namespace with a process, or an owner of one, was reported")
	}
	if o := got[net2]; o == nil || len(o.pins) != 1 || len(o.sockets) != 1 {
		t.Errorf("net 2 = %+v", o)
	}
	if o := got[nsKey{"net", 9}]; o == nil || len(o.pins) != 0 || len(o.sockets) != 1 {
		t.Errorf("socket-held net 9 = %+v", o)
	}
	if keys := sortedKeys(got); keys[0] != mnt1 {
		t.Errorf("order = %v", keys)
	}
	both := intersect(got, map[nsKey]*orphan{net2: {}})
	if len(both) != 1 || both[net2] == nil {
		t.Errorf("intersect = %v", both)
	}
}

func TestKnownLeftover(t *testing.T) {
	quiet := contents{kv: map[string]string{"interfaces": "lo"}}
	loud := contents{kv: map[string]string{"interfaces": "lo, d0"}, notable: true}
	bind := func(typ, path string) *orphan {
		return &orphan{key: nsKey{typ, 1}, pins: []pin{{how: "bind mount", where: path}}}
	}
	for _, tc := range []struct {
		name string
		o    *orphan
		c    contents
		want bool
	}{
		{"ip netns leftover", bind("net", "/run/netns/foo"), quiet, true},
		{"docker leftover", bind("net", "/run/docker/netns/abc"), quiet, true},
		{"rootless podman", bind("net", "/run/user/1000/netns/cni-1"), quiet, true},
		{"snap", bind("mnt", "/run/snapd/ns/lxd.mnt"), contents{}, true},
		{"netns with a device", bind("net", "/run/netns/foo"), loud, false},
		{"netns not inspected", bind("net", "/run/netns/foo"), contents{err: errEnterTimeout}, false},
		{"netns elsewhere", bind("net", "/run/orph/net"), quiet, false},
		{"hidden-looking dir", bind("net", "/var/lib/.x/net"), quiet, false},
		{"mount ns in netns dir", bind("mnt", "/run/netns/foo"), quiet, false},
		{"held by sockets", &orphan{key: nsKey{"net", 1}, pins: []pin{{how: "bind mount", where: "/run/netns/foo"}}, sockets: []fdowner.FD{{TGID: 5}}}, quiet, false},
		{"runtime descriptor", &orphan{key: nsKey{"net", 1}, pins: []pin{{how: "descriptor", comm: "containerd-shim"}}}, quiet, true},
		{"unknown descriptor", &orphan{key: nsKey{"net", 1}, pins: []pin{{how: "descriptor", comm: "orph-holder"}}}, quiet, false},
		{"no pin at all", &orphan{key: nsKey{"net", 1}}, quiet, false},
		{"path with traversal", bind("net", "/run/netns/../tmp/x"), quiet, false},
	} {
		if got := knownLeftover(tc.o, tc.c); got != tc.want {
			t.Errorf("%s: knownLeftover = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseNetTable(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55753 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 12345 1
   2: 0100007F:9C40 0100007F:2328 01 00000000:00000000 00:00000000 00000000     0        0 99 1
`
	n, l := parseNetTable(tcp, "tcp", false)
	if n != 3 || len(l) != 2 || l[0] != "tcp 0.0.0.0:9000" || l[1] != "tcp 127.0.0.1:53" {
		t.Errorf("tcp: %d %v", n, l)
	}
	udp := `  sl  local_address rem_address   st tx_queue
   0: 00000000:2328 00000000:0000 07 00000000:00000000
   1: 0100007F:1234 0100007F:5678 01 00000000:00000000
`
	if n, l := parseNetTable(udp, "udp", false); n != 2 || len(l) != 1 || l[0] != "udp 0.0.0.0:9000" {
		t.Errorf("udp: %d %v", n, l)
	}
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A
`
	if _, l := parseNetTable(tcp6, "tcp", true); len(l) != 1 || !strings.HasPrefix(l[0], "tcp [::1]:8080") {
		t.Errorf("tcp6: %v", l)
	}
	if n, l := parseNetTable("", "tcp", false); n != 0 || len(l) != 0 {
		t.Error("empty table")
	}
	if _, ok := parseProcAddr("zz:10", false); ok {
		t.Error("garbage address parsed")
	}
}

func TestParseMountSigs(t *testing.T) {
	a := parseMountSigs(`22 28 0:21 / /proc rw - proc proc rw
31 22 0:50 / /mnt rw - tmpfs orph rw
bad`)
	if len(a) != 2 {
		t.Fatalf("mounts = %v", a)
	}
	if _, ok := a[mountSig("/mnt", "tmpfs", "orph")]; !ok {
		t.Errorf("signature missing: %v", a)
	}
}

func TestInspectUTS(t *testing.T) {
	// inspectUTS reads /proc of the running system: only check the comparison.
	kv, err := inspectUTS("definitely-not-this-host")
	if err != nil {
		t.Skip("no procfs here")
	}
	if kv["notable"] == "" {
		t.Error("a hostname different from the host's should be notable")
	}
}

func TestNSFlags(t *testing.T) {
	seen := map[string]bool{}
	for _, typ := range nsFlags {
		seen[typ] = true
	}
	for _, want := range []string{"mnt", "net", "pid", "ipc", "uts", "user", "cgroup", "time"} {
		if !seen[want] {
			t.Errorf("no CLONE_NEW* flag maps to %q", want)
		}
	}
}

func TestDescriptorPinsTyping(t *testing.T) {
	// A descriptor of a namespace whose type is already known (it has a member, or
	// another pin names it) is typed without asking the kernel.
	v := &view{
		members: map[nsKey][]member{{"net", 10}: {{tgid: 1}}},
		pins:    map[nsKey][]pin{{"mnt", 20}: {{how: "bind mount", where: "/run/x"}}},
	}
	c := &Cell{proc: t.TempDir()}
	c.descriptorPins(v, []fdowner.FD{
		{TGID: 7, FD: 3, Inode: 10, Comm: "a"},
		{TGID: 8, FD: 4, Inode: 20, Comm: "b"},
		{TGID: 0, FD: 5, Inode: 10, Comm: "untranslatable"},
		{TGID: 9, FD: 6, Inode: 0, Comm: "no inode"},
	}, nil)
	if p := v.pins[nsKey{"net", 10}]; len(p) != 1 || p[0].pid != 7 || p[0].fd != 3 || p[0].comm != "a" || p[0].how != "descriptor" {
		t.Errorf("net pins = %+v", p)
	}
	if p := v.pins[nsKey{"mnt", 20}]; len(p) != 2 || p[1].pid != 8 {
		t.Errorf("mnt pins = %+v", p)
	}
}
