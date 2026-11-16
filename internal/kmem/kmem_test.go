package kmem

import (
	"errors"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/btf"
)

const base = 0xffffffffc0000000

func TestValid(t *testing.T) {
	for _, tc := range []struct {
		addr uint64
		n    int
		want bool
	}{
		{base, 8, true},
		{0x7fff00000000, 8, false},      // user space
		{0, 8, false},                   // NULL
		{base, 0, false},                // empty
		{0xfffffffffffffff8, 16, false}, // wraps
	} {
		if got := Valid(tc.addr, tc.n); got != tc.want {
			t.Errorf("Valid(%#x, %d) = %v, want %v", tc.addr, tc.n, got, tc.want)
		}
	}
	if runtime.GOARCH == "amd64" {
		for _, a := range []uint64{vsyscallPage, vsyscallPage + 100, vsyscallPage - 4} {
			if Valid(a, 8) {
				t.Errorf("Valid(%#x) = true inside the vsyscall page", a)
			}
		}
	}
}

func TestString(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"ext4\x00junk", "ext4", true},
		{"\x00", "", true}, // an empty setting, e.g. uevent_helper
		{"no terminator", "", false},
		{"Linux version 7.0.0 (gcc)\n\x00", "Linux version 7.0.0 (gcc)\n", true},
		{"esc\x1b[0m\x00", "", false},
		{"bin\xffary\x00", "", false},
	} {
		got, ok := String([]byte(tc.in))
		if got != tc.want || ok != tc.ok {
			t.Errorf("String(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPrefix(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"Linux version 6.8\x00tail", "Linux version 6.8", true},
		{"Linux version 6.8.0 longer than the read", "Linux version 6.8.0 longer than the read", true},
		{"Linux\x01version", "", false},
	} {
		got, ok := Prefix([]byte(tc.in))
		if got != tc.want || ok != tc.ok {
			t.Errorf("Prefix(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestReadStringsStopsAtPageEnd(t *testing.T) {
	m := NewFake()
	end := uint64(base + 4096 - 4)
	m.PutString(end, "abc") // the next page is unmapped
	s, ok, err := ReadStrings(m, []uint64{end}, 64)
	if err != nil || !ok[0] || s[0] != "abc" {
		t.Fatalf("ReadStrings = %q, %v, %v; want abc", s, ok, err)
	}
}

// list builds a circular list_head list at head through nodes.
func list(m *Fake, head uint64, nodes ...uint64) {
	all := append([]uint64{head}, nodes...)
	for i, n := range all {
		m.Put64(n, all[(i+1)%len(all)])
		m.Put64(n+8, all[(i+len(all)-1)%len(all)])
	}
}

func TestWalkList(t *testing.T) {
	m := NewFake()
	head, a, b := uint64(base), uint64(base+0x100), uint64(base+0x200)
	list(m, head, a, b)
	got, err := WalkList(m, head, 10)
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("WalkList = %#x, %v; want [a b]", got, err)
	}
	if got, err := WalkList(m, head, 1); err == nil {
		t.Errorf("WalkList over its bound = %#x, want an error", got)
	}

	m.Put64(b+8, head) // b's prev no longer a: a link changed under the walk
	if _, err := WalkList(m, head, 10); !errors.Is(err, ErrChanged) {
		t.Errorf("WalkList with a broken prev link: %v, want ErrChanged", err)
	}

	empty := NewFake()
	list(empty, head)
	if got, err := WalkList(empty, head, 10); err != nil || len(got) != 0 {
		t.Errorf("WalkList(empty) = %#x, %v", got, err)
	}

	unmapped := NewFake()
	unmapped.Put64(head, base+0x10000)
	unmapped.Put64(head+8, base+0x10000)
	if _, err := WalkList(unmapped, head, 10); err == nil {
		t.Error("WalkList through unmapped memory: want an error")
	}
}

func TestResolve(t *testing.T) {
	u64 := &btf.Int{Name: "u64", Size: 8}
	u32 := &btf.Int{Name: "u32", Size: 4}
	listHead := &btf.Struct{Name: "list_head", Size: 16, Members: []btf.Member{
		{Name: "next", Type: &btf.Pointer{Target: u64}},
		{Name: "prev", Type: &btf.Pointer{Target: u64}, Offset: 64},
	}}
	mem := &btf.Struct{Name: "module_memory", Size: 24, Members: []btf.Member{
		{Name: "base", Type: u64},
		{Name: "size", Type: u32, Offset: 64},
		{Name: "mtn", Type: u64, Offset: 128},
	}}
	typ := &btf.Struct{Name: "module", Size: 200, Members: []btf.Member{
		{Name: "state", Type: u32},
		{Name: "list", Type: listHead, Offset: 64},
		{Name: "", Type: &btf.Union{Size: 8, Members: []btf.Member{
			{Name: "bin_attrs", Type: u64},
			{Name: "bin_attrs_new", Type: u64},
		}}, Offset: 192},
		{Name: "mem", Type: &btf.Array{Type: mem, Nelems: 3}, Offset: 256},
	}}
	for _, tc := range []struct {
		path string
		want Field
	}{
		{"state", Field{0, 4}},
		{"list", Field{8, 16}},
		{"list.prev", Field{16, 8}},
		{"bin_attrs_new", Field{24, 8}},
		{"mem[0].mtn", Field{32 + 16, 8}},
		{"mem[2].size", Field{32 + 48 + 8, 4}},
	} {
		got, err := resolve(typ, tc.path)
		if err != nil || got != tc.want {
			t.Errorf("resolve(%q) = %+v, %v; want %+v", tc.path, got, err, tc.want)
		}
	}
	for _, bad := range []string{"missing", "mem[3].size", "state[0]", "mem[x]"} {
		if got, err := resolve(typ, bad); err == nil {
			t.Errorf("resolve(%q) = %+v, want an error", bad, got)
		}
	}
}
