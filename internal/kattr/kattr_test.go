package kattr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const kallsyms = `ffffffff81000000 T _stext
ffffffff81000000 T _text
ffffffff81100000 T tcp4_seq_show
ffffffff81100200 t proc_root_readdir
ffffffff81100400 t ext4_readdir.llvm.1234
ffffffff81200000 T _etext
ffffffff81300000 D tcp4_seq_ops
ffffffff81400000 B _end
ffffffffc0001000 t ext4_dir_open	[ext4]
ffffffffc0001100 t ext4_readdir	[ext4]
ffffffffc0003000 r ext4_dir_operations	[ext4]
ffffffffc0100000 t bpf_prog_6deef7357e7b4530_canary	[bpf]
ffffffffc0200000 t ftrace_trampoline	[__builtin__ftrace]
ffffffffc0300000 t kprobe_insn_page	[__builtin__kprobes]
`

const modules = `ext4 1048576 2 - Live 0xffffffffc0000000
mbcache 16384 1 ext4, Live 0xffffffffc0500000
jbd2 131072 1 ext4,ocfs2, Live 0xffffffffc0600000
`

const vmallocinfo = `0xffffffffc0000000-0xffffffffc0002000    8192 load_module+0x1b4/0x2010 pages=1 vmalloc N0=1
0xffffffffc0003000-0xffffffffc0004000    4096 load_module+0x1b4/0x2010 pages=1 vmalloc N0=1
0xffffffffc0100000-0xffffffffc0101000    4096 bpf_prog_pack_alloc+0x1f/0x100 pages=1 vmalloc
0xffffffffc0110000-0xffffffffc0111000    4096 bpf_jit_alloc_exec+0x10/0x20 pages=1 vmalloc
0xffffffffc0200000-0xffffffffc0201000    4096 arch_ftrace_update_trampoline+0x10/0x20 pages=1 vmalloc
0xffffffffc0300000-0xffffffffc0301000    4096 alloc_insn_page+0x10/0x20 pages=1 vmalloc
0xffffffffc0800000-0xffffffffc0802000    8192 load_module+0x1b4/0x2010 pages=1 vmalloc N0=1
0xffffc90000000000-0xffffc90000005000   20480 irq_init_percpu_irqstack+0x10/0x20 vmap
`

func resolver(t *testing.T, withVmalloc bool) *Resolver {
	t.Helper()
	var vm *strings.Reader
	if withVmalloc {
		vm = strings.NewReader(vmallocinfo)
	}
	secs := map[string]map[string]uint64{"ext4": {".text": 0xffffffffc0000000, ".rodata": 0xffffffffc0003000, ".init.text": 0xffffffffc0900000}}
	var r *Resolver
	var err error
	if vm != nil {
		r, err = New(strings.NewReader(kallsyms), strings.NewReader(modules), secs, vm)
	} else {
		r, err = New(strings.NewReader(kallsyms), strings.NewReader(modules), secs, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAttribute(t *testing.T) {
	cases := []struct {
		addr   uint64
		kind   Kind
		module string
		where  string
	}{
		{0xffffffff81100000, Kernel, "", "tcp4_seq_show+0x0 (kernel)"},
		{0xffffffff81100210, Kernel, "", "proc_root_readdir+0x10 (kernel)"},
		{0xffffffff81300000, KernelData, "", "tcp4_seq_ops+0x0 (kernel data)"},
		{0xffffffffc0001100, Module, "ext4", "ext4_readdir+0x0 (module ext4)"},
		{0xffffffffc0003010, Module, "ext4", "ext4_dir_operations+0x10 (module ext4)"},
		{0xffffffffc0100040, BPF, "", "bpf_prog_6deef7357e7b4530_canary+0x40 (BPF)"},
		{0xffffffffc0110000, BPF, "", "BPF"}, // jit_kallsyms off: allocator name
		{0xffffffffc0200010, Ftrace, "", "ftrace_trampoline+0x10 (ftrace trampoline)"},
		{0xffffffffc0300010, Kprobe, "", "kprobe_insn_page+0x10 (kprobe instruction page)"},
		{0xffffffffc0800010, Unknown, "", "unknown"}, // module allocation nobody owns
		{0xffffffffc0002010, Unknown, "", "unknown"}, // between allocations
		{0xffff888000001000, Unknown, "", "unknown"}, // heap
		{0, Unknown, "", "unknown"},
	}
	r := resolver(t, true)
	if !r.Precise() {
		t.Fatal("expected precise mode")
	}
	for _, c := range cases {
		a := r.Attribute(c.addr)
		if a.Kind != c.kind || a.Module != c.module || a.Where() != c.where {
			t.Errorf("%#x: got %+v (%s), want %v %q %q", c.addr, a, a.Where(), c.kind, c.module, c.where)
		}
	}
}

func TestAttributeWithoutVmalloc(t *testing.T) {
	r := resolver(t, false)
	if r.Precise() {
		t.Fatal("expected coarse mode")
	}
	for addr, want := range map[uint64]Kind{
		0xffffffffc0001100: Module,  // inside [base, base+size)
		0xffffffffc0100040: BPF,     // near a BPF symbol
		0xffffffffc0180000: Unknown, // too far from the BPF symbol
		0xffffffffc0200010: Ftrace,
		0xffff888000001000: Unknown,
	} {
		if a := r.Attribute(addr); a.Kind != want {
			t.Errorf("%#x: got %v, want %v", addr, a.Kind, want)
		}
	}
}

func TestHelpers(t *testing.T) {
	r := resolver(t, true)
	if got := r.Uses("ext4"); strings.Join(got, ",") != "jbd2,mbcache" {
		t.Errorf("Uses(ext4) = %v", got)
	}
	if got := r.CoreAddrs("ext4_readdir"); len(got) != 1 || got[0] != 0xffffffff81100400 {
		t.Errorf("CoreAddrs(ext4_readdir) = %x", got)
	}
	if BaseName("tcp4_seq_show.cfi_jt") != "tcp4_seq_show" || BaseName("foo") != "foo" {
		t.Error("BaseName")
	}
	if !r.InText(0xffffffff81000000) || r.InText(0xffffffff81200000) || !r.InImage(0xffffffff81300000) {
		t.Error("InText/InImage")
	}
}

func TestHiddenAddresses(t *testing.T) {
	_, err := New(strings.NewReader("0000000000000000 T _stext\n0000000000000000 T _etext\n"), nil, nil, nil)
	if err != ErrAddressesHidden {
		t.Errorf("got %v, want ErrAddressesHidden", err)
	}
	if _, err := ParseVmallocinfo(strings.NewReader("0x0000000000000000-0x0000000000000000 4096 foo\n")); err == nil {
		t.Error("hidden vmallocinfo accepted")
	}
	// Linux 5.10 with kptr_restrict=0 prints %pK as a hashed 32-bit value.
	hashed := "0x00000000ebbbae88-0x00000000c42472b8  147456 load_module+0xd97/0x2630 pages=35 vmalloc N0=35\n"
	if _, err := ParseVmallocinfo(strings.NewReader(hashed)); err == nil {
		t.Error("hashed vmallocinfo accepted")
	}
	mixed := hashed + "0xffffffffc0000000-0xffffffffc0002000    8192 load_module+0x1b4/0x2010 pages=1 vmalloc N0=1\n"
	areas, err := ParseVmallocinfo(strings.NewReader(mixed))
	if err != nil || len(areas) != 1 || areas[0].Start != 0xffffffffc0000000 {
		t.Errorf("mixed: got %v, %v", areas, err)
	}
}

func TestVmallocinfoFiveLevelPaging(t *testing.T) {
	// x86-64 with LA57: the vmalloc area starts at 0xffa0000000000000.
	in := "0xffa0000000000000-0xffa0000000002000    8192 load_module+0x1b4/0x2010 pages=1 vmalloc N0=1\n"
	areas, err := ParseVmallocinfo(strings.NewReader(in))
	if err != nil || len(areas) != 1 {
		t.Fatalf("got %v, %v", areas, err)
	}
}

func TestReadSectionsSkipsHiddenModules(t *testing.T) {
	dir := t.TempDir()
	mk := func(mod, sec, val string) {
		p := filepath.Join(dir, mod, "sections")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, sec), []byte(val+"\n"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	mk("ext4", ".text", "0xffffffffc0100000")
	mk("hidden_rootkit", ".text", "0xffffffffc0200000") // in /sys/module, not in /proc/modules

	all := ReadSections(dir, nil)
	if len(all) != 2 {
		t.Fatalf("nil filter should read every module: %v", all)
	}
	got := ReadSections(dir, map[string]bool{"ext4": true})
	if len(got) != 1 || got["ext4"][".text"] != 0xffffffffc0100000 {
		t.Fatalf("only visible modules should be read: %v", got)
	}
	if _, ok := got["hidden_rootkit"]; ok {
		t.Error("a module hidden from /proc/modules was read")
	}
}
