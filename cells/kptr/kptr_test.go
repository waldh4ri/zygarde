package kptr

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kattr"
)

const kallsyms = `ffffffff81000000 T _stext
ffffffff81100000 t tcp_seq_start
ffffffff81100100 t tcp_seq_next
ffffffff81100200 t tcp_seq_stop
ffffffff81100300 t tcp4_seq_show
ffffffff81100400 t single_start
ffffffff81100500 t proc_reg_read
ffffffff81200000 T _etext
ffffffff81300000 d tcp4_seq_ops
ffffffff81400000 B _end
ffffffffc0001000 t tcp6_seq_show	[ipv6]
ffffffffc0003000 r tcp6_seq_ops	[ipv6]
ffffffffc0011000 t evil_show	[rootkit]
`

const modules = `ipv6 1048576 2 - Live 0xffffffffc0000000
rootkit 16384 0 - Live 0xffffffffc0010000
`

const vmallocinfo = `0xffffffffc0000000-0xffffffffc0002000 8192 load_module+0x1/0x2 pages=1 vmalloc
0xffffffffc0003000-0xffffffffc0004000 4096 load_module+0x1/0x2 pages=1 vmalloc
0xffffffffc0010000-0xffffffffc0012000 8192 load_module+0x1/0x2 pages=1 vmalloc
0xffffffffc0020000-0xffffffffc0022000 8192 load_module+0x1/0x2 pages=1 vmalloc
`

func resolver(t *testing.T) *kattr.Resolver {
	t.Helper()
	r, err := kattr.New(strings.NewReader(kallsyms), strings.NewReader(modules), nil, strings.NewReader(vmallocinfo))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestJudge(t *testing.T) {
	r := resolver(t)
	allowed := map[string]bool{"ipv6": true}
	cases := []struct {
		addr  uint64
		table bool
		want  verdict
	}{
		{0xffffffff81100300, false, ok},         // kernel code
		{0xffffffff81300000, true, ok},          // kernel table
		{0xffffffff81300000, false, observe},    // code pointer into kernel data
		{0xffffffffc0001000, false, ok},         // the protocol's own module
		{0xffffffffc0003000, true, ok},          // its table
		{0xffffffffc0011000, false, suspicious}, // an unrelated visible module
		{0xffffffffc0020010, false, suspicious}, // module memory nobody owns
		{0xffffffffc0020010, true, suspicious},  // copied table there
		{0xffff888000001000, true, suspicious},  // table on the heap
	}
	for _, c := range cases {
		if got, why := judge(r.Attribute(c.addr), c.table, allowed, true); got != c.want {
			t.Errorf("%#x table=%v: got %v (%s), want %v", c.addr, c.table, got, why, c.want)
		}
	}
	// Without /proc/vmallocinfo, an unplaced table is only observed.
	if got, _ := judge(kattr.Attribution{}, true, allowed, false); got != observe {
		t.Errorf("coarse unknown table: got %v", got)
	}
}

func tcpRecord(show uint64) *kptrOpsRec {
	rec := &kptrOpsRec{Flags: flagSeq | flagPDE, FileOps: 0xffffffff81300800, SeqOps: 0xffffffff81300000, PdeSeq: 0xffffffff81300000}
	rec.FileFn[1] = 0xffffffff81100500
	rec.SeqFn = [4]uint64{0xffffffff81100000, 0xffffffff81100100, 0xffffffff81100200, show}
	return rec
}

func run(t *testing.T, f *opened) (*core.Recorder, *checker) {
	t.Helper()
	rec := core.NewRecorder(slog.New(slog.DiscardHandler))
	ch := &checker{res: resolver(t), rec: rec}
	ch.check(f)
	return rec, ch
}

func TestCheckCleanAndCanary(t *testing.T) {
	f := &opened{target: target{path: canaryPath, symbols: map[string][]string{"seq_operations": {"tcp4_seq_ops"}}}, rec: tcpRecord(0xffffffff81100300)}
	rec, ch := run(t, f)
	if len(rec.Findings()) != 0 {
		t.Fatalf("unexpected findings: %+v", rec.Findings())
	}
	if kattr.BaseName(ch.canary) != canaryShow || ch.symbolsChecked != 1 {
		t.Errorf("canary %q, symbols checked %d", ch.canary, ch.symbolsChecked)
	}
}

func TestCheckSwappedShow(t *testing.T) {
	for name, show := range map[string]uint64{
		"hidden module":    0xffffffffc0020010,
		"unrelated module": 0xffffffffc0011000,
		"mid-function":     0xffffffff81100310,
	} {
		f := &opened{target: target{path: canaryPath}, rec: tcpRecord(show)}
		rec, _ := run(t, f)
		if len(rec.Findings()) != 1 {
			t.Errorf("%s: got %d findings, want 1: %+v", name, len(rec.Findings()), rec.Findings())
		}
	}
}

func TestCheckKallsymsMismatch(t *testing.T) {
	rec := tcpRecord(0xffffffff81100300)
	rec.SeqOps, rec.PdeSeq = 0xffffffff81300040, 0xffffffff81300040 // still kernel data, not where kallsyms says
	f := &opened{target: target{path: canaryPath, symbols: map[string][]string{"seq_operations": {"tcp4_seq_ops"}}}, rec: rec}
	r, _ := run(t, f)
	if len(r.Findings()) != 1 || !strings.Contains(r.Findings()[0].Description, "kallsyms disagrees") {
		t.Errorf("got %+v", r.Findings())
	}
}

func TestSingleOpenTableOnHeap(t *testing.T) {
	rec := &kptrOpsRec{Flags: flagSeq, FileOps: 0xffffffff81300800, SeqOps: 0xffff888000001000}
	rec.SeqFn = [4]uint64{0xffffffff81100400, 0xffffffff81100400, 0xffffffff81100400, 0xffffffff81100300}
	r, _ := run(t, &opened{target: target{path: "/proc/1/status"}, rec: rec})
	if len(r.Findings()) != 0 {
		t.Errorf("single_open table flagged: %+v", r.Findings())
	}
}
