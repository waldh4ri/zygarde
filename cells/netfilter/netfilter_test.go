package netfilter

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kattr"
)

const kallsyms = `ffffffff81000000 T _stext
ffffffff81100000 t ipv4_conntrack_in
ffffffff81100100 t nf_hook_run_bpf
ffffffff81200000 T _etext
ffffffff81400000 B _end
ffffffffc0001000 t nft_do_chain_ipv4	[nf_tables]
`

const modules = "nf_tables 1048576 2 - Live 0xffffffffc0000000\n"

const vmallocinfo = `0xffffffffc0000000-0xffffffffc0002000 8192 load_module+0x1/0x2 pages=1 vmalloc
0xffffffffc0020000-0xffffffffc0022000 8192 load_module+0x1/0x2 pages=1 vmalloc
`

func chain(netns uint32, pf, hook uint8, num uint32, fns ...uint64) netfilterNfRec {
	r := netfilterNfRec{Inum: netns, Kind: recChain, Pf: pf, Hook: hook, Num: num}
	for i, f := range fns {
		r.Hooks[2*i] = f
	}
	return r
}

func TestAnalyse(t *testing.T) {
	res, err := kattr.New(strings.NewReader(kallsyms), strings.NewReader(modules), nil, strings.NewReader(vmallocinfo))
	if err != nil {
		t.Fatal(err)
	}
	dev := chain(2, nfprotoNetdev, 0, 1, 0xffffffffc0020040)
	copy(dev.Dev[:], []int8{'e', 't', 'h', '0'})
	recs := []netfilterNfRec{
		chain(1, nfprotoIPv4, 0, 2, 0xffffffff81100000, 0xffffffffc0001000),
		chain(1, nfprotoIPv4, nfInetLocalOut, 1, 0xffffffff81100100),
		{Inum: 1, Kind: recNetns},
		chain(2, nfprotoIPv6, 1, 30, 0xffffffff81100000),
		dev,
		{Inum: 2, Kind: recNetns, Flags: flagTruncated},
	}
	inv := analyse(recs, res)
	if !inv.namespaces[1] || !inv.namespaces[2] || !inv.bpfLocalOut[1] || inv.bpfLocalOut[2] {
		t.Errorf("namespaces %v, bpf canary %v", inv.namespaces, inv.bpfLocalOut)
	}
	if len(inv.truncated) != 1 || inv.devsCut != 1 {
		t.Errorf("truncated %v, devsCut %d", inv.truncated, inv.devsCut)
	}

	rec := core.NewRecorder(slog.New(slog.DiscardHandler))
	report(rec, inv, res)
	f := rec.Findings()
	if len(f) != 1 || !strings.Contains(f[0].Description, "netdev ingress on eth0") {
		t.Fatalf("findings: %+v", f)
	}
}

func TestHookName(t *testing.T) {
	for want, got := range map[string]string{
		"ipv4 PRE_ROUTING":  hookName(nfprotoIPv4, 0),
		"ipv6 POST_ROUTING": hookName(nfprotoIPv6, 4),
		"arp OUT":           hookName(nfprotoARP, 1),
		"bridge FORWARD":    hookName(nfprotoBridge, 2),
		"netdev egress":     hookName(nfprotoNetdev, 1),
		"family 12 hook 0":  hookName(12, 0),
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
