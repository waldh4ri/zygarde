// Package netfilter inventories netfilter hooks in every network namespace
// and flags hook functions that belong to no visible module.
package netfilter

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type nf_rec netfilter netfilter.bpf.c -- -I../../bpf/include

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kattr"
)

// As in netfilter.bpf.c.
const (
	maxHooks       = 24
	recNetns       = 0
	recChain       = 1
	flagTruncated  = 1
	flagNoDevHooks = 2

	nfprotoIPv4   = 2
	nfprotoARP    = 3
	nfprotoNetdev = 5
	nfprotoBridge = 7
	nfprotoIPv6   = 10

	nfInetLocalOut = 3
)

// canaryPriority is the canary's place in the IPv4 LOCAL_OUT chain: after
// conntrack and the iptables/nftables tables, so it sees nothing they drop.
const canaryPriority = 1 << 20

// bpfRunner is the kernel function BPF netfilter links register as their hook.
const bpfRunner = "nf_hook_run_bpf"

// Cell reads, for every network namespace a task lives in, the netfilter
// hook functions registered at each hook point (IPv4, IPv6, ARP, bridge, and
// per-device ingress/egress), from struct net through a BPF task iterator.
//
// Kernel rootkits receive their commands through netfilter hooks: a hook sees
// every packet before any socket, so a "magic packet" can trigger a reverse
// shell or a privilege change while staying invisible to the network stack
// (Reptile, Diamorphine variants, Syslogk, FontOnLake, VoidLink). The hook
// function is an execution pointer: it must belong to the kernel, a visible
// module (conntrack, iptables, nftables, bridge) or a BPF netfilter link.
// One that belongs to nothing visible runs from a hidden module.
type Cell struct{}

// New returns the netfilter hook Cell.
func New() *Cell { return &Cell{} }

func (*Cell) ID() string             { return "netfilter_hooks" }
func (*Cell) Name() string           { return "Netfilter Hook Inventory" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Lists netfilter hook functions in every network namespace and flags hooks running code no visible module owns"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__task", "the BPF task iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if env.Lockdown == "confidentiality" {
		return core.Skip("kernel lockdown (confidentiality) forbids reading kernel memory from BPF")
	}
	if !hasMember(env.BTF, "netns_nf", "hooks_ipv4") {
		return core.Skip("kernel built without netfilter, or with a netfilter layout older than Linux 4.16")
	}
	return nil
}

func hasMember(spec *btf.Spec, typ, member string) bool {
	var s *btf.Struct
	if err := spec.TypeByName(typ, &s); err != nil {
		return false
	}
	for _, m := range s.Members {
		if m.Name == member {
			return true
		}
	}
	return false
}

// iterObjs are the objects needed on every kernel; the canary program is
// loaded separately, only where BPF netfilter programs exist.
type iterObjs struct {
	DumpHooks *ebpf.Program `ebpf:"dump_hooks"`
	Stats     *ebpf.Map     `ebpf:"stats"`
}

func (o *iterObjs) Close() {
	o.DumpHooks.Close()
	o.Stats.Close()
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	res, err := kattr.Load()
	if err != nil {
		return core.Skip("kernel symbols unavailable: %v", err)
	}
	selfNS, err := netnsInode()
	if err != nil {
		return err
	}

	spec, err := loadNetfilter()
	if err != nil {
		return err
	}
	planted, closeCanary := plantCanary(env, rec, spec)
	defer closeCanary()

	var objs iterObjs
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return err
	}
	defer objs.Close()
	data, err := bpfutil.ReadIter(objs.DumpHooks)
	closeCanary() // the canary only needs to exist while the hooks are read
	if err != nil {
		return err
	}
	recs, err := bpfutil.Decode[netfilterNfRec](data)
	if err != nil {
		return err
	}
	var dropped uint64
	if err := objs.Stats.Lookup(uint32(0), &dropped); err == nil && dropped > 0 {
		rec.Limit("%d network namespace(s) not checked: more than 4096 namespaces", dropped)
	}

	inv := analyse(recs, res)
	rec.Canary("zygarde's network namespace", "BPF task iterator", inv.namespaces[selfNS])
	if planted {
		rec.Canary("BPF netfilter link on IPv4 LOCAL_OUT", "hooks read from struct net", inv.bpfLocalOut[selfNS])
	}
	report(rec, inv, res)
	return nil
}

// plantCanary attaches a do-nothing BPF netfilter program to zygarde's
// namespace (Linux 6.4+). It reports whether it did, and returns a function
// detaching it, safe to call more than once.
func plantCanary(env *core.Env, rec *core.Recorder, spec *ebpf.CollectionSpec) (bool, func()) {
	nop := func() {}
	if env.BTF == nil {
		return false, nop
	}
	if _, err := env.BTF.AnyTypeByName("bpf_nf_ctx"); err != nil {
		rec.Limit("No canary hook: BPF netfilter programs need Linux 6.4+")
		return false, nop
	}
	var p struct {
		Prog *ebpf.Program `ebpf:"canary"`
	}
	if err := bpfutil.Load(env, spec, &p); err != nil {
		rec.Limit("No canary hook: the BPF netfilter program did not load (%v)", err)
		return false, nop
	}
	l, err := link.AttachNetfilter(link.NetfilterOptions{
		Program:        p.Prog,
		ProtocolFamily: link.NetfilterProtoIPv4,
		Hook:           link.NetfilterInetLocalOut,
		Priority:       canaryPriority,
	})
	if err != nil {
		p.Prog.Close()
		rec.Limit("No canary hook: attaching the BPF netfilter link failed (%v)", err)
		return false, nop
	}
	done := false
	return true, func() {
		if !done {
			done = true
			l.Close()
			p.Prog.Close()
		}
	}
}

func netnsInode() (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		return 0, fmt.Errorf("stat /proc/self/ns/net: %w", err)
	}
	return uint32(st.Ino), nil
}

// place is one hook point in one namespace.
type place struct {
	netns uint32
	pf    uint8
	hook  uint8
	dev   string
}

func (p place) String() string {
	s := hookName(p.pf, p.hook)
	if p.dev != "" {
		s += " on " + p.dev
	}
	return s
}

func hookName(pf, hook uint8) string {
	inet := []string{"PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"}
	arp := []string{"IN", "OUT", "FORWARD"}
	switch pf {
	case nfprotoIPv4, nfprotoIPv6, nfprotoBridge:
		fam := map[uint8]string{nfprotoIPv4: "ipv4", nfprotoIPv6: "ipv6", nfprotoBridge: "bridge"}[pf]
		if int(hook) < len(inet) {
			return fam + " " + inet[hook]
		}
	case nfprotoARP:
		if int(hook) < len(arp) {
			return "arp " + arp[hook]
		}
	case nfprotoNetdev:
		return map[uint8]string{0: "netdev ingress", 1: "netdev egress"}[hook]
	}
	return fmt.Sprintf("family %d hook %d", pf, hook)
}

// entry is one hook function found at a place.
type entry struct {
	place
	addr uint64
	attr kattr.Attribution
}

type inventory struct {
	namespaces  map[uint32]bool
	bpfLocalOut map[uint32]bool // a BPF netfilter link on ipv4 LOCAL_OUT
	entries     []entry
	truncated   []string // hook points with more than maxHooks entries
	devsCut     int      // namespaces with more devices than walked
	noDevHooks  bool
}

func analyse(recs []netfilterNfRec, res *kattr.Resolver) *inventory {
	inv := &inventory{namespaces: map[uint32]bool{}, bpfLocalOut: map[uint32]bool{}}
	for _, r := range recs {
		switch r.Kind {
		case recNetns:
			inv.namespaces[r.Inum] = true
			if r.Flags&flagTruncated != 0 {
				inv.devsCut++
			}
			if r.Flags&flagNoDevHooks != 0 {
				inv.noDevHooks = true
			}
		case recChain:
			p := place{netns: r.Inum, pf: r.Pf, hook: r.Hook}
			if r.Pf == nfprotoNetdev {
				p.dev = bpfutil.Int8String(r.Dev[:])
			}
			n := int(r.Num)
			if n > maxHooks {
				inv.truncated = append(inv.truncated, fmt.Sprintf("%s (netns %d, %d hooks)", p, p.netns, n))
				n = maxHooks
			}
			for i := 0; i < n; i++ {
				fn := r.Hooks[2*i]
				if fn == 0 {
					continue
				}
				a := res.Attribute(fn)
				if r.Pf == nfprotoIPv4 && r.Hook == nfInetLocalOut && a.Kind == kattr.Kernel && kattr.BaseName(a.Symbol) == bpfRunner {
					inv.bpfLocalOut[r.Inum] = true
				}
				inv.entries = append(inv.entries, entry{p, fn, a})
			}
		}
	}
	return inv
}

// maxObservations caps the per-function observations.
const maxObservations = 64

func report(rec *core.Recorder, inv *inventory, res *kattr.Resolver) {
	if len(inv.truncated) > 0 {
		sort.Strings(inv.truncated)
		rec.Limit("Only the first %d hooks of these hook points were checked: %s", maxHooks, strings.Join(inv.truncated, "; "))
	}
	if inv.devsCut > 0 {
		rec.Limit("%d network namespace(s) have more than 32 devices: per-device hooks of the others were not checked", inv.devsCut)
	}
	if inv.noDevHooks {
		rec.Limit("Kernel built without netfilter ingress hooks: per-device hooks not checked")
	}
	if !res.Precise() {
		rec.Limit("/proc/vmallocinfo unreadable: module ownership inferred from symbol distances")
	}

	// Group legitimate hooks by function for the observations.
	type group struct {
		attr   kattr.Attribution
		places map[string]bool
		netns  map[uint32]bool
	}
	groups := map[string]*group{}
	suspicious := 0
	for _, e := range inv.entries {
		details := map[string]string{
			"hook_point": e.place.String(),
			"netns":      fmt.Sprint(e.netns),
			"function":   fmt.Sprintf("%#x", e.addr),
			"owner":      e.attr.Where(),
		}
		switch e.attr.Kind {
		case kattr.Unknown:
			suspicious++
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("Netfilter hook at %s runs code at %#x that belongs to no visible module", e.place, e.addr),
				Details:     details,
				Why: "Every packet at this hook point is handed to this function before any socket sees it. It is " +
					"not in the kernel, a visible module or a BPF program, which is how a hidden module listens " +
					"for \"magic packets\" (Reptile, Diamorphine variants, Syslogk, FontOnLake, VoidLink).",
				Benign: "Rare. Check the address against /proc/modules and loaded BPF programs; a module unloading " +
					"during the scan leaves its hooks briefly.",
			})
			continue
		case kattr.KernelData:
			rec.Observe(fmt.Sprintf("Netfilter hook at %s points into kernel data, not code", e.place), details)
			continue
		}
		name := e.attr.Owner()
		if e.attr.Symbol != "" {
			name = kattr.BaseName(e.attr.Symbol) + " (" + e.attr.Owner() + ")"
		}
		if e.attr.Kind == kattr.Kernel && kattr.BaseName(e.attr.Symbol) == bpfRunner {
			name = "BPF netfilter link (" + bpfRunner + ")"
		}
		g := groups[name]
		if g == nil {
			g = &group{attr: e.attr, places: map[string]bool{}, netns: map[uint32]bool{}}
			groups[name] = g
		}
		g.places[e.place.String()] = true
		g.netns[e.netns] = true
	}

	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		if i == maxObservations {
			rec.Limit("%d more hook functions not listed", len(names)-maxObservations)
			break
		}
		g := groups[n]
		places := make([]string, 0, len(g.places))
		for p := range g.places {
			places = append(places, p)
		}
		sort.Strings(places)
		rec.Observe(fmt.Sprintf("Netfilter hook %s", n), map[string]string{
			"hook_points": strings.Join(places, ", "),
			"namespaces":  fmt.Sprint(len(g.netns)),
			"owner":       g.attr.Owner(),
		})
	}

	switch {
	case suspicious > 0:
		rec.Message("%d unattributed netfilter hook(s) among %d in %d network namespace(s)", suspicious, len(inv.entries), len(inv.namespaces))
	case len(inv.entries) == 0:
		rec.Message("No netfilter hooks registered in %d network namespace(s)", len(inv.namespaces))
	default:
		rec.Message("%d netfilter hook(s) in %d network namespace(s), all attributed to the kernel, visible modules or BPF", len(inv.entries), len(inv.namespaces))
	}
}
