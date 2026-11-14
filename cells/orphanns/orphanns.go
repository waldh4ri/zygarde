// Package orphanns detects namespaces that no process belongs to but that
// something else keeps alive, and says what is inside them.
//
// A namespace outlives its last process when a bind mount of its nsfs file
// (what `ip netns add` does), an open descriptor of it, or a socket created in
// it still references it. Everything that follows tasks (hidden process
// detection, netfilter hooks, socket tables, mount tables) never reaches such a
// namespace, which makes it a place to keep files, listeners, devices and
// firewall rules out of sight.
package orphanns

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-Wall -Werror -Wno-missing-declarations" -type ns_rec orphanns orphanns.bpf.c -- -I../../bpf/include

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
)

// Cell compares the namespaces the kernel's tasks live in with the namespaces
// that exist because something pins them.
type Cell struct {
	proc string
}

// New returns the orphan namespace Cell.
func New() *Cell { return &Cell{proc: "/proc"} }

func (*Cell) ID() string             { return "orphan_namespace" }
func (*Cell) Name() string           { return "Orphan Namespace Detection" }
func (*Cell) Timeout() time.Duration { return 30 * time.Second }
func (*Cell) Description() string {
	return "Finds namespaces that no process belongs to but that a bind mount, an open descriptor or a socket keeps alive, and reports what they contain"
}

func (*Cell) Supported(env *core.Env) error {
	if err := env.RequireBTFType("bpf_iter__task", "the BPF task iterator (Linux 5.8+)"); err != nil {
		return err
	}
	if err := fdowner.Supported(env); err != nil {
		return err
	}
	self, err := os.Readlink("/proc/self")
	if err != nil {
		return fmt.Errorf("reading /proc/self: %w", err)
	}
	if self != strconv.Itoa(os.Getpid()) {
		return core.Skip("/proc belongs to a different PID namespace than zygarde")
	}
	return nil
}

// nsTypes are the namespace kinds, as named in /proc/<pid>/ns and nsfs.
var nsTypes = []string{"mnt", "net", "pid", "ipc", "uts", "user", "cgroup", "time"}

// nsKey identifies a namespace: its type and nsfs inode number.
type nsKey struct {
	typ  string
	inum uint64
}

func (k nsKey) String() string { return fmt.Sprintf("%s:[%d]", k.typ, k.inum) }

// member is a process with at least one task in a namespace.
type member struct {
	tgid  uint32
	comm  string
	tasks int
}

// view is one reading of the namespace state.
type view struct {
	members map[nsKey][]member
	pins    map[nsKey][]pin
	sockets map[uint64][]fdowner.FD // by network namespace inode
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	spec, err := loadOrphanns()
	if err != nil {
		return err
	}
	var objs struct {
		Dump *ebpf.Program `ebpf:"dump_ns"`
	}
	if err := bpfutil.Load(env, spec, &objs); err != nil {
		return err
	}
	defer objs.Dump.Close()
	if id, err := bpfutil.ProgramID(objs.Dump); err == nil {
		rec.Footprint("bpf_prog_id", strconv.FormatUint(uint64(id), 10))
	}

	// Canary: a namespace kept alive only by a socket of ours. The check below
	// has to find it, or it would not find a rootkit's either.
	canary, err := newCanary()
	if err != nil {
		rec.Limit("The canary orphan namespace could not be created (%v): detection of namespaces held only by sockets was not validated", err)
	} else {
		defer canary.Close()
		rec.Footprint("canary_netns", strconv.FormatUint(canary.netns, 10))
	}

	v, err := c.read(env, objs.Dump, rec)
	if err != nil {
		return err
	}
	cand := orphans(v, c.referenced(v))
	if len(cand) > 0 {
		// A namespace of a process that just exited, or one being set up, shows up
		// for an instant: keep only what is still orphaned a moment later.
		select {
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
		if v2, err := c.read(env, objs.Dump, rec); err == nil {
			cand = intersect(cand, orphans(v2, c.referenced(v2)))
		}
	}
	if canary != nil {
		_, found := cand[nsKey{"net", canary.netns}]
		rec.Canary(fmt.Sprintf("network namespace %d held only by a socket", canary.netns), "kernel socket table against namespace members", found)
		delete(cand, nsKey{"net", canary.netns})
	}

	c.report(ctx, env, rec, v, cand)
	return nil
}

// read takes one reading of members, pins and socket namespaces.
func (c *Cell) read(env *core.Env, prog *ebpf.Program, rec *core.Recorder) (*view, error) {
	members, err := readMembers(prog)
	if err != nil {
		return nil, err
	}
	v := &view{members: members, pins: map[nsKey][]pin{}, sockets: map[uint64][]fdowner.FD{}}
	for _, p := range c.mountPins(members) {
		v.pins[p.key] = append(v.pins[p.key], p)
	}
	for _, p := range c.fdPins() {
		v.pins[p.key] = append(v.pins[p.key], p)
	}
	tab, err := fdowner.Snapshot(env)
	if err != nil {
		rec.Limit("Sockets were not checked for network namespaces without a process: %v", err)
	} else {
		for _, fd := range tab.Of(fdowner.Socket) {
			if fd.NetNS != 0 {
				v.sockets[uint64(fd.NetNS)] = append(v.sockets[uint64(fd.NetNS)], fd)
			}
		}
	}
	return v, nil
}

func readMembers(prog *ebpf.Program) (map[nsKey][]member, error) {
	data, err := bpfutil.ReadIter(prog)
	if err != nil {
		return nil, err
	}
	recs, err := bpfutil.Decode[orphannsNsRec](data)
	if err != nil {
		return nil, err
	}
	type slot struct {
		key  nsKey
		tgid uint32
	}
	out := map[nsKey][]member{}
	idx := map[slot]int{}
	for _, r := range recs {
		comm := bpfutil.Int8String(r.Comm[:])
		for _, ns := range []nsKey{
			{"mnt", uint64(r.Mnt)}, {"net", uint64(r.Net)}, {"pid", uint64(r.Pid)}, {"ipc", uint64(r.Ipc)},
			{"uts", uint64(r.Uts)}, {"user", uint64(r.User)}, {"cgroup", uint64(r.Cgroup)}, {"time", uint64(r.Time)},
			// A process that unshared a namespace but has not forked yet references it too.
			{"pid", uint64(r.PidChildren)}, {"time", uint64(r.TimeChildren)},
		} {
			if ns.inum == 0 {
				continue
			}
			s := slot{ns, r.Tgid}
			if i, ok := idx[s]; ok {
				out[ns][i].tasks++
				continue
			}
			idx[s] = len(out[ns])
			out[ns] = append(out[ns], member{tgid: r.Tgid, comm: comm, tasks: 1})
		}
	}
	return out, nil
}

// referenced returns the namespaces that are alive because a live one needs
// them: the user namespace that owns each namespace with a process in it, and
// the parents of user and PID namespaces. Such a namespace has no process of
// its own and is not an orphan.
func (c *Cell) referenced(v *view) map[nsKey]bool {
	out := map[nsKey]bool{}
	seen := map[nsKey]bool{}
	for k, ms := range v.members {
		if len(ms) == 0 || seen[k] {
			continue
		}
		seen[k] = true
		path := fmt.Sprintf("%s/%d/ns/%s", c.proc, ms[0].tgid, k.typ)
		for _, owner := range ownersOf(path, k.typ) {
			out[owner] = true
		}
	}
	return out
}

// orphan is a namespace without members, with what keeps it alive.
type orphan struct {
	key     nsKey
	pins    []pin
	sockets []fdowner.FD
}

// orphans lists the pinned namespaces that have no member and are not
// referenced by one that has.
func orphans(v *view, referenced map[nsKey]bool) map[nsKey]*orphan {
	out := map[nsKey]*orphan{}
	get := func(k nsKey) *orphan {
		if out[k] == nil {
			out[k] = &orphan{key: k}
		}
		return out[k]
	}
	for k, ps := range v.pins {
		if len(v.members[k]) == 0 && !referenced[k] {
			get(k).pins = append(get(k).pins, ps...)
		}
	}
	for inum, fds := range v.sockets {
		k := nsKey{"net", inum}
		if len(v.members[k]) == 0 && !referenced[k] {
			get(k).sockets = append(get(k).sockets, fds...)
		}
	}
	return out
}

func intersect(a, b map[nsKey]*orphan) map[nsKey]*orphan {
	out := map[nsKey]*orphan{}
	for k, o := range a {
		if _, ok := b[k]; ok {
			out[k] = o
		}
	}
	return out
}

func sortedKeys(m map[nsKey]*orphan) []nsKey {
	keys := make([]nsKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].typ != keys[j].typ {
			return keys[i].typ < keys[j].typ
		}
		return keys[i].inum < keys[j].inum
	})
	return keys
}

// stat of a nsfs file gives the namespace's inode number.
func nsInode(path string) (uint64, bool) {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return 0, false
	}
	return st.Ino, true
}
