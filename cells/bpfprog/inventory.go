package bpfprog

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fdowner"
)

// inventory is where every BPF program is attached and who holds it.
type inventory struct {
	attach   map[uint32][]attachment // by program ID
	links    []uint32
	table    *fdowner.Table  // nil if ownership could not be read
	listed   map[uint32]bool // PIDs listed in /proc; nil if not comparable
	pins     []pin
	pinned   map[uint32]string   // program ID -> pin keeping it loaded
	mapUsers map[uint32][]uint32 // map ID -> programs using it
}

// collect gathers the inventory. Parts that can't run here are recorded as
// limitations; none of them is fatal.
func collect(env *core.Env, rec *core.Recorder, progs map[uint32]bpfprogProgInfo) *inventory {
	inv := &inventory{attach: map[uint32][]attachment{}, mapUsers: map[uint32][]uint32{}}
	ks, _ := env.Kallsyms()

	names, xdp, err := interfaces()
	if err != nil {
		rec.Limit("XDP attachments not listed: %v", err)
	}
	tc, err := tcAttachments(names)
	if err != nil {
		rec.Limit("tc attachments not listed: %v", err)
	}
	links, linkIDs, err := linkAttachments(env, ks, names)
	if err != nil {
		rec.Limit("BPF links not fully listed: %v", err)
	}
	inv.links = linkIDs

	if err := fdowner.Supported(env); err != nil {
		rec.Limit("Owners of BPF objects not identified: %v", err)
	} else if inv.table, err = fdowner.Snapshot(env); err != nil {
		rec.Limit("Owners of BPF objects not identified: %v", err)
		inv.table = nil
	}
	var perf []attachment
	if inv.table != nil {
		perf = perfAttachments(inv.table, ks)
		if !inv.table.Learned[fdowner.Perf] {
			rec.Limit("Programs attached through perf events without a BPF link (tracepoints, kprobes) not listed: zygarde could not open a perf event")
		}
		if self, err := os.Readlink("/proc/self"); err == nil && self == strconv.Itoa(os.Getpid()) {
			if inv.listed, err = fdowner.ListedPIDs(); err != nil {
				rec.Limit("Owners of BPF objects not compared with /proc: %v", err)
			}
		} else {
			rec.Limit("Owners of BPF objects not compared with /proc: /proc belongs to another PID namespace")
		}
	}

	// XDP attached through a link is reported by both the link and netlink.
	linkedXDP := map[uint32]bool{}
	for _, a := range links {
		if a.Net && strings.HasPrefix(a.Where, "XDP") {
			linkedXDP[a.ProgID] = true
		}
	}
	for _, a := range xdp {
		if !linkedXDP[a.ProgID] {
			inv.add(a)
		}
	}
	for _, list := range [][]attachment{links, perf, tc} {
		for _, a := range list {
			inv.add(a)
		}
	}

	var st unix.Statfs_t
	if err := unix.Statfs(bpffsRoot, &st); err != nil || st.Type != unix.BPF_FS_MAGIC {
		rec.Limit("Pinned BPF objects not listed: no BPF filesystem is mounted at %s (objects pinned elsewhere look unowned)", bpffsRoot)
	}
	inv.pins = pins()
	inv.pinned = pinnedProgs(inv.pins)

	for id := range progs {
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
		if err != nil {
			continue
		}
		if info, err := prog.Info(); err == nil {
			if maps, ok := info.MapIDs(); ok {
				for _, m := range maps {
					inv.mapUsers[uint32(m)] = append(inv.mapUsers[uint32(m)], id)
				}
			}
		}
		prog.Close()
	}
	return inv
}

// add records an attachment. A perf event attached through a link shows up
// both as the link and as the perf event its owner holds: merge them.
func (inv *inventory) add(a attachment) {
	if a.ProgID == 0 {
		return
	}
	list := inv.attach[a.ProgID]
	for i := range list {
		if list[i].Where == a.Where {
			list[i].Via += "; " + a.Via
			if list[i].Link == 0 {
				list[i].Link = a.Link
			}
			return
		}
	}
	inv.attach[a.ProgID] = append(list, a)
}

// holders returns who holds an object, or nil if unknown.
func (inv *inventory) holders(kind fdowner.Kind, id uint32) []fdowner.Holder {
	if inv.table == nil {
		return nil
	}
	return inv.table.Holders(kind, uint64(id))
}

// wheres joins attachment points.
func wheres(atts []attachment) string {
	var s []string
	for _, a := range atts {
		s = append(s, a.Where+" ["+a.Via+"]")
	}
	return strings.Join(s, "; ")
}

// report records the inventory: ownership findings, attachments, unowned
// objects and pins. own lists zygarde's own programs, which are skipped.
func (inv *inventory) report(rec *core.Recorder, progs map[uint32]bpfprogProgInfo, enumSet map[uint32]bool, own map[uint32]bool, selfID uint32) {
	self := uint32(os.Getpid())
	if inv.table != nil {
		held := false
		for _, h := range inv.holders(fdowner.Prog, selfID) {
			held = held || h.TGID == self
		}
		rec.Canary(fmt.Sprintf("program #%d held by zygarde (process %d)", selfID, self), "process file tables (task_file iterator)", held)
	}

	ids := make([]uint32, 0, len(progs))
	for id := range progs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	reportedHidden := map[uint32]bool{}
	for _, id := range ids {
		if own[id] {
			continue
		}
		p := progs[id]
		name := bpfutil.Int8String(p.Name[:])
		atts := inv.attach[id]
		holders := inv.holders(fdowner.Prog, id)
		base := map[string]string{
			"program_id":   strconv.Itoa(int(id)),
			"program_name": name,
			"program_type": ebpf.ProgramType(p.Type).String(),
		}
		with := func(extra map[string]string) map[string]string {
			d := map[string]string{}
			for k, v := range base {
				d[k] = v
			}
			for k, v := range extra {
				if v != "" {
					d[k] = v
				}
			}
			return d
		}
		heldBy := fdowner.Describe(holders)
		label := fmt.Sprintf("#%d (%s)", id, name)
		if name == "" {
			label = fmt.Sprintf("#%d (unnamed)", id)
		}

		if inv.listed != nil && fdowner.HiddenOnly(holders, inv.listed) && fdowner.StillHidden(holders) {
			reportedHidden[id] = true
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("BPF program %s is held only by process(es) hidden from /proc: %s", label, heldBy),
				Details:     with(map[string]string{"held_by": heldBy, "attached_to": wheres(atts)}),
				Why: "A BPF program stays loaded while a process holds a descriptor to it. Every process holding this one " +
					"is missing from /proc, so the loader is hiding itself: the typical layout of an eBPF rootkit, whose " +
					"user-space part hides its own process.",
				Benign: "None expected: the holders were read from the kernel's task list, which /proc normally mirrors.",
			})
		}

		for _, a := range atts {
			if a.Net && (!enumSet[id] || (name == "" && a.TCName == "")) {
				why := "hidden from BPF_PROG_GET_NEXT_ID"
				if enumSet[id] {
					why = "has no name"
				}
				rec.Suspicious(core.Finding{
					Description: fmt.Sprintf("BPF program %s attached to %s %s", label, a.Where, why),
					Details:     with(map[string]string{"attached_to": a.Where, "via": a.Via, "tc_filter_name": a.TCName, "held_by": heldBy}),
					Why: "Programs on network interfaces see and can rewrite or drop every packet, which is how eBPF " +
						"backdoors run covert channels (e.g. port knocking on XDP, replies rewritten on tc egress). " +
						"Legitimate networking tools name their programs and don't hide them.",
					Benign: "Programs loaded by old iproute2 versions (tc/ip without libbpf) can be unnamed; the tc filter " +
						"name or the loading tool's configuration identifies them.",
				})
				continue
			}
			desc := fmt.Sprintf("BPF program %s is attached to %s", label, a.Where)
			if s := sensitive(a.Name); s != "" {
				desc += ", which controls " + s
			}
			pinnedAt := inv.pinned[id]
			rec.Observe(desc, with(map[string]string{"via": a.Via, "held_by": heldBy, "pinned_at": pinnedAt, "tc_filter_name": a.TCName}))
		}

		if inv.table != nil && len(holders) == 0 && inv.pinned[id] == "" && !anyNet(atts) {
			rec.Observe(fmt.Sprintf("BPF program %s is held by no process and is not pinned under %s", label, bpffsRoot), with(map[string]string{
				"attached_to": wheres(atts),
				"note": "kept alive by the kernel: e.g. attached with BPF_PROG_ATTACH (systemd's cgroup programs), " +
					"a tail-call target, or a struct_ops/LSM attachment",
			}))
		}
	}

	// Links whose holders are all hidden, unless their program was reported.
	if inv.listed != nil {
		for _, lid := range inv.links {
			holders := inv.holders(fdowner.Link, lid)
			if !fdowner.HiddenOnly(holders, inv.listed) || !fdowner.StillHidden(holders) {
				continue
			}
			var prog uint32
			for _, atts := range inv.attach {
				for _, a := range atts {
					if a.Link == lid {
						prog = a.ProgID
					}
				}
			}
			if reportedHidden[prog] || own[prog] {
				continue
			}
			rec.Suspicious(core.Finding{
				Description: fmt.Sprintf("BPF link #%d is held only by process(es) hidden from /proc: %s", lid, fdowner.Describe(holders)),
				Details:     map[string]string{"link_id": strconv.Itoa(int(lid)), "program_id": strconv.Itoa(int(prog)), "held_by": fdowner.Describe(holders)},
				Why: "A link keeps a program attached while a process holds it. Every holder of this one is missing " +
					"from /proc, so whoever attached it is hiding.",
				Benign: "None expected: the holders were read from the kernel's task list.",
			})
		}
	}

	for _, p := range inv.pins {
		if (p.Kind == fdowner.Prog && own[p.ID]) || (p.Kind == fdowner.Link && own[p.ProgID]) {
			continue
		}
		details := map[string]string{"path": p.Path, p.Kind.String() + "_id": strconv.Itoa(int(p.ID))}
		if p.Name != "" {
			details["name"] = p.Name
		}
		if h := fdowner.Describe(inv.holders(p.Kind, p.ID)); h != "" {
			details["held_by"] = h
		}
		switch p.Kind {
		case fdowner.Map:
			var users []string
			for _, pid := range inv.mapUsers[p.ID] {
				up := progs[pid]
				users = append(users, fmt.Sprintf("#%d (%s)", pid, bpfutil.Int8String(up.Name[:])))
			}
			details["used_by_programs"] = strings.Join(users, ", ")
		case fdowner.Link:
			details["program_id"] = strconv.Itoa(int(p.ProgID))
		}
		rec.Observe(fmt.Sprintf("Pinned BPF %s %s", p.Kind, p.Path), details)
	}
}

func anyNet(atts []attachment) bool {
	for _, a := range atts {
		if a.Net {
			return true
		}
	}
	return false
}
