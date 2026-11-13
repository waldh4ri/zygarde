package bpfprog

import (
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

const cgroupRoot = "/sys/fs/cgroup"

// cgroupQueryTypes are attach types commonly installed with legacy
// BPF_PROG_ATTACH (without a BPF link, e.g. systemd's sd_devices and sd_fw_*).
var cgroupQueryTypes = []ebpf.AttachType{
	ebpf.AttachCGroupInetIngress,
	ebpf.AttachCGroupInetEgress,
	ebpf.AttachCGroupInetSockCreate,
	ebpf.AttachCGroupSockOps,
	ebpf.AttachCGroupDevice,
	ebpf.AttachCGroupInet4Bind,
	ebpf.AttachCGroupInet6Bind,
	ebpf.AttachCGroupInet4Connect,
	ebpf.AttachCGroupInet6Connect,
	ebpf.AttachCGroupUDP4Sendmsg,
	ebpf.AttachCGroupUDP6Sendmsg,
	ebpf.AttachCGroupSysctl,
	ebpf.AttachCGroupGetsockopt,
	ebpf.AttachCGroupSetsockopt,
}

// cgroupAttachments walks the cgroup2 hierarchy and queries legacy
// BPF_PROG_ATTACH attachments (BPF_PROG_QUERY), deduplicating any already
// accounted for by a cgroup BPF link.
func cgroupAttachments(linkedProgCgroups map[string]bool) []attachment {
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil
	}

	const (
		maxDepth = 5
		maxDirs  = 512
	)
	var out []attachment
	visited := 0

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth || visited >= maxDirs {
			return
		}
		visited++
		f, err := fsutil.OpenNoAtime(dir)
		if err != nil {
			return
		}
		var cgID uint64
		if info, err := f.Stat(); err == nil {
			if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys != nil {
				cgID = sys.Ino
			}
		}
		for _, at := range cgroupQueryTypes {
			res, err := link.QueryPrograms(link.QueryOptions{
				Target: int(f.Fd()),
				Attach: at,
			})
			if err != nil || res == nil {
				continue
			}
			for _, p := range res.Programs {
				key := fmt.Sprintf("%d:%d:%d", p.ID, cgID, uint32(at))
				if linkedProgCgroups[key] {
					continue
				}
				where := fmt.Sprintf("cgroup %s (%s)", dir, attachTypeName(at))
				out = append(out, attachment{
					ProgID:     uint32(p.ID),
					Where:      where,
					Via:        "BPF_PROG_ATTACH",
					AttachType: at,
				})
			}
		}
		f.Close()

		entries, err := fsutil.ReadDirNoAtime(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				walk(filepath.Join(dir, e.Name()), depth+1)
			}
		}
	}
	walk(cgroupRoot, 0)
	return out
}

// progArrayTargets inspects loaded BPF_MAP_TYPE_PROG_ARRAY maps to attribute
// tail-call target programs that may have no direct link or FD holder.
func progArrayTargets() []attachment {
	mapIDs, err := fsutil.WithCommVal("bpftool", bpfutil.EnumerateMapIDs)
	if err != nil {
		return nil
	}
	var out []attachment
	for _, mid := range mapIDs {
		m, err := ebpf.NewMapFromID(ebpf.MapID(mid))
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil || info.Type != ebpf.ProgramArray || info.MaxEntries > 4096 {
			m.Close()
			continue
		}
		seen := map[uint32]bool{}
		for slot := uint32(0); slot < info.MaxEntries; slot++ {
			var progID uint32
			if err := m.Lookup(slot, &progID); err == nil && progID != 0 && !seen[progID] {
				seen[progID] = true
				label := fmt.Sprintf("prog_array map #%d", mid)
				if info.Name != "" {
					label += " (" + info.Name + ")"
				}
				out = append(out, attachment{
					ProgID: progID,
					Where:  "tail-call target in " + label,
					Via:    fmt.Sprintf("map #%d", mid),
				})
			}
		}
		m.Close()
	}
	return out
}
