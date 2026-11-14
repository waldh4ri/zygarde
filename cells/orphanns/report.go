package orphanns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

// maxInspected bounds how many orphan namespaces are entered per scan.
const maxInspected = 256

// inspectBudget bounds the time spent entering orphans, well inside the Cell's timeout:
// a namespace that hangs a read costs up to enterTimeout.
const inspectBudget = 18 * time.Second

// leftoverPaths are where container runtimes and `ip netns` keep namespace
// files that outlive their processes: stopped containers, deleted network
// namespaces, snap mount namespaces.
var leftoverPaths = map[string]*regexp.Regexp{
	"net": regexp.MustCompile(`^/(var/)?run/(docker/)?netns/[^/]+$|^/run/user/[0-9]+/(docker/|containers/)?netns/[^/]+$`),
	"mnt": regexp.MustCompile(`^/run/snapd/ns/[^/]+$`),
}

// runtimeComms are processes that legitimately keep a descriptor of a
// namespace they do not live in.
var runtimeComms = map[string]bool{
	"dockerd": true, "containerd": true, "containerd-shim": true, "containerd-shim-runc-v2": true,
	"runc": true, "crun": true, "conmon": true, "podman": true, "crio": true, "kubelet": true,
	"systemd": true, "snapd": true, "snap-confine": true,
}

// knownLeftover reports whether an orphan namespace looks like one of the
// leftovers above: every pin is at a runtime's path or held by a runtime, no
// process holds a socket in it, and (for a network namespace) nothing in it
// beyond loopback.
func knownLeftover(o *orphan, c contents) bool {
	if len(o.sockets) > 0 || len(o.pins) == 0 {
		return false
	}
	for _, p := range o.pins {
		switch p.how {
		case "bind mount":
			re := leftoverPaths[o.key.typ]
			if re == nil || !re.MatchString(p.where) {
				return false
			}
		case "descriptor":
			if !runtimeComms[p.comm] {
				return false
			}
		default:
			return false
		}
	}
	if o.key.typ == "net" {
		return c.err == nil && !c.notable
	}
	return true // snap mount namespaces hold the snap's own mounts
}

// describeHolds lists what keeps the namespace alive, for humans.
func describeHolds(o *orphan) (how []string, holders []string) {
	for _, p := range o.pins {
		switch p.how {
		case "bind mount":
			how = append(how, "bind mount at "+p.where)
		case "descriptor":
			how = append(how, fmt.Sprintf("descriptor %d of process %d (%s)", p.fd, p.pid, p.comm))
			holders = append(holders, fmt.Sprintf("%d (%s)", p.pid, p.comm))
		}
	}
	if len(o.sockets) > 0 {
		by := map[uint32]string{}
		count := map[uint32]int{}
		for _, s := range o.sockets {
			by[s.TGID] = s.Comm
			count[s.TGID]++
		}
		var pids []uint32
		for p := range by {
			pids = append(pids, p)
		}
		sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
		for _, p := range pids {
			how = append(how, fmt.Sprintf("%d socket(s) of process %d (%s)", count[p], p, by[p]))
			holders = append(holders, fmt.Sprintf("%d (%s)", p, by[p]))
		}
	}
	return how, holders
}

func (c *Cell) hostMounts() map[string]bool {
	b, err := fsutil.ReadFileNoAtime(filepath.Join(c.proc, strconv.Itoa(os.Getppid()), "mountinfo"))
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for sig := range parseMountSigs(string(b)) {
		out[sig] = true
	}
	return out
}

func hostHostname() string {
	h, _ := os.Hostname()
	return h
}

func (c *Cell) report(ctx context.Context, env *core.Env, rec *core.Recorder, v *view, cand map[nsKey]*orphan) {
	keys := sortedKeys(cand)
	total := 0
	for _, ms := range v.members {
		if len(ms) > 0 {
			total++
		}
	}
	pinned := len(v.pins)
	if len(keys) == 0 {
		rec.Message("No orphan namespaces (%d namespaces with processes, %d pinned by mounts or descriptors, %d network namespaces with sockets)", total, pinned, len(v.sockets))
		return
	}

	start := time.Now()
	uninspected := 0
	host := c.hostMounts()
	hostname := hostHostname()
	suspicious, leftovers := 0, 0
	for i, k := range keys {
		if ctx.Err() != nil {
			return
		}
		o := cand[k]
		how, holders := describeHolds(o)
		var in contents
		switch {
		case i >= maxInspected:
			in.err = fmt.Errorf("more than %d orphan namespaces", maxInspected)
			uninspected++
		case time.Since(start) > inspectBudget:
			in.err = errors.New("time budget for entering namespaces used up")
			uninspected++
		default:
			in = c.inspect(o, host, hostname)
		}

		d := map[string]string{
			"type":    k.typ,
			"inode":   strconv.FormatUint(k.inum, 10),
			"kept_by": strings.Join(how, "; "),
		}
		if len(holders) > 0 {
			d["processes"] = strings.Join(holders, ", ")
		}
		for key, val := range in.kv {
			d[key] = val
		}
		if in.err != nil {
			d["contents"] = "not inspected: " + in.err.Error()
		}

		if knownLeftover(o, in) {
			leftovers++
			rec.Observe(fmt.Sprintf("Namespace %s has no process and is kept by a container runtime's leftover (%s)", k, strings.Join(how, "; ")), d)
			continue
		}
		suspicious++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("Namespace %s has no process but is kept alive by %s", k, strings.Join(how, "; ")),
			Details:     d,
			Why: "A namespace normally goes away with its last process. This one is held by something else, so what it contains " +
				"(files, listening sockets, network devices, shared memory) is out of reach of every check that starts from a process: " +
				"ps, ss, netstat, mountinfo and the kernel's task-based views never look at it. A rootkit can keep a listener, a stash " +
				"or firewall rules there, with the process that uses them elsewhere or gone.",
			Benign: "A leftover of a container or `ip netns add`, a snap's mount namespace, or a runtime holding the namespace " +
				"on purpose. Check the process that holds it and what the namespace contains (the evidence lists it).",
		})
	}
	if suspicious == 0 {
		rec.Message("%d orphan namespace(s), all leftovers of container runtimes; none with anything inside", leftovers)
	} else {
		rec.Message("%d orphan namespace(s) with no process (%d more look like container leftovers)", suspicious, leftovers)
	}
	if uninspected > 0 {
		rec.Limit("%d of %d orphan namespaces were not entered to list their contents (at most %d, within %s)", uninspected, len(keys), maxInspected, inspectBudget)
	}
}
