package bpfprog

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/waldh4ri/zygarde/internal/bpfutil"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
)

// helperRisk classifies BPF helpers that let a program act on the rest of the
// system rather than just observe it.
var helperRisk = map[string]struct {
	suspicious bool
	what       string
}{
	"bpf_probe_write_user":   {true, "writes into the memory of user processes (e.g. rewriting syscall results)"},
	"bpf_override_return":    {false, "changes the return value of kernel functions (error injection, enforcement)"},
	"bpf_send_signal":        {false, "sends signals to processes"},
	"bpf_send_signal_thread": {false, "sends signals to threads"},
}

// helperCalls resolves the helper functions a loaded program calls.
//
// In the translated instructions the kernel returns (BPF_OBJ_GET_INFO_BY_FD),
// a helper call's immediate is the helper's address relative to
// __bpf_call_base (bpf_insn_prepare_dump() in kernel/bpf/syscall.c), so
// kallsyms names it exactly.
func helperCalls(prog *ebpf.Program, ks *kernel.Kallsyms, callBase uint64) ([]string, error) {
	info, err := prog.Info()
	if err != nil {
		return nil, core.WrapBPF("BPF_OBJ_GET_INFO_BY_FD", err)
	}
	insns, err := info.Instructions()
	if err != nil {
		return nil, err
	}
	return resolveHelpers(insns, ks, callBase), nil
}

func resolveHelpers(insns asm.Instructions, ks *kernel.Kallsyms, callBase uint64) []string {
	seen := map[string]bool{}
	for _, ins := range insns {
		if !ins.IsBuiltinCall() || ins.Constant == 0 {
			continue
		}
		addr := callBase + uint64(int64(int32(ins.Constant)))
		if name, ok := ks.Name(addr); ok {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// auditHelpers records programs that call helpers able to modify the system.
// selfID is zygarde's own iterator program, whose bpf_seq_write() call must
// be resolved: a canary for the decoding itself.
func auditHelpers(rec *core.Recorder, env *core.Env, progs map[uint32]bpfprogProgInfo, selfID uint32) {
	ks, err := env.Kallsyms()
	if err != nil {
		rec.Limit("Capabilities of loaded BPF programs not audited: kernel symbols unavailable (%v)", err)
		return
	}
	callBase, ok := ks.Addr("__bpf_call_base")
	if !ok {
		rec.Limit("Capabilities of loaded BPF programs not audited: __bpf_call_base not in /proc/kallsyms")
		return
	}

	ids := make([]uint32, 0, len(progs))
	for id := range progs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var uninspectable []string
	for _, id := range ids {
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
		if err != nil {
			uninspectable = append(uninspectable, strconv.Itoa(int(id)))
			continue
		}
		helpers, err := helperCalls(prog, ks, callBase)
		prog.Close()
		if errors.Is(err, ebpf.ErrRestrictedKernel) {
			rec.Limit("Capabilities of loaded BPF programs not audited: the kernel restricts instruction dumps (kernel.kptr_restrict)")
			return
		}
		if err != nil {
			uninspectable = append(uninspectable, strconv.Itoa(int(id)))
			continue
		}

		if id == selfID {
			found := false
			for _, h := range helpers {
				found = found || h == "bpf_seq_write"
			}
			rec.Canary(fmt.Sprintf("bpf_seq_write() call of program #%d", id), "translated instructions", found)
			continue
		}

		p := progs[id]
		for _, h := range helpers {
			risk, ok := helperRisk[h]
			if !ok {
				continue
			}
			name := bpfutil.Int8String(p.Name[:])
			details := map[string]string{
				"program_id":   strconv.Itoa(int(id)),
				"program_name": name,
				"program_type": ebpf.ProgramType(p.Type).String(),
				"helper":       h,
				"capability":   risk.what,
				"all_helpers":  strings.Join(helpers, ", "),
			}
			desc := fmt.Sprintf("BPF program #%d (%s) calls %s: %s", id, name, h, risk.what)
			if risk.suspicious {
				rec.Suspicious(core.Finding{
					Description: desc,
					Details:     details,
					Why: "This helper lets a BPF program change what other processes read from their own memory, " +
						"e.g. rewrite a directory listing or a file's contents as a process receives them. Monitoring " +
						"and security tools almost never need it; eBPF rootkits rely on it.",
					Benign: "Debugging or research tools that use it deliberately. Identify what loaded the program " +
						"(bpftool prog show id <id> lists its owner and load time).",
				})
			} else {
				rec.Observe(desc, details)
			}
		}
	}
	if len(uninspectable) > 0 {
		rec.Limit("Capabilities of %d loaded BPF program(s) not audited: they could not be opened (IDs %s)",
			len(uninspectable), strings.Join(uninspectable, ", "))
	}
}
