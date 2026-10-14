//go:build vmtest

package bpfprog

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"

	"github.com/waldh4ri/zygarde/internal/kernel"
)

// TestHelperAuditFlagsWriteUser loads, but never attaches, a program that
// calls bpf_probe_write_user and checks that the audit resolves the call.
// Run as root inside a test VM: go test -tags vmtest ./cells/bpfprog/
func TestHelperAuditFlagsWriteUser(t *testing.T) {
	_ = rlimit.RemoveMemlock()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "zyg_fixture",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R1, 0),
			asm.StoreMem(asm.R10, -8, asm.R1, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Imm(asm.R3, 8),
			asm.FnProbeWriteUser.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Skipf("kernel refused the fixture: %v", err)
	}
	defer prog.Close()

	ks, err := kernel.LoadKallsyms()
	if err != nil {
		t.Fatal(err)
	}
	base, ok := ks.Addr("__bpf_call_base")
	if !ok {
		t.Skip("no __bpf_call_base in kallsyms")
	}
	helpers, err := helperCalls(prog, ks, base)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(helpers, "bpf_probe_write_user") {
		t.Fatalf("helpers = %v, want bpf_probe_write_user", helpers)
	}
	if !helperRisk["bpf_probe_write_user"].suspicious {
		t.Error("bpf_probe_write_user must be classified suspicious")
	}
}
