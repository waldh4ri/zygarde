package bpfprog

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/waldh4ri/zygarde/internal/kernel"
)

func TestResolveHelpers(t *testing.T) {
	ks, err := kernel.ParseKallsyms(strings.NewReader(`ffffffff81100000 T __bpf_call_base
ffffffff81100400 T bpf_probe_write_user
ffffffff810fff00 T bpf_map_lookup_elem
`))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := ks.Addr("__bpf_call_base")

	call := func(imm int64) asm.Instruction {
		return asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: imm}
	}
	insns := asm.Instructions{
		call(0x400),   // after __bpf_call_base
		call(-0x100),  // before it: negative 32-bit offset
		call(0x99999), // unknown address
		asm.Return(),
	}
	got := resolveHelpers(insns, ks, base)
	if want := []string{"bpf_map_lookup_elem", "bpf_probe_write_user"}; !slices.Equal(got, want) {
		t.Errorf("resolveHelpers = %v, want %v", got, want)
	}
}
