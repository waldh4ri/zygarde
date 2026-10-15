package inlinehook

import (
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/kernel"
)

const base = 0xffffffff81000000

func TestDecodeEntry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   []byte
		kind   entryKind
		off    int
		target uint64
	}{
		{"ftrace nop", []byte{0x0f, 0x1f, 0x44, 0x00, 0x00, 0x55}, entryNop, 0, 0},
		{"endbr + nop", []byte{0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x1f, 0x44, 0x00, 0x00}, entryNop, 4, 0},
		{"sealed endbr + nop", []byte{0x0f, 0x1f, 0x40, 0xd6, 0x0f, 0x1f, 0x44, 0x00, 0x00}, entryNop, 4, 0},
		{"old sealed endbr + nop", []byte{0x66, 0x0f, 0x1f, 0x00, 0x0f, 0x1f, 0x44, 0x00, 0x00}, entryNop, 4, 0},
		{"endbr + call", []byte{0xf3, 0x0f, 0x1e, 0xfa, 0xe8, 0x10, 0x00, 0x00, 0x00}, entryCall, 4, base + 4 + 5 + 0x10},
		{"jmp rel32 backwards", []byte{0xe9, 0xfb, 0xff, 0xff, 0xff}, entryJump, 0, base},
		{"jmp rel8", []byte{0xeb, 0x02}, entryJump, 0, base + 4},
		{"jmp [rip+x]", []byte{0xff, 0x25, 0, 0, 0, 0}, entryIndirect, 0, 0},
		{"push imm32; ret", []byte{0x68, 0x00, 0x10, 0x00, 0xa0, 0xc3}, entryJump, 0, 0xffffffffa0001000},
		{"movabs rax; jmp rax", []byte{0x48, 0xb8, 0x00, 0x10, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0}, entryJump, 0, 0xffffffffc0001000},
		{"movabs r11; jmp r11", []byte{0x49, 0xbb, 0x00, 0x10, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x41, 0xff, 0xe3}, entryJump, 0, 0xffffffffc0001000},
		{"int3", []byte{0xcc, 0x1f, 0x44, 0x00, 0x00}, entryInt3, 0, 0},
		{"push rbp", []byte{0x55, 0x48, 0x89, 0xe5, 0, 0, 0, 0, 0, 0, 0, 0}, entryUnknown, 0, 0},
	} {
		code := make([]byte, 16)
		copy(code, tc.code)
		e := decodeEntry(code, base)
		if e.Kind != tc.kind || e.Offset != tc.off || e.Target != tc.target {
			t.Errorf("%s: got %v off=%d target=%#x, want %v off=%d target=%#x", tc.name, e.Kind, e.Offset, e.Target, tc.kind, tc.off, tc.target)
		}
	}
}

func TestJudge(t *testing.T) {
	ks, err := kernel.ParseKallsyms(strings.NewReader(`ffffffff81000000 T _stext
ffffffff81000100 T ftrace_caller
ffffffff81000200 T filldir64
ffffffff81000300 T other_fn
ffffffff82000000 T _etext
`))
	if err != nil {
		t.Fatal(err)
	}
	inText := func(a uint64) bool { return a >= 0xffffffff81000000 && a < 0xffffffff82000000 }
	f := function{"filldir64", "filldir64", 0xffffffff81000200}

	for _, tc := range []struct {
		name       string
		e          entry
		traced     map[string]bool
		haveTraced bool
		suspicious bool
		observed   bool
	}{
		{"nop", entry{Kind: entryNop}, nil, true, false, false},
		{"jump out of text", entry{Kind: entryJump, Target: 0xffffffffc0001000}, nil, true, true, false},
		{"jump inside text", entry{Kind: entryJump, Target: 0xffffffff81000300}, nil, true, false, true},
		{"call ftrace_caller", entry{Kind: entryCall, Target: 0xffffffff81000100}, nil, true, false, false},
		{"call trampoline, traced", entry{Kind: entryCall, Target: 0xffffffffc0002000}, map[string]bool{"filldir64": true}, true, false, false},
		{"call trampoline, not traced", entry{Kind: entryCall, Target: 0xffffffffc0002000}, map[string]bool{}, true, true, false},
		{"call trampoline, no tracefs", entry{Kind: entryCall, Target: 0xffffffffc0002000}, nil, false, false, true},
		{"indirect", entry{Kind: entryIndirect}, nil, true, true, false},
	} {
		susp, obs, _ := judge(tc.e, f, ks, inText, tc.traced, tc.haveTraced)
		if susp != tc.suspicious || (obs != "") != tc.observed {
			t.Errorf("%s: suspicious=%v observed=%q, want %v/%v", tc.name, susp, obs, tc.suspicious, tc.observed)
		}
	}
}
