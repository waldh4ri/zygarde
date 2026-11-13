package inlinehook

import (
	"bytes"
	"encoding/binary"
)

// entryKind classifies the first instruction of a function (after an
// optional endbr64) on x86-64.
type entryKind int

const (
	entryUnknown  entryKind = iota // an ordinary instruction: no ftrace site
	entryNop                       // ftrace site, not in use
	entryCall                      // call rel32: ftrace site in use, or a hook
	entryJump                      // a jump: jmp rel32/rel8, push+ret, movabs+jmp
	entryIndirect                  // jmp *[rip+disp32]: target read from memory
	entryInt3                      // breakpoint: kprobe or code being patched
)

func (k entryKind) String() string {
	return [...]string{"unrecognised", "ftrace nop", "call", "jump", "indirect jump", "int3 breakpoint"}[k]
}

// entry is a decoded function entry.
type entry struct {
	Kind    entryKind
	Offset  int    // where the instruction starts (4 after endbr64, 9 if PostNop)
	Target  uint64 // for calls and jumps
	PostNop bool   // instruction sits immediately after a 5-byte ftrace NOP
	Gadget  bool   // push+ret or movabs+jmp trampoline gadget
}

var (
	// endbr64, and what the kernel turns unused ones into when it seals IBT
	// (arch/x86/kernel/alternative.c: "osp nopl (%rax)" before 6.9-ish,
	// "nopl -42(%rax)" since).
	endbrs = [][]byte{{0xf3, 0x0f, 0x1e, 0xfa}, {0x66, 0x0f, 0x1f, 0x00}, {0x0f, 0x1f, 0x40, 0xd6}}
	// 5-byte NOPs ftrace writes over its call site: P6 (all modern CPUs),
	// K8 and the 32-bit generic one some old kernels chose.
	nop5s = [][]byte{{0x0f, 0x1f, 0x44, 0x00, 0x00}, {0x66, 0x66, 0x90, 0x66, 0x90}, {0x3e, 0x8d, 0x74, 0x26, 0x00}}
)

// decodeEntry classifies the code at the start of a function at addr, and also
// checks the instruction immediately following an unused 5-byte ftrace NOP so
// hooks placed right past __fentry__ (to coexist with ftrace) are caught.
func decodeEntry(code []byte, addr uint64) entry {
	off := 0
	for _, e := range endbrs {
		if bytes.HasPrefix(code, e) {
			off = 4
			break
		}
	}
	c := code[off:]
	for _, n := range nop5s {
		if bytes.HasPrefix(c, n) {
			if post, ok := decodeBranch(c[5:], addr+uint64(off+5), off+5); ok && post.Kind != entryCall && post.Kind != entryInt3 {
				post.PostNop = true
				return post
			}
			return entry{Kind: entryNop, Offset: off}
		}
	}
	if br, ok := decodeBranch(c, addr+uint64(off), off); ok {
		return br
	}
	return entry{Kind: entryUnknown, Offset: off}
}

func decodeBranch(c []byte, at uint64, off int) (entry, bool) {
	rel := func(n, size int) uint64 {
		var d int64
		switch size {
		case 1:
			d = int64(int8(c[n]))
		case 4:
			d = int64(int32(binary.LittleEndian.Uint32(c[n:])))
		}
		return at + uint64(n+size) + uint64(d)
	}
	switch {
	case len(c) >= 5 && c[0] == 0xe8:
		return entry{Kind: entryCall, Offset: off, Target: rel(1, 4)}, true
	case len(c) >= 5 && c[0] == 0xe9:
		return entry{Kind: entryJump, Offset: off, Target: rel(1, 4)}, true
	case len(c) >= 2 && c[0] == 0xeb:
		return entry{Kind: entryJump, Offset: off, Target: rel(1, 1)}, true
	case len(c) >= 6 && c[0] == 0xff && c[1] == 0x25:
		return entry{Kind: entryIndirect, Offset: off}, true
	case len(c) >= 6 && c[0] == 0x68 && c[5] == 0xc3: // push imm32; ret
		return entry{Kind: entryJump, Offset: off, Target: uint64(int64(int32(binary.LittleEndian.Uint32(c[1:])))), Gadget: true}, true
	case len(c) >= 12 && (c[0] == 0x48 || c[0] == 0x49) && c[1] >= 0xb8 && c[1] <= 0xbf:
		// movabs $imm64, %reg followed by jmp *%reg or push %reg; ret.
		reg := c[1] - 0xb8
		ext := c[0] == 0x49
		tail := c[10:]
		if ext {
			if len(tail) >= 3 && tail[0] == 0x41 && tail[1] == 0xff && tail[2] == 0xe0+reg ||
				len(tail) >= 3 && tail[0] == 0x41 && tail[1] == 0x50+reg && tail[2] == 0xc3 {
				return entry{Kind: entryJump, Offset: off, Target: binary.LittleEndian.Uint64(c[2:]), Gadget: true}, true
			}
		} else if tail[0] == 0xff && tail[1] == 0xe0+reg || tail[0] == 0x50+reg && tail[1] == 0xc3 {
			return entry{Kind: entryJump, Offset: off, Target: binary.LittleEndian.Uint64(c[2:]), Gadget: true}, true
		}
	case len(c) >= 1 && c[0] == 0xcc:
		return entry{Kind: entryInt3, Offset: off}, true
	}
	return entry{}, false
}
