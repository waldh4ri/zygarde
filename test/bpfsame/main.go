// Command bpfsame undoes meaningless changes to regenerated BPF objects.
//
// clang's BTF emitter numbers some forward declarations in an order that
// depends on the build host (it differs on some Intel Xeon CPUs), so
// `go generate` can rewrite a *_bpfel.o whose code, maps and relocations are
// unchanged. For every modified *_bpfel.o in the working tree, bpfsame compares
// it with the committed version and, if the only difference is the numbering
// of BTF forward declarations, restores the committed bytes. Any other
// difference is left in place, so `git diff` still shows real changes.
//
// usage: go run ./test/bpfsame   (from the repository root, after go generate)
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

func main() {
	files, err := git("diff", "--name-only", "--", "*_bpfel.o")
	if err != nil {
		fail(err)
	}
	for _, path := range strings.Fields(string(files)) {
		committed, err := git("show", "HEAD:"+path)
		if err != nil {
			continue // new file
		}
		current, err := os.ReadFile(path)
		if err != nil {
			fail(err)
		}
		same, why := equivalent(committed, current)
		if !same {
			fmt.Printf("%s: changed (%s)\n", path, why)
			continue
		}
		if err := os.WriteFile(path, committed, 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("%s: only BTF forward declarations were renumbered, kept the committed object\n", path)
	}
}

func git(args ...string) ([]byte, error) {
	// The toolchain container runs as root on a checkout owned by someone else.
	cmd := exec.Command("git", append([]string{"-c", "safe.directory=*"}, args...)...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "bpfsame:", err)
	os.Exit(1)
}

// equivalent reports whether two BPF ELF objects differ only in the order of
// BTF forward declarations. Every section other than .BTF must be identical.
func equivalent(a, b []byte) (bool, string) {
	ea, err := elf.NewFile(bytes.NewReader(a))
	if err != nil {
		return false, err.Error()
	}
	eb, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return false, err.Error()
	}
	if len(ea.Sections) != len(eb.Sections) {
		return false, "different sections"
	}
	for i, sa := range ea.Sections {
		sb := eb.Sections[i]
		if sa.SectionHeader != sb.SectionHeader {
			return false, "section header " + sa.Name
		}
		if sa.Type == elf.SHT_NOBITS {
			continue
		}
		da, err1 := sa.Data()
		db, err2 := sb.Data()
		if err := errors.Join(err1, err2); err != nil {
			return false, err.Error()
		}
		if sa.Name == ".BTF" {
			ca, err1 := canonicalBTF(da)
			cb, err2 := canonicalBTF(db)
			if err := errors.Join(err1, err2); err != nil {
				return false, err.Error()
			}
			if ca != cb {
				return false, "BTF types"
			}
			continue
		}
		if !bytes.Equal(da, db) {
			return false, "section " + sa.Name
		}
	}
	return true, ""
}

const (
	kindInt = iota + 1
	kindPtr
	kindArray
	kindStruct
	kindUnion
	kindEnum
	kindFwd
	kindTypedef
	kindVolatile
	kindConst
	kindRestrict
	kindFunc
	kindFuncProto
	kindVar
	kindDatasec
	kindFloat
	kindDeclTag
	kindTypeTag
	kindEnum64
)

type btfType struct {
	name      string
	info      uint32
	sizeType  uint32
	extra     []uint32 // kind-specific data, as u32 words
	nameWords []int    // indices in extra holding string offsets
	refWords  []int    // indices in extra holding type IDs
}

func (t btfType) kind() int { return int(t.info>>24) & 0x1f }

// canonicalBTF renders a raw .BTF section so that two sections differing only
// in the numbering of forward declarations render the same: references to a
// forward declaration name it instead of using its ID, the other types keep
// their relative order, and the declarations themselves are listed sorted.
func canonicalBTF(raw []byte) (string, error) {
	le := binary.LittleEndian
	if len(raw) < 24 || le.Uint16(raw) != 0xeb9f {
		return "", errors.New("not a little-endian BTF section")
	}
	hdrLen := le.Uint32(raw[4:])
	typeOff, typeLen := le.Uint32(raw[8:]), le.Uint32(raw[12:])
	strOff, strLen := le.Uint32(raw[16:]), le.Uint32(raw[20:])
	if uint64(hdrLen)+uint64(typeOff)+uint64(typeLen) > uint64(len(raw)) ||
		uint64(hdrLen)+uint64(strOff)+uint64(strLen) > uint64(len(raw)) {
		return "", errors.New("BTF header out of bounds")
	}
	types := raw[hdrLen+typeOff : hdrLen+typeOff+typeLen]
	strs := raw[hdrLen+strOff : hdrLen+strOff+strLen]
	str := func(off uint32) string {
		if int(off) >= len(strs) {
			return fmt.Sprintf("<bad string %d>", off)
		}
		s := strs[off:]
		if i := bytes.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		return string(s)
	}

	all := []btfType{{}} // ID 0 is void
	for p := 0; p < len(types); {
		if p+12 > len(types) {
			return "", errors.New("truncated BTF type")
		}
		t := btfType{name: str(le.Uint32(types[p:])), info: le.Uint32(types[p+4:]), sizeType: le.Uint32(types[p+8:])}
		p += 12
		vlen := int(t.info & 0xffff)
		var words, stride int
		var names, refs []int // word positions within each stride
		switch t.kind() {
		case kindInt, kindVar, kindDeclTag:
			words = 1
		case kindArray:
			words, refs = 3, []int{0, 1}
		case kindStruct, kindUnion:
			stride, names, refs = 3, []int{0}, []int{1}
		case kindEnum:
			stride, names = 2, []int{0}
		case kindFuncProto:
			stride, names, refs = 2, []int{0}, []int{1}
		case kindDatasec:
			stride, refs = 3, []int{0}
		case kindEnum64:
			stride, names = 3, []int{0}
		case kindPtr, kindFwd, kindTypedef, kindVolatile, kindConst, kindRestrict,
			kindFunc, kindFloat, kindTypeTag:
		default:
			return "", fmt.Errorf("unknown BTF kind %d", t.kind())
		}
		if stride > 0 {
			words = stride * vlen
			for i := 0; i < vlen; i++ {
				for _, n := range names {
					t.nameWords = append(t.nameWords, i*stride+n)
				}
				for _, r := range refs {
					t.refWords = append(t.refWords, i*stride+r)
				}
			}
		} else {
			t.refWords = refs
		}
		if p+4*words > len(types) {
			return "", errors.New("truncated BTF type data")
		}
		for i := 0; i < words; i++ {
			t.extra = append(t.extra, le.Uint32(types[p+4*i:]))
		}
		p += 4 * words
		all = append(all, t)
	}

	// Number the non-forward types in order; name the forward ones.
	label := make([]string, len(all))
	label[0] = "void"
	n := 0
	for id := 1; id < len(all); id++ {
		if t := all[id]; t.kind() == kindFwd {
			label[id] = fmt.Sprintf("fwd(%q,%d)", t.name, t.info>>31)
		} else {
			n++
			label[id] = fmt.Sprintf("#%d", n)
		}
	}
	ref := func(id uint32) string {
		if int(id) >= len(label) {
			return fmt.Sprintf("<bad type %d>", id)
		}
		return label[id]
	}

	var out, fwds []string
	for id := 1; id < len(all); id++ {
		t := all[id]
		if t.kind() == kindFwd {
			fwds = append(fwds, label[id])
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s %q info=%#x", label[id], t.name, t.info)
		switch t.kind() {
		case kindPtr, kindTypedef, kindVolatile, kindConst, kindRestrict, kindFunc,
			kindFuncProto, kindVar, kindDeclTag, kindTypeTag:
			fmt.Fprintf(&b, " type=%s", ref(t.sizeType))
		default:
			fmt.Fprintf(&b, " size=%d", t.sizeType)
		}
		for i, w := range t.extra {
			switch {
			case slices.Contains(t.nameWords, i):
				fmt.Fprintf(&b, " %q", str(w))
			case slices.Contains(t.refWords, i):
				fmt.Fprintf(&b, " %s", ref(w))
			default:
				fmt.Fprintf(&b, " %d", w)
			}
		}
		out = append(out, b.String())
	}
	slices.Sort(fwds)
	return strings.Join(out, "\n") + "\n--\n" + strings.Join(fwds, "\n"), nil
}
