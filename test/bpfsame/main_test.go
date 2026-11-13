package main

import (
	"encoding/binary"
	"testing"
)

type rawType struct {
	name     string
	kind     int
	sizeType uint32
}

// buildBTF encodes types (IDs from 1) with their names appended to the string
// table in the order given by strOrder.
func buildBTF(types []rawType, strOrder []string) []byte {
	le := binary.LittleEndian
	strs := []byte{0}
	off := map[string]uint32{"": 0}
	for _, s := range strOrder {
		off[s] = uint32(len(strs))
		strs = append(append(strs, s...), 0)
	}
	var tb []byte
	for _, t := range types {
		tb = le.AppendUint32(tb, off[t.name])
		tb = le.AppendUint32(tb, uint32(t.kind)<<24)
		tb = le.AppendUint32(tb, t.sizeType)
	}
	hdr := make([]byte, 24)
	le.PutUint16(hdr, 0xeb9f)
	hdr[2] = 1
	le.PutUint32(hdr[4:], 24)
	le.PutUint32(hdr[8:], 0)
	le.PutUint32(hdr[12:], uint32(len(tb)))
	le.PutUint32(hdr[16:], uint32(len(tb)))
	le.PutUint32(hdr[20:], uint32(len(strs)))
	return append(append(hdr, tb...), strs...)
}

func TestCanonicalBTF(t *testing.T) {
	// Pointers to two forward declarations, as clang emits for vmlinux.h
	// types referenced only through pointers. Only kinds without trailing
	// data, so the encoding stays trivial.
	committed := buildBTF([]rawType{
		{"", kindPtr, 3},          // 1 -> fwd module
		{"", kindPtr, 4},          // 2 -> fwd kobj_type
		{"module", kindFwd, 0},    // 3
		{"kobj_type", kindFwd, 0}, // 4
	}, []string{"module", "kobj_type"})
	renumbered := buildBTF([]rawType{
		{"", kindPtr, 4},          // 1 -> fwd module
		{"", kindPtr, 3},          // 2 -> fwd kobj_type
		{"kobj_type", kindFwd, 0}, // 3
		{"module", kindFwd, 0},    // 4
	}, []string{"kobj_type", "module"})
	swappedRefs := buildBTF([]rawType{
		{"", kindPtr, 4},          // 1 -> fwd kobj_type: a real change
		{"", kindPtr, 3},          // 2 -> fwd module
		{"module", kindFwd, 0},    // 3
		{"kobj_type", kindFwd, 0}, // 4
	}, []string{"module", "kobj_type"})

	canon := func(b []byte) string {
		s, err := canonicalBTF(b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if canon(committed) != canon(renumbered) {
		t.Errorf("renumbered forward declarations should be equivalent:\n%s\n---\n%s", canon(committed), canon(renumbered))
	}
	if canon(committed) == canon(swappedRefs) {
		t.Error("pointers retargeted to other declarations must not be equivalent")
	}
}
