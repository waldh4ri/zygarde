// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package kmem

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// Field is a member's byte offset and size inside a struct.
type Field struct {
	Offset uint64
	Size   uint64
}

// Struct looks up a struct type by name in spec. Older kernels' BTF can hold
// several copies of one struct (Ubuntu 20.04's 5.4 has two struct module):
// they are accepted when they agree on the size, and the first is used.
func Struct(spec *btf.Spec, name string) (*btf.Struct, error) {
	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return nil, fmt.Errorf("struct %s: %w", name, err)
	}
	var found *btf.Struct
	for _, t := range types {
		s, ok := t.(*btf.Struct)
		if !ok {
			continue
		}
		if found != nil && found.Size != s.Size {
			return nil, fmt.Errorf("struct %s: copies of different sizes (%d, %d) in BTF", name, found.Size, s.Size)
		}
		if found == nil {
			found = s
		}
	}
	if found == nil {
		return nil, fmt.Errorf("struct %s: not in BTF", name)
	}
	return found, nil
}

// Lookup resolves a member path in the named struct: dot-separated member
// names, each optionally indexed ("mkobj.kobj.entry", "mem[1].mtn").
// Members of anonymous structs and unions are found as if they were direct
// members, as in C.
func Lookup(spec *btf.Spec, typ, path string) (Field, error) {
	s, err := Struct(spec, typ)
	if err != nil {
		return Field{}, err
	}
	f, err := resolve(s, path)
	if err != nil {
		return Field{}, fmt.Errorf("struct %s: %w", typ, err)
	}
	return f, nil
}

// Has reports whether the named struct has the member path.
func Has(spec *btf.Spec, typ, path string) bool {
	_, err := Lookup(spec, typ, path)
	return err == nil
}

// Size returns the size of the named struct.
func Size(spec *btf.Spec, typ string) (uint64, error) {
	s, err := Struct(spec, typ)
	if err != nil {
		return 0, err
	}
	return uint64(s.Size), nil
}

// resolve walks path from t.
func resolve(t btf.Type, path string) (Field, error) {
	var off uint64
	for _, seg := range strings.Split(path, ".") {
		name, idx, err := parseSegment(seg)
		if err != nil {
			return Field{}, err
		}
		m, moff, ok := member(t, name)
		if !ok {
			return Field{}, fmt.Errorf("no member %q", name)
		}
		off += moff
		t = m.Type
		if idx >= 0 {
			arr, ok := btf.UnderlyingType(t).(*btf.Array)
			if !ok {
				return Field{}, fmt.Errorf("member %q is not an array", name)
			}
			if arr.Nelems != 0 && uint32(idx) >= arr.Nelems {
				return Field{}, fmt.Errorf("index %d out of range for %q (%d elements)", idx, name, arr.Nelems)
			}
			es, err := btf.Sizeof(arr.Type)
			if err != nil {
				return Field{}, err
			}
			off += uint64(idx) * uint64(es)
			t = arr.Type
		}
	}
	size, err := btf.Sizeof(t)
	if err != nil {
		return Field{}, err
	}
	return Field{off, uint64(size)}, nil
}

// member finds a named member of a struct or union, looking through
// anonymous members, and returns its byte offset.
func member(t btf.Type, name string) (btf.Member, uint64, bool) {
	var members []btf.Member
	switch c := btf.UnderlyingType(t).(type) {
	case *btf.Struct:
		members = c.Members
	case *btf.Union:
		members = c.Members
	default:
		return btf.Member{}, 0, false
	}
	for _, m := range members {
		if m.Name == name {
			return m, uint64(m.Offset.Bytes()), true
		}
	}
	for _, m := range members {
		if m.Name != "" {
			continue
		}
		if inner, off, ok := member(m.Type, name); ok {
			return inner, uint64(m.Offset.Bytes()) + off, true
		}
	}
	return btf.Member{}, 0, false
}

func parseSegment(seg string) (string, int, error) {
	name, rest, indexed := strings.Cut(seg, "[")
	if !indexed {
		return seg, -1, nil
	}
	n, err := strconv.Atoi(strings.TrimSuffix(rest, "]"))
	if err != nil || !strings.HasSuffix(rest, "]") || n < 0 {
		return "", 0, fmt.Errorf("bad path segment %q", seg)
	}
	return name, n, nil
}
