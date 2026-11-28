// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package core

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// BTFHub's BTF for Ubuntu 5.4.0-72-generic defines task_struct twice:
// a duplicated type must count as present, not as missing.
func TestBTFTypeDuplicates(t *testing.T) {
	b, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	u32 := &btf.Int{Name: "u32", Size: 4}
	for range 2 {
		if _, err := b.Add(&btf.Struct{Name: "task_struct", Size: 4, Members: []btf.Member{{Name: "pid", Type: u32}}}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spec.AnyTypeByName("task_struct"); err == nil {
		t.Fatal("test BTF should hold two task_struct definitions")
	}
	if !HasBTFType(spec, "task_struct") {
		t.Error("HasBTFType: duplicated task_struct reported missing")
	}
	if s := BTFStruct(spec, "task_struct"); s == nil || s.Members[0].Name != "pid" {
		t.Errorf("BTFStruct = %v", s)
	}
	if HasBTFType(spec, "bpf_iter__task") || BTFStruct(spec, "bpf_iter__task") != nil || HasBTFType(nil, "x") {
		t.Error("absent types must not be found")
	}
	env := &Env{BTF: spec}
	if err := env.RequireBTFType("task_struct", "tasks"); err != nil {
		t.Errorf("RequireBTFType with a duplicated type: %v", err)
	}
}
