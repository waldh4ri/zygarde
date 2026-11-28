// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package syscalltable

import (
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/kernel"
)

// A table entry pointing into a hidden module's memory is named as such, not
// after the nearest core symbol (Diamorphine on Debian 11 used to show
// "__init_scratch_end+0x1a9ad020").
func TestActualSymbol(t *testing.T) {
	ks, err := kernel.ParseKallsyms(strings.NewReader(`ffffffff81000000 T _stext
ffffffff81200000 T __x64_sys_kill
ffffffff81400000 T _etext
ffffffff82000000 D __init_scratch_end
ffffffffc0ae8000 t visible_hook	[visible]
`))
	if err != nil {
		t.Fatal(err)
	}
	img := kernel.Image{TextStart: 0xffffffff81000000, TextEnd: 0xffffffff81400000, End: 0xffffffff83000000, HasData: true}
	for addr, want := range map[uint64]string{
		0xffffffff81200010: "__x64_sys_kill+0x10",
		0xffffffffc0ae8020: "visible_hook+0x20 [visible]",
		0xffffffffc05ad020: "outside the kernel's text (hidden module, BPF or allocated memory)",
	} {
		if got := actualSymbol(ks, img, addr); got != want {
			t.Errorf("actualSymbol(%#x) = %q, want %q", addr, got, want)
		}
	}
}
