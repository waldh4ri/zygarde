// Copyright (c) 2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package process

import "testing"

func TestSuspiciousTracer(t *testing.T) {
	for _, tc := range []struct {
		exe  string
		euid uint32
		want bool
	}{
		{"/usr/bin/gdb", 0, false},
		{"/usr/bin/gdb (deleted)", 0, false}, // upgraded while running
		{"/memfd:x (deleted)", 1000, true},
		{"/tmp/inj", 1000, true},
		{"/dev/shm/inj", 0, true},
		{"/srv/inj (deleted)", 0, true},
		{"/home/u/.vscode/extensions/lldb/bin/lldb", 1000, false},
		{"/root/.cache/x/inj", 0, true},
	} {
		if got := suspiciousTracer(exeLocation(tc.exe), tc.exe, tc.euid); got != tc.want {
			t.Errorf("suspiciousTracer(%q, euid %d) = %v, want %v", tc.exe, tc.euid, got, tc.want)
		}
	}
}
