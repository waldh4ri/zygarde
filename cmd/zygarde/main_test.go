package main

import (
	"strings"
	"testing"
)

func TestPanicOnOopsGuard(t *testing.T) {
	for _, tc := range []struct {
		value int
		allow bool
		block bool
	}{
		{0, false, false},  // normal host
		{-1, false, false}, // sysctl unreadable (container): nothing to guard
		{1, false, true},   // would panic: refuse
		{1, true, false},   // explicitly accepted
		{0, true, false},
	} {
		msg := panicOnOopsGuard(tc.value, tc.allow)
		if (msg != "") != tc.block {
			t.Errorf("panicOnOopsGuard(%d, %v) = %q, want block=%v", tc.value, tc.allow, msg, tc.block)
		}
		if tc.block && !strings.Contains(msg, "--allow-panic-on-oops") {
			t.Errorf("message does not say how to override: %q", msg)
		}
	}
}
