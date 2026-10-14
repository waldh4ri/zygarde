package kernel

import (
	"errors"
	"strings"
	"testing"
)

func TestParseKallsyms(t *testing.T) {
	ks, err := ParseKallsyms(strings.NewReader(`ffffffff81000000 T _stext
ffffffff82200300 D sys_call_table
ffffffff81234560 t x64_sys_call
ffffffff81234560 T __x64_sys_read
ffffffffc0a01000 t hidden_fn	[evilmod]
ffffffff81234999 T __x64_sys_read
`))
	if err != nil {
		t.Fatal(err)
	}
	if addr, ok := ks.Addr("sys_call_table"); !ok || addr != 0xffffffff82200300 {
		t.Errorf("sys_call_table = %#x, %v", addr, ok)
	}
	if addr, _ := ks.Addr("__x64_sys_read"); addr != 0xffffffff81234560 {
		t.Errorf("duplicate symbol should keep the first address, got %#x", addr)
	}
	if !ks.Has("x64_sys_call") {
		t.Error("static symbol x64_sys_call missing")
	}
	if ks.Has("hidden_fn") {
		t.Error("module symbols must be ignored")
	}
}

func TestParseKallsymsHidden(t *testing.T) {
	_, err := ParseKallsyms(strings.NewReader("0000000000000000 T _stext\n0000000000000000 D sys_call_table\n"))
	if !errors.Is(err, ErrAddressesHidden) {
		t.Fatalf("got %v, want ErrAddressesHidden", err)
	}
}

func TestParseLockdown(t *testing.T) {
	for in, want := range map[string]string{
		"[none] integrity confidentiality\n": "none",
		"none [integrity] confidentiality\n": "integrity",
		"none integrity [confidentiality]\n": "confidentiality",
		"garbage":                            "",
	} {
		if got := ParseLockdown(in); got != want {
			t.Errorf("ParseLockdown(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStatus(t *testing.T) {
	st, err := ParseStatus(strings.NewReader("Name:\tzygarde\nCapEff:\t000001ffffffffff\nSeccomp:\t2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasCap(CapSysAdmin) || !st.HasCap(CapBPF) {
		t.Errorf("caps not parsed: %#x", st.CapEff)
	}
	if st.Seccomp != 2 {
		t.Errorf("seccomp = %d, want 2", st.Seccomp)
	}

	st, _ = ParseStatus(strings.NewReader("CapEff:\t0000000000000000\n"))
	if st.HasCap(CapSysAdmin) || st.Seccomp != -1 {
		t.Errorf("unprivileged/unknown parse wrong: %+v", st)
	}
}
