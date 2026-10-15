package process

import "testing"

func TestLooksLikeKthread(t *testing.T) {
	for _, tc := range []struct {
		comm, cmdline string
		want          bool
	}{
		{"kworker/0:1", "", true},
		{"sleep", "[kworker/0:1]", true},
		{"bash", "[kthreadd] -c x", true},
		{"rcu_sched", "", true},
		{"sshd", "sshd: root@pts/0", false},
		{"watchdog", "/usr/sbin/watchdog", false}, // the userspace daemon
		{"irqbalance", "/usr/sbin/irqbalance --foreground", false},
		{"kworkerd", "", false},
	} {
		if got := looksLikeKthread(tc.comm, tc.cmdline); got != tc.want {
			t.Errorf("looksLikeKthread(%q, %q) = %v, want %v", tc.comm, tc.cmdline, got, tc.want)
		}
	}
}

func TestExeLocation(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/sbin/sshd":            "",
		"/usr/sbin/sshd (deleted)":  "deleted",
		"/memfd:x (deleted)":        "memfd",
		"/dev/shm/a":                "memory-backed directory",
		"/tmp/x (deleted)":          "temporary directory",
		"/var/lib/.cache/bin/agent": "hidden directory",
		"/usr/bin/.local/sudo":      "hidden directory",
		"/opt/app/bin/app":          "",
	} {
		if got := exeLocation(in); got != want {
			t.Errorf("exeLocation(%q) = %q, want %q", in, got, want)
		}
	}
	if !packaged("/usr/sbin/sshd") || packaged("/root/x") {
		t.Error("packaged() misclassifies")
	}
}

func TestPadded(t *testing.T) {
	pad := func(c byte, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = c
		}
		return string(b)
	}
	for _, tc := range []struct {
		name    string
		cmdline string
		want    bool
	}{
		{"normal", "/usr/bin/python3\x00-m\x00http.server\x00", false},
		{"setproctitle trailing NULs", "postgres: checkpointer" + pad(0, 200), false},
		{"spaces then args", "[kworker/0:1]" + pad(' ', 64) + "-c /tmp/x\x00", true},
		{"NULs then args", "sleep\x00" + pad(0, 40) + "realarg\x00", true},
		{"short padding", "a" + pad(' ', 10) + "b", false},
	} {
		if _, got := padded([]byte(tc.cmdline)); got != tc.want {
			t.Errorf("%s: padded = %v, want %v", tc.name, got, tc.want)
		}
	}
}
