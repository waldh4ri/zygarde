// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package umhelper

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/waldh4ri/zygarde/internal/core"
)

func TestProgram(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"modprobe", "/sbin/modprobe", "/sbin/modprobe"},
		{"modprobe", "", ""},
		{"core_pattern", "core", ""},
		{"core_pattern", "|/usr/share/apport/apport -p%p -s%s", "/usr/share/apport/apport"},
		{"core_pattern", "| /tmp/x %p", "/tmp/x"},
		{"poweroff_cmd", "/sbin/poweroff -f", "/sbin/poweroff"},
	} {
		if got := program(tc.name, tc.value); got != tc.want {
			t.Errorf("program(%q, %q) = %q, want %q", tc.name, tc.value, got, tc.want)
		}
	}
}

func TestLocation(t *testing.T) {
	for p, bad := range map[string]bool{
		"/sbin/modprobe":                      false,
		"/tmp/x":                              true,
		"/dev/shm/x":                          true,
		"/run/x":                              true,
		"/run/current-system/sw/bin/modprobe": false,
		"/usr/lib/.cache/x":                   true,
		"/opt/vendor/crash":                   false,
	} {
		if got := location(p) != ""; got != bad {
			t.Errorf("location(%q) = %q", p, location(p))
		}
	}
}

func TestUnescape(t *testing.T) {
	if got := unescape(`/sys/fs/cgroup/a\040b`); got != "/sys/fs/cgroup/a b" {
		t.Errorf("got %q", got)
	}
}

// TestRun checks a fixture system: one helper in /tmp, one unpackaged
// program in a system directory, packaged ones and a cgroup release agent.
func TestRun(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the ownership checks need a fixture owned by root")
	}
	root := t.TempDir()
	write := func(p, content string, mode os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("/proc/sys/kernel/modprobe", "/tmp/x\n", 0o644)
	write("/proc/sys/kernel/core_pattern", "|/usr/lib/systemd/systemd-coredump %P %u\n", 0o644)
	write("/sys/kernel/uevent_helper", "/usr/sbin/evil\n", 0o644)
	write("/proc/sys/kernel/poweroff_cmd", "/sbin/poweroff\n", 0o644)
	write("/usr/lib/systemd/systemd-coredump", "x", 0o755)
	write("/usr/lib/systemd/systemd-cgroups-agent", "x", 0o755)
	write("/usr/sbin/evil", "x", 0o755)
	write("/var/lib/dpkg/info/systemd.list", "/usr/lib/systemd/systemd-coredump\n/lib/systemd/systemd-cgroups-agent\n", 0o644)
	write("/proc/self/mountinfo", "30 25 0:26 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n"+
		"31 25 0:27 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw\n", 0o644)
	write("/sys/fs/cgroup/systemd/release_agent", "/usr/lib/systemd/systemd-cgroups-agent\n", 0o644)
	for _, d := range []string{"/", "/usr", "/usr/lib", "/usr/sbin", "/usr/lib/systemd"} {
		os.Chmod(filepath.Join(root, d), 0o755)
	}

	c := &Cell{root: root, mountinfo: "/proc/self/mountinfo"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := core.NewRecorder(log)
	if err := c.Run(context.Background(), &core.Env{Log: log}, rec); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range rec.Findings() {
		got = append(got, f.Description)
	}
	sort.Strings(got)
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"runs /tmp/x as root through modprobe (/proc/sys/kernel/modprobe): it lives in a temporary directory",
		"runs /usr/sbin/evil as root through uevent_helper (/sys/kernel/uevent_helper): /usr/sbin/evil is in a system directory but belongs to no installed package",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing finding %q in:\n%s", want, all)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2:\n%s", len(got), all)
	}
}

// When /bin/sh can be replaced by anyone, so can every system program: a
// helper in the same directories is not singled out.
func TestOwnershipBaseline(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the ownership checks need a fixture owned by root")
	}
	root := t.TempDir()
	for p, content := range map[string]string{
		"/proc/sys/kernel/modprobe":       "/usr/sbin/modprobe\n",
		"/usr/sbin/modprobe":              "x",
		"/usr/bin/sh":                     "x",
		"/var/lib/dpkg/info/kmod.list":    "/usr/sbin/modprobe\n",
		"/proc/self/mountinfo":            "",
		"/proc/sys/kernel/core_pattern":   "core\n",
		"/proc/sys/kernel/poweroff_cmd":   "\n",
		"/sys/kernel/uevent_helper":       "\n",
		"/var/lib/dpkg/info/dash.list":    "/usr/bin/sh\n",
		"/var/lib/dpkg/info/other.md5sum": "",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(root, "usr"), 0o777)

	c := &Cell{root: root, mountinfo: "/proc/self/mountinfo"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := core.NewRecorder(log)
	if err := c.Run(context.Background(), &core.Env{Log: log}, rec); err != nil {
		t.Fatal(err)
	}
	if f := rec.Findings(); len(f) != 0 {
		t.Errorf("helper singled out although /bin/sh is just as replaceable: %v", f[0].Description)
	}
}
