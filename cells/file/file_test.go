package file

import (
	"slices"
	"testing"
)

func TestDiff(t *testing.T) {
	produced := map[string]bool{"ls": true, "rootkit.ko": true, "bash": true, ".hidden": true}
	returned := map[string]bool{"ls": true, "bash": true}
	if got := diff(produced, returned); !slices.Equal(got, []string{".hidden", "rootkit.ko"}) {
		t.Errorf("diff = %v", got)
	}
	if got := diff(returned, produced); len(got) != 0 {
		t.Errorf("returned-but-not-produced must not count: %v", got)
	}
}

func TestIntersect(t *testing.T) {
	// Only entries missing in both listings are reported.
	if got := intersect([]string{"a", "b", "c"}, []string{"b", "c", "d"}); !slices.Equal(got, []string{"b", "c"}) {
		t.Errorf("intersect = %v", got)
	}
}

func TestScanDirs(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:relative:/opt/tool/bin/")
	dirs := scanDirs()
	for _, want := range []string{"/tmp", "/proc", "/sys/module", "/opt/tool/bin"} {
		if !slices.Contains(dirs, want) {
			t.Errorf("scanDirs() missing %s", want)
		}
	}
	if slices.Contains(dirs, "relative") {
		t.Error("relative PATH entries must be ignored")
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		if seen[d] {
			t.Errorf("duplicate directory %s", d)
		}
		seen[d] = true
	}
}

func TestRemoteMounts(t *testing.T) {
	mounts := map[string]string{"/home": "nfs4", "/mnt/my share": "cifs"}
	if got := under("/home/alice/.ssh", mounts); got != "nfs4" {
		t.Errorf("under(/home/alice/.ssh) = %q", got)
	}
	if got := under("/homework", mounts); got != "" {
		t.Errorf("under(/homework) = %q", got)
	}
	if got := under("/mnt/my share/x", mounts); got != "cifs" {
		t.Errorf("under(space) = %q", got)
	}
	if unescapeMount(`/mnt/my\040share`) != "/mnt/my share" || unescapeMount(`/a\04`) != `/a\04` {
		t.Error("unescapeMount")
	}
	if !remoteMountType("fuse.sshfs") || !remoteMountType("nfs") || remoteMountType("ext4") || remoteMountType("overlay") {
		t.Error("remoteMountType")
	}
}
