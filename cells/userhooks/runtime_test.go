package userhooks

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// jdkFixture builds <root>/opt/jdk with a launcher, libjvm.so and a release
// file, and returns the root (the process's root directory).
func jdkFixture(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	for _, f := range []string{"opt/jdk/bin/java", "opt/jdk/lib/server/libjvm.so", "opt/jdk/release"} {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fakeELF(t *testing.T, byBase map[string]elfInfo) {
	t.Helper()
	old := readELF
	readELF = func(path string) (elfInfo, error) {
		if i, ok := byBase[filepath.Base(path)]; ok {
			return i, nil
		}
		return elfInfo{}, os.ErrNotExist
	}
	t.Cleanup(func() { readELF = old })
}

var goodELFs = map[string]elfInfo{
	"java":      {typ: elf.ET_DYN, needed: []string{"libjli.so", "libc.so.6"}},
	"libjvm.so": {typ: elf.ET_DYN, dynsyms: []string{"JNI_CreateJavaVM", "JVM_Halt"}},
}

func jvmMaps(home string) []string {
	return []string{"7f00-7f10 r-xp 00000000 00:68 1   " + home + "/lib/server/libjvm.so"}
}

func TestAttestJVM(t *testing.T) {
	c := &Cell{}
	exe := "/opt/jdk/bin/java"

	t.Run("genuine", func(t *testing.T) {
		root := jdkFixture(t)
		fakeELF(t, goodELFs)
		if j := c.attestJVM("1", exe, jvmMaps("/opt/jdk"), root); !j.ok || j.home != "/opt/jdk" {
			t.Fatalf("attestJVM = %+v", j)
		}
	})
	for name, tc := range map[string]struct {
		exe     string
		maps    []string
		elfs    map[string]elfInfo
		mutate  func(root string)
		noRoot  bool
		wantWhy string
	}{
		"deleted executable":    {exe: exe + " (deleted)", maps: jvmMaps("/opt/jdk"), elfs: goodELFs},
		"not in bin":            {exe: "/opt/jdk/java", maps: jvmMaps("/opt/jdk"), elfs: goodELFs},
		"in /tmp":               {exe: "/tmp/jdk/bin/java", maps: jvmMaps("/tmp/jdk"), elfs: goodELFs},
		"libjvm not mapped":     {exe: exe, maps: nil, elfs: goodELFs},
		"libjvm from elsewhere": {exe: exe, maps: jvmMaps("/opt/other"), elfs: goodELFs},
		"not the launcher": {exe: exe, maps: jvmMaps("/opt/jdk"), elfs: map[string]elfInfo{
			"java": {typ: elf.ET_DYN, needed: []string{"libc.so.6"}}, "libjvm.so": goodELFs["libjvm.so"]}},
		"libjvm lacks JNI": {exe: exe, maps: jvmMaps("/opt/jdk"), elfs: map[string]elfInfo{
			"java": goodELFs["java"], "libjvm.so": {typ: elf.ET_DYN, dynsyms: []string{"foo"}}}},
		"libjvm writable": {exe: exe, maps: jvmMaps("/opt/jdk"), elfs: goodELFs, mutate: func(root string) {
			_ = os.Chmod(filepath.Join(root, "opt/jdk/lib/server/libjvm.so"), 0o666)
		}},
		"launcher writable": {exe: exe, maps: jvmMaps("/opt/jdk"), elfs: goodELFs, mutate: func(root string) {
			_ = os.Chmod(filepath.Join(root, "opt/jdk/bin/java"), 0o777)
		}},
		"no runtime image": {exe: exe, maps: jvmMaps("/opt/jdk"), elfs: goodELFs, mutate: func(root string) {
			_ = os.Remove(filepath.Join(root, "opt/jdk/release"))
		}},
		"no process root": {exe: exe, maps: jvmMaps("/opt/jdk"), elfs: goodELFs, noRoot: true},
	} {
		t.Run(name, func(t *testing.T) {
			root := jdkFixture(t)
			fakeELF(t, tc.elfs)
			if tc.mutate != nil {
				tc.mutate(root)
			}
			if tc.noRoot {
				root = ""
			}
			if j := c.attestJVM("1", tc.exe, tc.maps, root); j.ok {
				t.Errorf("accepted: %+v", j)
			}
		})
	}
}

func TestJVMOwnLibrary(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
		return p
	}
	fakeELF(t, map[string]elfInfo{
		"so": {typ: elf.ET_DYN}, "exec": {typ: elf.ET_EXEC},
	})
	uid := uint32(os.Getuid())
	file := write("so", 0o644)
	if !jvmOwnLibrary("/tmp/jna17284518115760084602.tmp (deleted)", file, uid, uid) {
		t.Error("JNA extraction rejected")
	}
	if !jvmOwnLibrary("/tmp/elasticsearch-3858800767794248065/libjansi.so", file, uid, uid) {
		t.Error("extraction into a temporary directory rejected")
	}
	if !jvmOwnLibrary("/tmp/x/jansi-2.4.0-4fd9a49fd5a9d114-libjansi.so", file, uid, uid) {
		t.Error("hexadecimal id rejected")
	}
	if jvmOwnLibrary("/tmp/libevil.so", file, uid, uid) {
		t.Error("name without a Java-generated part accepted")
	}
	if jvmOwnLibrary("/tmp/jna17284518115760084602.tmp", file, uid+1, uid) {
		t.Error("file owned by another user accepted")
	}
	if jvmOwnLibrary("/tmp/jna17284518115760084602.tmp", write("so", 0o666), uid, uid) {
		t.Error("world-writable file accepted")
	}
	grp := write("so", 0o664)
	if jvmOwnLibrary("/tmp/jna17284518115760084602.tmp", grp, uid, uid+1) {
		t.Error("group-writable file of another group accepted")
	}
	if !jvmOwnLibrary("/tmp/jna17284518115760084602.tmp", grp, uid, uint32(os.Getgid())) {
		t.Error("group-writable file of the process's own group rejected")
	}
	exec := write("exec", 0o644)
	if jvmOwnLibrary("/tmp/jna17284518115760084602.tmp", exec, uid, uid) {
		t.Error("an executable that is not a shared object accepted")
	}
	if jvmOwnLibrary("/tmp/jna17284518115760084602.tmp", filepath.Join(dir, "missing"), uid, uid) {
		t.Error("unreadable mapping accepted")
	}
}
