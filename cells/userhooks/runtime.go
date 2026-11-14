package userhooks

import (
	"debug/elf"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// Java runtimes unpack native libraries (JNA, jansi, netty, sqlite-jdbc...)
// into temporary or cache directories and map them from there, often deleting
// the file afterwards. That looks like an injected library, so the process
// maps check lets such a mapping through only when the process is proven to be
// a real JVM, and then only for a file that looks like what the JVM extracts.
// The mapping is still reported, as an observation.

// elfInfo is what the checks need from an ELF file.
type elfInfo struct {
	typ      elf.Type
	needed   []string // DT_NEEDED
	dynsyms  []string // defined dynamic symbols
	readable bool
}

// readELF is replaced in tests.
var readELF = func(path string) (elfInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return elfInfo{}, err
	}
	defer f.Close()
	info := elfInfo{typ: f.Type, readable: true}
	info.needed, _ = f.ImportedLibraries()
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF {
			info.dynsyms = append(info.dynsyms, s.Name)
		}
	}
	return info, nil
}

func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// jvm is the result of checking whether a process is a real Java runtime.
type jvm struct {
	ok   bool
	home string // the JDK or JRE directory
	why  string // what failed, for the limitation text
}

// attestJVM decides whether pid is a genuine JVM. A name is not enough (any
// process can be called java), so it requires the structure of an installed
// runtime, checked on the files the process itself has mapped:
//   - the executable is a regular file in <home>/bin that is not deleted, in an
//     ordinary directory, and cannot be modified by group or others;
//   - it is the JDK launcher (ELF needing libjli.so, or exporting JLI_Launch);
//   - the process maps <home>/lib/**/server/libjvm.so, an unmodifiable ELF
//     shared object that exports JNI_CreateJavaVM;
//   - <home> has the runtime image of a JDK (release, lib/modules or rt.jar).
//
// mapsLines are the process's /proc/<pid>/maps lines.
func (c *Cell) attestJVM(pid, exe string, mapsLines []string, procRoot string) jvm {
	fail := func(why string) jvm { return jvm{why: why} }
	if procRoot == "" || exe == "" || strings.HasSuffix(exe, " (deleted)") || !filepath.IsAbs(exe) {
		return fail("no usable executable")
	}
	bin := filepath.Dir(exe)
	if filepath.Base(bin) != "bin" {
		return fail("executable is not in a bin directory")
	}
	home := filepath.Dir(bin)
	if why := c.unusualDir(filepath.ToSlash(bin), procRoot); why != "" {
		return fail("executable in " + why)
	}
	inRoot := func(p string) string { return filepath.Join(procRoot, p) }
	if !plainFile(inRoot(exe)) {
		return fail("executable is not an unmodifiable regular file")
	}
	launcher, err := readELF(inRoot(exe))
	if err != nil || !(hasString(launcher.needed, "libjli.so") || hasString(launcher.dynsyms, "JLI_Launch")) {
		return fail("executable is not the JDK launcher")
	}

	libjvm := ""
	for _, l := range mapsLines {
		f := strings.Fields(l)
		if len(f) < 6 || !strings.Contains(f[1], "x") {
			continue
		}
		p := strings.TrimSpace(l[strings.Index(l, f[5]):])
		if strings.HasPrefix(p, home+"/") && strings.HasSuffix(p, "/server/libjvm.so") && !strings.HasSuffix(p, " (deleted)") {
			libjvm = p
			break
		}
	}
	if libjvm == "" {
		return fail("libjvm.so is not mapped from the executable's runtime")
	}
	if !plainFile(inRoot(libjvm)) || !dirLocked(inRoot(filepath.Dir(libjvm))) {
		return fail("libjvm.so can be modified by group or others")
	}
	vm, err := readELF(inRoot(libjvm))
	if err != nil || vm.typ != elf.ET_DYN || !hasString(vm.dynsyms, "JNI_CreateJavaVM") {
		return fail("libjvm.so does not export JNI_CreateJavaVM")
	}
	for _, image := range []string{"release", "lib/modules", "lib/rt.jar", "jre/lib/rt.jar"} {
		if _, err := os.Stat(inRoot(filepath.Join(home, image))); err == nil {
			return jvm{ok: true, home: home}
		}
	}
	return fail("no JDK runtime image under " + home)
}

// plainFile reports whether path is a regular file that neither group nor
// others can write.
func plainFile(path string) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o022 == 0
}

func dirLocked(path string) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&0o022 == 0
}

// javaExtractedName matches what Java's temporary-file and extraction code
// produces: createTempFile appends a long random number, and libraries such as
// jansi, sqlite-jdbc and snappy-java put a 16-digit hexadecimal id in the name.
var javaExtractedName = regexp.MustCompile(`[0-9]{15,}|[0-9a-f]{16}`)

// jvmOwnLibrary reports whether a library mapped by the verified JVM process
// is something the JVM extracted itself: an ELF shared object (read through
// the mapping, so deleted files work), owned by the process's user, not
// writable by others (or by a group other than the process's), with a Java-generated name or directory name.
// mapFile is the /proc/<pid>/map_files entry of the mapping.
func jvmOwnLibrary(libPath, mapFile string, procUID, procGID uint32) bool {
	clean := strings.TrimSuffix(libPath, " (deleted)")
	if !javaExtractedName.MatchString(filepath.Base(clean)) && !javaExtractedName.MatchString(filepath.Base(filepath.Dir(clean))) {
		return false
	}
	var st unix.Stat_t
	if unix.Stat(mapFile, &st) != nil || st.Uid != procUID || st.Mode&0o002 != 0 || (st.Mode&0o020 != 0 && st.Gid != procGID) || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	info, err := readELF(mapFile)
	return err == nil && info.typ == elf.ET_DYN
}
