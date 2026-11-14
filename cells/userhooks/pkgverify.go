package userhooks

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/rpmdb"
)

// dpkgInfoDir holds one <package>.md5sums file per installed Debian package.
const dpkgInfoDir = "/var/lib/dpkg/info"

// systemLibDirs are where distribution packages install shared libraries.
var systemLibDirs = []string{"/lib", "/lib32", "/lib64", "/usr/lib", "/usr/lib32", "/usr/lib64"}

func isSystemLib(path string) bool {
	if !strings.Contains(filepath.Base(path), ".so") {
		return false
	}
	for _, d := range systemLibDirs {
		if under(path, d) {
			return true
		}
	}
	return false
}

// md5sumKeys returns the names a packaged file can appear under in a
// .md5sums file: relative to /, with and without the usr-merge prefix.
func md5sumKeys(path string) []string {
	rel := strings.TrimPrefix(path, "/")
	keys := []string{rel}
	if strings.HasPrefix(rel, "usr/") {
		keys = append(keys, strings.TrimPrefix(rel, "usr/"))
	} else {
		keys = append(keys, "usr/"+rel)
	}
	return keys
}

// packagedChecksums returns, for each wanted library path, the checksums the
// installed packages declare for it (and the packages that declare them).
// wanted maps path to true. It reads every <infoDir>/*.md5sums file once.
func packagedChecksums(infoDir string, wanted map[string]bool) (sums map[string]map[string]string, packages int, err error) {
	files, err := filepath.Glob(filepath.Join(infoDir, "*.md5sums"))
	if err != nil || len(files) == 0 {
		return nil, 0, err
	}
	byKey := map[string]string{}
	for p := range wanted {
		for _, k := range md5sumKeys(p) {
			byKey[k] = p
		}
	}
	sums = map[string]map[string]string{} // path -> checksum -> package
	for _, f := range files {
		fh, err := fsutil.Open(f)
		if err != nil {
			continue
		}
		pkg := strings.TrimSuffix(filepath.Base(f), ".md5sums")
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			sum, rel, ok := strings.Cut(sc.Text(), "  ")
			if !ok || len(sum) != 32 {
				continue
			}
			if p, hit := byKey[rel]; hit {
				if sums[p] == nil {
					sums[p] = map[string]string{}
				}
				sums[p][sum] = pkg
			}
		}
		fh.Close()
	}
	return sums, len(files), nil
}

// mappedSystemLibs lists the system shared libraries mapped executable into
// running processes of this mount namespace, with the processes holding them.
func (c *Cell) mappedSystemLibs(ctx context.Context) (map[string][]string, error) {
	entries, err := fsutil.ReadDirNoAtime(c.proc)
	if err != nil {
		return nil, nil
	}
	// The worker unshares its mount namespace (CLONE_NEWNS), so compare with its
	// parent, the supervisor, which lives in the host namespace being scanned.
	var self unix.Stat_t
	haveSelf := unix.Stat(filepath.Join(c.proc, strconv.Itoa(os.Getppid()), "ns", "mnt"), &self) == nil
	if !haveSelf {
		haveSelf = unix.Stat(filepath.Join(c.proc, "self", "ns", "mnt"), &self) == nil
	}
	selfPID := strconv.Itoa(os.Getpid())
	out := map[string][]string{}
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil || pid == selfPID {
			continue
		}
		// Containers ship their own libraries: only this mount namespace's
		// files correspond to the host's package database.
		if haveSelf {
			var st unix.Stat_t
			if unix.Stat(filepath.Join(c.proc, pid, "ns", "mnt"), &st) != nil || st.Ino != self.Ino {
				continue
			}
		}
		f, err := fsutil.OpenNoAtime(filepath.Join(c.proc, pid, "maps"))
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 6 || !strings.Contains(fields[1], "x") || fields[4] == "0" {
				continue
			}
			p := fields[5]
			if p == "" || p[0] != '/' || seen[p] || !isSystemLib(p) {
				continue
			}
			if strings.Contains(sc.Text(), "(deleted)") {
				continue // replaced by a package upgrade after the process started
			}
			seen[p] = true
			out[p] = append(out[p], pid)
		}
		f.Close()
	}
	return out, nil
}

// pkgDigest is a checksum a package database declares for a file.
type pkgDigest struct{ algo, hex, pkg string }

// rpmDBPaths are where rpm keeps its SQLite database ("/var/lib/rpm" is
// usually a symlink to the first).
var rpmDBPaths = []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite"}

// pathVariants returns the names a packaged file can be recorded under: the
// path as mapped and with the usr-merge prefix added or removed.
func pathVariants(p string) []string {
	if strings.HasPrefix(p, "/usr/") {
		return []string{p, strings.TrimPrefix(p, "/usr")}
	}
	return []string{p, "/usr" + p}
}

// declaredDigests returns the checksums installed packages declare for the
// wanted paths, and which database they came from ("dpkg" or "rpm"). It
// records a limit and returns nil when the system's package database cannot be read.
func (c *Cell) declaredDigests(rec *core.Recorder, wanted map[string]bool) (digests map[string][]pkgDigest, owners map[string]string, source string) {
	if infoDir := c.path(dpkgInfoDir); dirExists(infoDir) {
		sums, packages, err := packagedChecksums(infoDir, wanted)
		if err != nil || packages == 0 {
			rec.Limit("Mapped system libraries were not verified against package checksums: no *.md5sums files in %s", dpkgInfoDir)
			return nil, nil, ""
		}
		out := map[string][]pkgDigest{}
		for p, bySum := range sums {
			for sum, pkg := range bySum {
				out[p] = append(out[p], pkgDigest{"md5", sum, pkg})
			}
		}
		return out, dpkgOwners(infoDir, wanted), "dpkg"
	}
	for _, dbPath := range rpmDBPaths {
		real := c.path(dbPath)
		if _, err := os.Stat(real); err != nil {
			continue
		}
		byVariant := map[string]string{}
		variants := map[string]bool{}
		for p := range wanted {
			for _, v := range pathVariants(p) {
				byVariant[v] = p
				variants[v] = true
			}
		}
		got, own, err := rpmdb.Scan(real, variants)
		if err != nil {
			rec.Limit("Mapped system libraries were not verified against package checksums: %v", err)
			return nil, nil, ""
		}
		out := map[string][]pkgDigest{}
		for v, ds := range got {
			for _, d := range ds {
				out[byVariant[v]] = append(out[byVariant[v]], pkgDigest{d.Algo, d.Hex, d.Package})
			}
		}
		owners = map[string]string{}
		for v, pkg := range own {
			owners[byVariant[v]] = pkg
		}
		return out, owners, "rpm"
	}
	rec.Limit("Mapped system libraries were not verified against package checksums: no dpkg or SQLite rpm database found (Berkeley DB rpm databases are not supported)")
	return nil, nil, ""
}

// dpkgOwners returns, for each wanted library path, a package whose file list
// (<infoDir>/*.list) contains it. Unlike the md5sums files, the lists cover
// every file a package installs, so a path missing from all of them is unowned.
func dpkgOwners(infoDir string, wanted map[string]bool) map[string]string {
	byVariant := map[string]string{}
	for p := range wanted {
		for _, v := range pathVariants(p) {
			byVariant[v] = p
		}
	}
	owners := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(infoDir, "*.list"))
	for _, f := range files {
		fh, err := fsutil.Open(f)
		if err != nil {
			continue
		}
		pkg := strings.TrimSuffix(filepath.Base(f), ".list")
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if p, ok := byVariant[sc.Text()]; ok {
				owners[p] = pkg
			}
		}
		fh.Close()
	}
	return owners
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// fileDigest hashes a file with the given algorithm ("md5" or "sha256").
func fileDigest(path, algo string) (string, error) {
	f, err := fsutil.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var h hash.Hash
	switch algo {
	case "md5":
		h = md5.New()
	case "sha256":
		h = sha256.New()
	default:
		return "", fmt.Errorf("unsupported digest algorithm %q", algo)
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// pamGlobs match the directories PAM loads its modules from. A module is only
// mapped while a login, sudo or sshd session is being authenticated, so the
// directories are listed as well as the running processes' maps.
var pamGlobs = []string{"/lib/security/*.so*", "/lib*/security/*.so*", "/lib/*/security/*.so*", "/usr/lib*/security/*.so*", "/usr/lib/*/security/*.so*"}

// addPAMModules adds the regular files of the PAM module directories to mapped
// (with no process), so they are checked like mapped libraries.
func (c *Cell) addPAMModules(mapped map[string][]string) {
	prefix := strings.TrimSuffix(c.root, "/")
	for _, g := range pamGlobs {
		matches, _ := filepath.Glob(c.path(g))
		for _, m := range matches {
			if st, err := os.Lstat(m); err != nil || !st.Mode().IsRegular() {
				continue // symlinks (alternatives, /lib -> /usr/lib duplicates) are covered by their target
			}
			r, err := filepath.EvalSymlinks(m) // /lib -> /usr/lib: one name per file, as in /proc/<pid>/maps
			if err != nil {
				continue
			}
			p := strings.TrimPrefix(r, prefix)
			if _, ok := mapped[p]; !ok {
				mapped[p] = nil
			}
		}
	}
}

// reportUnowned records a mapped library in a system directory that no
// installed package ships.
func (c *Cell) reportUnowned(rec *core.Recorder, p, source string, pids []string) {
	if len(pids) > 10 {
		pids = append(pids[:10:10], fmt.Sprintf("… (%d more)", len(pids)-10))
	}
	d := map[string]string{
		"library":         p,
		"package_manager": source,
		"mapped_by_pids":  strings.Join(pids, ", "),
	}
	fsutil.MergeMetadata(d, "file_", fsutil.FileMetadata(c.path(p)))
	rec.Suspicious(core.Finding{
		Description: fmt.Sprintf("Library %s in a system directory belongs to no installed package", p),
		Details:     d,
		Why: "This library sits among the distribution's own libraries (mapped by a process or in a PAM module directory), but no " +
			"package's file list contains it. Implants add a module such as a PAM module or NSS library next to the " +
			"legitimate ones (pam_unix.so lookalikes that accept a backdoor password or log credentials), where it " +
			"passes for part of the system and is loaded by sshd, login or sudo.",
		Benign: "Software installed outside the package manager: vendor installers (GPU drivers, Oracle JDK), " +
			"manually built libraries or files a package's install script generated. Check who installed it " +
			"(file times, the processes that map it) and compare its checksum with the vendor's.",
	})
}

// checkPackagedLibraries compares system libraries mapped into running
// processes with the checksums of the package that installed them (dpkg
// md5sums, or the SQLite rpm database). A library that differs was modified
// in place after installation: the way Ebury and similar implants trojanise
// libkeyutils, libcrypto or libpam so that sshd loads them from their normal
// path.
func (c *Cell) checkPackagedLibraries(ctx context.Context, rec *core.Recorder) (int, error) {
	mapped, err := c.mappedSystemLibs(ctx)
	if err != nil {
		return 0, err
	}
	c.addPAMModules(mapped)
	if len(mapped) == 0 {
		return 0, nil
	}
	wanted := make(map[string]bool, len(mapped))
	paths := make([]string, 0, len(mapped))
	for p := range mapped {
		wanted[p] = true
		paths = append(paths, p)
	}
	sort.Strings(paths)
	declared, owners, source := c.declaredDigests(rec, wanted)
	if declared == nil {
		return 0, nil
	}

	suspicious, verified, unowned := 0, 0, 0
	for _, p := range paths {
		if owners != nil && owners[p] == "" {
			unowned++
			suspicious++
			c.reportUnowned(rec, p, source, mapped[p])
			continue
		}
		var usable []pkgDigest
		for _, d := range declared[p] {
			if d.algo == "md5" || d.algo == "sha256" {
				usable = append(usable, d)
			}
		}
		if len(usable) == 0 {
			continue // not shipped with a checksum (generated at install time or unowned)
		}
		computed := map[string]string{}
		match, failed := false, false
		for _, d := range usable {
			got, ok := computed[d.algo]
			if !ok {
				if got, err = fileDigest(c.path(p), d.algo); err != nil {
					failed = true
					break
				}
				computed[d.algo] = got
			}
			if got == d.hex {
				match = true
				break
			}
		}
		if failed {
			continue
		}
		verified++
		if match {
			continue
		}
		pkg := usable[0].pkg
		expected := make([]string, 0, len(usable))
		for _, d := range usable {
			expected = append(expected, d.algo+":"+d.hex)
		}
		sort.Strings(expected)
		actual := make([]string, 0, len(computed))
		for algo, sum := range computed {
			actual = append(actual, algo+":"+sum)
		}
		sort.Strings(actual)
		pids := mapped[p]
		if len(pids) > 10 {
			pids = append(pids[:10:10], fmt.Sprintf("… (%d more)", len(mapped[p])-10))
		}
		d := map[string]string{
			"library":         p,
			"package":         pkg,
			"package_manager": source,
			"checksum":        strings.Join(actual, ", "),
			"expected":        strings.Join(expected, ", "),
			"mapped_by_pids":  strings.Join(pids, ", "),
		}
		var st unix.Stat_t
		if unix.Stat(c.path(p), &st) == nil {
			d["size"] = strconv.FormatInt(st.Size, 10)
			d["modified"] = fmt.Sprintf("%d", st.Mtim.Sec)
			d["changed"] = fmt.Sprintf("%d", st.Ctim.Sec)
		}
		fsutil.MergeMetadata(d, "file_", fsutil.FileMetadata(c.path(p)))
		suspicious++
		rec.Suspicious(core.Finding{
			Description: fmt.Sprintf("System library %s differs from the copy package %s installed", p, pkg),
			Details:     d,
			Why: "Running processes have this library mapped, and its checksum no longer matches the one its package " +
				"declares. Implants such as Ebury replace a library that sshd loads (libkeyutils, libcrypto, libpam) " +
				"with a trojanised build at its normal path, which no preload or unusual-directory check can see.",
			Benign: "A library rebuilt or patched locally, or a package whose files were modified by an installer script. " +
				"Compare with the package's copy (rpm -V " + pkg + " or debsums " + pkg + ") or reinstall the package.",
		})
	}
	rec.Log().Debug("package ownership", "source", source, "unowned", unowned)
	rec.Log().Debug("package checksums", "source", source, "mapped_libraries", len(paths), "with_checksum", len(declared), "verified", verified)
	if verified > 0 {
		rec.Observe(fmt.Sprintf("%d of %d mapped system libraries verified against %s package checksums", verified, len(paths), source), nil)
	}
	if verified == 0 {
		rec.Limit("No mapped system library had a package checksum to verify (%d libraries mapped)", len(paths))
	}
	return suspicious, nil
}
