package userhooks

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/fsutil"
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

func fileMD5(path string) (string, error) {
	f, err := fsutil.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

// checkPackagedLibraries compares system libraries mapped into running
// processes with the checksums of the package that installed them (Debian and
// derivatives). A library that differs was modified in place after
// installation: the way Ebury and similar implants trojanise libkeyutils,
// libcrypto or libpam so that sshd loads them from their normal path.
func (c *Cell) checkPackagedLibraries(ctx context.Context, rec *core.Recorder) (int, error) {
	infoDir := c.path(dpkgInfoDir)
	if _, err := os.Stat(infoDir); err != nil {
		rec.Limit("Mapped system libraries were not verified against package checksums: only dpkg systems are supported (no %s)", dpkgInfoDir)
		return 0, nil
	}
	mapped, err := c.mappedSystemLibs(ctx)
	if err != nil {
		return 0, err
	}
	if len(mapped) == 0 {
		return 0, nil
	}
	wanted := make(map[string]bool, len(mapped))
	for p := range mapped {
		wanted[p] = true
	}
	sums, packages, err := packagedChecksums(infoDir, wanted)
	if err != nil || packages == 0 {
		rec.Limit("Mapped system libraries were not verified against package checksums: no %s files found", "*.md5sums")
		return 0, nil
	}

	paths := make([]string, 0, len(mapped))
	for p := range mapped {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	suspicious, verified := 0, 0
	for _, p := range paths {
		want := sums[p]
		if len(want) == 0 {
			continue // not shipped with a checksum (generated at install time or unowned)
		}
		got, err := fileMD5(c.path(p))
		if err != nil {
			continue
		}
		verified++
		if _, ok := want[got]; ok {
			continue
		}
		pkg, expected := "", make([]string, 0, len(want))
		for sum, name := range want {
			expected = append(expected, sum)
			pkg = name
		}
		sort.Strings(expected)
		pids := mapped[p]
		if len(pids) > 10 {
			pids = append(pids[:10:10], fmt.Sprintf("… (%d more)", len(mapped[p])-10))
		}
		d := map[string]string{
			"library":        p,
			"package":        pkg,
			"md5":            got,
			"expected_md5":   strings.Join(expected, ", "),
			"mapped_by_pids": strings.Join(pids, ", "),
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
				"Compare with the package's copy (apt-get download <package>, dpkg-deb -x) or reinstall it (apt-get install --reinstall).",
		})
	}
	rec.Log().Debug("package checksums", "mapped_libraries", len(paths), "with_checksum", len(sums), "verified", verified, "packages", packages)
	if verified > 0 {
		rec.Observe(fmt.Sprintf("%d of %d mapped system libraries verified against package checksums", verified, len(paths)), nil)
	}
	if verified == 0 && len(paths) > 0 {
		rec.Limit("No mapped system library had a package checksum to verify (%d libraries mapped)", len(paths))
	}
	return suspicious, nil
}
