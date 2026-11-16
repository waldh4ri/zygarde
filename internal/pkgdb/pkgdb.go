// Copyright (c) 2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package pkgdb answers which installed package owns a file, from the dpkg
// file lists or the SQLite rpm database, read directly (no dpkg or rpm binary).
package pkgdb

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/waldh4ri/zygarde/internal/fsutil"
	"github.com/waldh4ri/zygarde/internal/rpmdb"
)

// DpkgInfoDir holds one <package>.list (and .md5sums) file per installed Debian package.
const DpkgInfoDir = "/var/lib/dpkg/info"

// RPMDBPaths are where rpm keeps its SQLite database ("/var/lib/rpm" is
// usually a symlink to the first).
var RPMDBPaths = []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite"}

// ErrNoDatabase means neither a dpkg database nor a SQLite rpm database was found.
var ErrNoDatabase = errors.New("no dpkg or SQLite rpm database found (Berkeley DB rpm databases are not supported)")

// PathVariants returns the names a packaged file can be recorded under: the
// path as given and with the usr-merge prefix added or removed.
func PathVariants(p string) []string {
	if strings.HasPrefix(p, "/usr/") {
		return []string{p, strings.TrimPrefix(p, "/usr")}
	}
	return []string{p, "/usr" + p}
}

// DpkgOwners returns, for each wanted path, a package whose file list
// (<infoDir>/*.list) contains it. Unlike the md5sums files, the lists cover
// every file a package installs, so a path missing from all of them is unowned.
func DpkgOwners(infoDir string, wanted map[string]bool) map[string]string {
	byVariant := map[string]string{}
	for p := range wanted {
		for _, v := range PathVariants(p) {
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

// Owners returns the package owning each wanted path ("" for none) and the
// database used ("dpkg" or "rpm"). root prefixes the database paths (tests
// use a fixture tree).
func Owners(root string, wanted map[string]bool) (map[string]string, string, error) {
	if st, err := os.Stat(filepath.Join(root, DpkgInfoDir)); err == nil && st.IsDir() {
		return DpkgOwners(filepath.Join(root, DpkgInfoDir), wanted), "dpkg", nil
	}
	for _, dbPath := range RPMDBPaths {
		real := filepath.Join(root, dbPath)
		if _, err := os.Stat(real); err != nil {
			continue
		}
		byVariant := map[string]string{}
		variants := map[string]bool{}
		for p := range wanted {
			for _, v := range PathVariants(p) {
				byVariant[v] = p
				variants[v] = true
			}
		}
		_, own, err := rpmdb.Scan(real, variants)
		if err != nil {
			return nil, "rpm", err
		}
		owners := map[string]string{}
		for v, pkg := range own {
			owners[byVariant[v]] = pkg
		}
		return owners, "rpm", nil
	}
	return nil, "", ErrNoDatabase
}
