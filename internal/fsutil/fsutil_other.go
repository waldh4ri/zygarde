// Copyright (c) 2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

//go:build !linux

package fsutil

import (
	"io/fs"
	"os"
)

func ControlledBy(_, _ string) string { return "" }

func Open(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	return os.Open(path)
}

func OpenSystem(path string) (*os.File, error)     { return os.Open(path) }
func Owner(_ *os.File) (uint32, error)             { return 0, nil }
func OpenNoAtime(path string) (*os.File, error)    { return os.Open(path) }
func OpenDirNoAtime(path string) (*os.File, error) { return os.Open(path) }
func InListing(dir, name string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return inListing(f, name)
}
func OpenInRoot(_, _ string, _ int) (*os.File, error) { return nil, ErrNoOpenat2 }
func SameAsHostRoot(_ string) bool                    { return false }
func fillStatSys(_ fs.FileInfo, _ map[string]string)  {}
func withComm(_ string, fn func())                    { fn() }
