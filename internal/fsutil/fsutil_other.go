//go:build !linux

package fsutil

import (
	"io/fs"
	"os"
)

func OpenNoAtime(path string) (*os.File, error)      { return os.Open(path) }
func openDirNoAtime(path string) (*os.File, error)   { return os.Open(path) }
func fillStatSys(_ fs.FileInfo, _ map[string]string) {}
func withComm(_ string, fn func())                   { fn() }
