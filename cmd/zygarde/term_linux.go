//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// termWidth is the output width: the terminal's, or 100 when not a terminal.
func termWidth(f *os.File) int {
	if ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col >= 60 {
		return int(ws.Col)
	}
	return 100
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
