//go:build !linux

package main

import "os"

func termWidth(_ *os.File) int   { return 100 }
func isTerminal(_ *os.File) bool { return false }
