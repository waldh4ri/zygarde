// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

//go:build !linux

package main

import "os"

func termWidth(_ *os.File) int   { return 100 }
func isTerminal(_ *os.File) bool { return false }
