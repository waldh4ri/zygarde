// Copyright (c) 2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package zygarde holds the license texts embedded in the zygarde binary, so a
// binary distributed on its own still carries the notices that the licenses of
// its components require.
package zygarde

import _ "embed"

// License is Zygarde's own license notice (the LICENSE file).
//
//go:embed LICENSE
var License string

// ThirdParty is the notices for the third-party code compiled into the binary
// (the THIRD_PARTY_LICENSES file).
//
//go:embed THIRD_PARTY_LICENSES
var ThirdParty string
