// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf/btf"

	"github.com/waldh4ri/zygarde/internal/btfhub"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/kernel"
	"github.com/waldh4ri/zygarde/internal/report"
)

// fetchBTF handles kernels built without BTF. Without --btfhub it only
// records where BTFHub would have this kernel's BTF, so the header can hint
// at --btfhub. With --btfhub it downloads that BTF into a private temporary
// directory and points the scan at it (o.settings.BTFPath, and --btf in the
// worker's arguments), once its source, size, git blob hash and format check
// out (see package btfhub) and it parses as kernel BTF. It records what it did
// in the report and returns a function removing the temporary file. It does
// nothing when the kernel has its own BTF or --btf is given.
func fetchBTF(ctx context.Context, o *options, rep *report.Report, workerArgs *[]string) func() {
	none := func() {}
	switch {
	case o.settings.BTFPath != "":
		rep.Host.BTFSource = "file"
		return none
	case rep.Host.BTF:
		return none
	}
	release := kernel.Release()
	id, ver := btfhub.OSRelease("/etc/os-release")
	path, err := btfhub.Path(id, ver, release, runtime.GOARCH)
	rec := &report.BTFHub{Requested: o.btfhub, Path: path}
	rep.Host.BTFHub = rec
	if err != nil {
		rec.Error = err.Error()
		return none
	}
	if !o.btfhub {
		return none
	}
	dir, err := os.MkdirTemp("", "zygarde-btf-") // mode 0700
	if err != nil {
		rec.Error = err.Error()
		return none
	}
	cleanup := func() { os.RemoveAll(dir) }

	cctx, cancel := context.WithTimeout(ctx, btfhub.Timeout)
	defer cancel()
	rep.AddArtifact("network", "BTFHub lookup and download of "+path)
	f, err := btfhub.Fetch(cctx, btfhub.NewClient(), path, release, dir, "zygarde/"+version)
	if err == nil {
		err = checkKernelBTF(f.Path)
	}
	if err != nil {
		cleanup()
		rec.Error = err.Error()
		return none
	}
	rec.URL, rec.GitBlobSHA1, rec.ArchiveSHA256, rec.Verified = f.URL, f.GitBlobSHA1, f.ArchiveSHA256, true
	rep.AddArtifact("file", f.Path+" (BTF from BTFHub, removed after the scan)")
	rep.Host.BTFSource = "btfhub"
	o.settings.BTFPath = f.Path
	*workerArgs = append(*workerArgs, "--btf", f.Path)
	return cleanup
}

// checkKernelBTF parses a BTF file and checks that it describes a kernel.
func checkKernelBTF(path string) error {
	spec, err := btf.LoadSpec(path)
	if err != nil {
		return fmt.Errorf("downloaded file is not valid BTF: %w", err)
	}
	if !core.HasBTFType(spec, "task_struct") {
		return errors.New("downloaded BTF does not describe a kernel (no task_struct)")
	}
	return nil
}
