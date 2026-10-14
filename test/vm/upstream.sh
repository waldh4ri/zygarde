#!/bin/bash
# Runs zygarde on upstream kernels from ghcr.io/cilium/ci-kernels using vimto.
# Must run in the zygarde-vmtest image (build/vmtest.Dockerfile) with /dev/kvm,
# from the repository root, after `make build`.
#
# usage: test/vm/upstream.sh [kernel-version...]
set -euo pipefail

# Oldest first. 4.19 and 5.4 lack features most Cells need: they check that
# zygarde degrades to SKIPPED instead of failing. 5.10 predates the
# x64_sys_call() change, so the syscall table Cell really runs there.
DEFAULT_KERNELS=(4.19.322 5.4.296 5.10.270 5.15.221 6.1.188 6.6.157 6.12.111 6.18.53 7.2.7)
kernels=("${@:-${DEFAULT_KERNELS[@]}}")

root=$(pwd)
outdir=$root/test/vm/out
git config --global --add safe.directory "$root" 2>/dev/null || true

run() {
	local name=$1 kernel=$2 lockdown=${3:-}
	local dir=$outdir/$name
	rm -rf "$dir"
	echo "=== $name"
	if ! vimto -kernel "ghcr.io/cilium/ci-kernels:$kernel" -memory size=1G -smp cpus=2 -sudo \
		exec -- /bin/sh "$root/test/vm/inside.sh" "$root/zygarde" "$dir" $lockdown; then
		mkdir -p "$dir"
		echo "boot_error=vimto failed" >> "$dir/meta.env"
	fi
	echo "target=upstream $kernel${lockdown:+ (lockdown=$lockdown)}" >> "$dir/meta.env"
}

for k in "${kernels[@]}"; do
	run "upstream-$k" "$k"
done
