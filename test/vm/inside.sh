#!/bin/sh
# Runs inside a test VM: records kernel facts and zygarde's JSON results.
#
# usage: inside.sh <zygarde-binary> <output-dir> [lockdown-mode]
#
# Writes <output-dir>/meta.env and <output-dir>/results.json. Uses only
# POSIX sh and coreutils so it also works on minimal distribution images.
# If lockdown-mode is given ("integrity" or "confidentiality"), lockdown is
# raised to it first; it can't be lowered again without a reboot.
set -u

bin=$1
out=$2
lockdown=${3:-}
mkdir -p "$out"

if [ -n "$lockdown" ]; then
	mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
	if ! echo "$lockdown" > /sys/kernel/security/lockdown 2>/dev/null; then
		echo "lockdown_error=could not set lockdown=$lockdown" >> "$out/meta.env"
	fi
fi

"$bin" --json > "$out/results.json" 2> "$out/stderr.log"
code=$?

distro=unknown
if [ -r /etc/os-release ]; then
	distro=$(. /etc/os-release && echo "${PRETTY_NAME:-$ID}")
fi
{
	echo "kernel=$(uname -r)"
	echo "arch=$(uname -m)"
	echo "distro=$distro"
	if [ -e /sys/kernel/btf/vmlinux ]; then echo "btf=yes"; else echo "btf=no"; fi
	# "none [integrity] confidentiality" -> "integrity"
	mode=$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null)
	echo "lockdown=${mode:-unavailable}"
	echo "exit=$code"
} >> "$out/meta.env"
