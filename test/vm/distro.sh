#!/bin/bash
# Runs zygarde on distribution kernels by booting official cloud images with
# QEMU. cloud-init runs test/vm/inside.sh from a seed ISO, and the results come
# back over a dedicated console (second serial port on x86_64, virtio console
# on arm64), so no SSH or network setup is needed.
#
# x86_64 images run with KVM; arm64 images are emulated (TCG) and slower.
#
# Must run in the zygarde-vmtest image (build/vmtest.Dockerfile) with /dev/kvm,
# from the repository root, after `make dist` (dist/zygarde-linux-<arch>).
#
# usage: test/vm/distro.sh [name...]     names from test/vm/distros.txt
# env:   IMAGE_CACHE (default /images)   where base images are kept
#        JOBS        (default 6)         VMs booted in parallel
#        VM_TIMEOUT  (default 900)       seconds before a KVM VM is abandoned
#                                        (tripled for emulated VMs)
set -euo pipefail

if [ ! -e /dev/kvm ]; then
	echo "error: /dev/kvm is missing. Run in a privileged container on a host with KVM." >&2
	echo "On Docker Desktop with WSL2, start any WSL distro first so the kvm module loads." >&2
	exit 1
fi

root=$(pwd)
outdir=$root/test/vm/out
cache=${IMAGE_CACHE:-/images}
jobs=${JOBS:-6}
vm_timeout=${VM_TIMEOUT:-900}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$cache" "$outdir"

# fetch downloads an image once; the cache key includes a hash of the URL.
fetch() {
	local url=$1
	local file
	file=$cache/$(printf '%s' "$url" | sha1sum | cut -c1-12)-$(basename "$url")
	if [ ! -s "$file" ]; then
		curl -fsSL --retry 3 -o "$file.part" "$url"
		mv "$file.part" "$file"
	fi
	echo "$file"
}

# qemu_cmd prints the QEMU invocation for an architecture.
qemu_cmd() {
	local arch=$1 vm=$2 dir=$3
	case $arch in
	amd64)
		echo qemu-system-x86_64 -accel kvm -cpu host -m 2048 -smp 2 \
			-serial "file:$dir/console.log" -serial "file:$vm/results.log" \
			-drive "file=$vm/disk.qcow2,if=virtio" \
			-drive "file=$vm/seed.iso,media=cdrom"
		;;
	arm64)
		cp /usr/share/AAVMF/AAVMF_VARS.fd "$vm/vars.fd"
		echo qemu-system-aarch64 -machine virt -cpu max -m 2048 -smp 4 \
			-drive "if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd" \
			-drive "if=pflash,format=raw,file=$vm/vars.fd" \
			-serial "file:$dir/console.log" \
			-device virtio-serial-device -chardev "file,id=results,path=$vm/results.log" \
			-device virtconsole,chardev=results \
			-drive "file=$vm/disk.qcow2,if=virtio" \
			-drive "file=$vm/seed.iso,if=virtio,format=raw,readonly=on"
		;;
	esac
}

run_one() {
	local name=$1 url=$2 lockdown=$3 arch=$4 fixtures=$5
	local vm=$work/$name dir=$outdir/$name
	local results_tty=/dev/ttyS1 timeout=$vm_timeout
	if [ "$arch" = arm64 ]; then
		results_tty=/dev/hvc0
		timeout=$((vm_timeout * 3))
	fi
	mkdir -p "$vm/seed"
	rm -rf "$dir"
	mkdir -p "$dir"
	echo "target=distro $name${lockdown:+ (lockdown=$lockdown)}" > "$dir/meta.env"

	local base
	if ! base=$(fetch "$url"); then
		echo "boot_error=download failed: $url" >> "$dir/meta.env"
		return
	fi
	# No size: inherit the base image's, which may be larger than any default.
	qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$vm/disk.qcow2"

	cp "$root/dist/zygarde-linux-$arch" "$vm/seed/zygarde"
	cp "$root/test/vm/inside.sh" "$vm/seed/"
	local fixture_env=""
	if [ "$fixtures" = fixtures ]; then
		cp "$work/fixture-$arch" "$vm/seed/zyg-fixture"
		cp "$root/test/vm/fixtures.sh" "$vm/seed/"
		fixture_env="FIXTURE=/usr/local/sbin/zyg-fixture"
	fi
	echo "instance-id: zygarde-$name" > "$vm/seed/meta-data"
	cat > "$vm/seed/user-data" <<-EOF
		#cloud-config
		runcmd:
		  - |
		    set -x
		    mkdir -p /run/zygseed
		    mount -o ro -L cidata /run/zygseed || mount -o ro /dev/sr0 /run/zygseed
		    cp /run/zygseed/zygarde /usr/local/sbin/zygarde-test  # /run is often noexec
		    chmod 755 /usr/local/sbin/zygarde-test
		    if [ -e /run/zygseed/zyg-fixture ]; then install -m 755 /run/zygseed/zyg-fixture /usr/local/sbin/zyg-fixture; fi
		    $fixture_env sh /run/zygseed/inside.sh /usr/local/sbin/zygarde-test /run/zygout $lockdown > /dev/console 2>&1
		    for f in meta.env results.json stderr.log fixtures.log; do
		      [ -e /run/zygout/\$f ] || continue
		      echo "--- \$f"; cat /run/zygout/\$f
		    done > $results_tty
		    echo "--- end" > $results_tty
		    poweroff -f
	EOF
	xorriso -as mkisofs -quiet -o "$vm/seed.iso" -V cidata -J -r "$vm/seed"

	echo "=== $name ($arch): booting"
	# shellcheck disable=SC2046
	if ! timeout "$timeout" $(qemu_cmd "$arch" "$vm" "$dir") \
		-display none -monitor none \
		-netdev user,id=n0 -device virtio-net-pci,netdev=n0; then
		echo "boot_error=VM did not power off within ${timeout}s (see console.log)" >> "$dir/meta.env"
	fi

	# Split "--- <file>" sections back into files (appending: meta.env
	# already holds the target name).
	touch "$vm/results.log"
	awk -v dir="$dir" '
		{ sub(/\r$/, "") }
		/^--- end/ { exit }
		/^--- / { f = dir "/" $2; next }
		f { print >> f }
	' "$vm/results.log"
	if [ ! -s "$dir/results.json" ] && ! grep -q boot_error "$dir/meta.env"; then
		echo "boot_error=no results on the results console (see console.log)" >> "$dir/meta.env"
	fi
	echo "=== $name: done"
}

targets=()
while IFS='|' read -r name url lockdown arch fixtures; do
	case $name in ''|'#'*) continue ;; esac
	if [ $# -eq 0 ] || printf '%s\n' "$@" | grep -qx "$name"; then
		targets+=("$name|$url|$lockdown|${arch:-amd64}|$fixtures")
	fi
done < "$root/test/vm/distros.txt"

# The fixture helper (test/vm/fixture), for targets that plant fixtures.
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOARCH=$arch go build -o "$work/fixture-$arch" ./test/vm/fixture
done

running=0
for t in "${targets[@]}"; do
	IFS='|' read -r name url lockdown arch fixtures <<< "$t"
	run_one "$name" "$url" "$lockdown" "$arch" "$fixtures" &
	running=$((running + 1))
	if [ "$running" -ge "$jobs" ]; then
		wait -n
		running=$((running - 1))
	fi
done
wait
