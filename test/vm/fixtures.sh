#!/bin/sh
# Plants benign stand-ins for what the Cells look for, so a fixture target
# checks that zygarde reports them (test/vm/fixtures.expect). Throwaway test
# VMs only: it modifies /etc, /usr/bin and /tmp.
#
# usage: fixtures.sh <fixture-binary> <output-dir>
#
# Leaves the fixture helper (BPF programs, listener, disguised process) and
# a process running from a deleted file in /tmp running; zygarde runs next.
set -u

fx=$1
out=$2
mkdir -p "$out"
log=$out/fixtures.log

# userspace_hooks: a system-wide preload of a harmless existing library.
for lib in /usr/lib/x86_64-linux-gnu/libm.so.6 /usr/lib/aarch64-linux-gnu/libm.so.6 \
	/lib/x86_64-linux-gnu/libm.so.6 /lib/aarch64-linux-gnu/libm.so.6 /usr/lib64/libm.so.6 /lib64/libm.so.6; do
	if [ -e "$lib" ]; then
		echo "$lib" > /etc/ld.so.preload
		break
	fi
done

# hidden_file: a "trojaned sudo" in a dot-directory under /usr/bin (Scales).
mkdir -p /usr/bin/.local
cp /bin/true /usr/bin/.local/sudo

# hidden_kernel_module: Mélofée-style loading from outside the module tree,
# and a modprobe.d install directive running a command.
mkdir -p /etc/intel_audio
echo "not a module" > /etc/intel_audio/intel_audio.ko
printf '#!/bin/sh\ninsmod /etc/intel_audio/intel_audio.ko\n' > /etc/rc.modules
mkdir -p /etc/modprobe.d
echo 'install zyg_fixture_mod /usr/local/bin/zyg-fixture-hook' > /etc/modprobe.d/zyg-fixture.conf

# hidden_process: a root process running from a binary deleted from /tmp.
cp /bin/sleep /tmp/zyg-deleted-sleep
/tmp/zyg-deleted-sleep 3600 > /dev/null 2>&1 &
sleep 1
rm -f /tmp/zyg-deleted-sleep

# hidden_ebpf_program, hidden_socket, hidden_process: BPF attachments, a
# listener and a disguised child, held by the fixture helper. Its stdin
# stays open as long as the sleep runs. Tracepoints need tracefs.
if [ ! -e /sys/kernel/tracing/events ] && [ ! -e /sys/kernel/debug/tracing/events ]; then
	mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
fi
sleep 3600 | "$fx" > "$log" 2>&1 &
i=0
while [ $i -lt 30 ] && ! grep -q ready "$log" 2>/dev/null; do
	sleep 1
	i=$((i + 1))
done
echo "fixtures=yes" >> "$out/meta.env"
