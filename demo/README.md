# Demos

The detection demos run a real sample on a disposable VM, which is reset right after: each opens with the date, the distribution and the kernel, shows the sample's SHA-256, and loads it on camera. Zygarde's output is unedited; only the pace is slowed so it can be read.

## gojiberi: a kernel rootkit nobody detects yet

gojiberi is a loadable kernel module rootkit first seen on VirusTotal on 2026-11-19; on 2026-11-28, 0 of 35 engines detected this build. Once loaded it disappears from `lsmod` and `/sys/module`, hooks syscalls through hidden ftrace hooks, and hides its reverse-shell runner, its control file and its own files. Zygarde finds the hooks, the hidden module, the hidden processes and the hidden files.

Ubuntu 22.04, kernel 6.2.0-26-generic (the kernel this build targets). Network egress was blocked, so its C2 traffic never left the VM.

![gojiberi](gojiberi.gif)

## BPFDoor: a passive backdoor with no open port

BPFDoor (Red Menshen) runs as root, copies itself to `/dev/shm`, deletes the copy and takes the name of a system daemon. It opens no port: it sniffs raw packets for a magic value. `ss` shows nothing unusual and `ps` shows an ordinary daemon; Zygarde flags the process running from deleted memory-backed storage and its packet sniffer.

Ubuntu 26.04, kernel 7.0.

![BPFDoor](bpfdoor.gif)

## rkhunter vs Zygarde on BPFDoor

rkhunter scans the clean host, BPFDoor starts, and rkhunter scans again: its output is identical to the baseline. Zygarde, on the same host, reports the implant. (chkrootkit 0.58b is not shown: its BPFDoor check does flag this build.)

Ubuntu 26.04, kernel 7.0, rkhunter 1.4.6.

![rkhunter vs Zygarde](rkhunter-vs-zygarde.gif)

## Diamorphine: a classic syscall-hooking rootkit

Diamorphine, built from source for the running kernel, hooks the syscall table to hide itself, a process and a file. `lsmod`, `ps` and `ls` no longer see them; Zygarde reports the hooked syscall table entries, the hidden module, the hidden process and the hidden file.

Debian 11, kernel 5.10.

![Diamorphine](diamorphine.gif)

## Kernels without BTF, and `--btfhub`

Some distribution kernels are built without BTF, which eBPF CO-RE needs. Zygarde says which checks that costs and where the kernel's BTF can be found. With `--btfhub` it downloads that BTF from the BTFHub archive, verifies it against the hash GitHub publishes, and runs the checks the kernel supports.

Ubuntu 20.04, kernel 5.4.0-72-generic.

![BTFHub](btfhub.gif)
