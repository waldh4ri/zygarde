# Zygarde documentation

| I want to... | Read |
|--------------|------|
| run Zygarde on a host and understand the output | [Getting started](getting-started.md), then [Usage and reports](usage.md) |
| know what each check (Cell) detects and when it reports SUSPICIOUS | [Cell reference](cells.md) |
| understand how it works and why its results can be trusted | [Architecture](architecture.md) |
| know which kernels, distributions and lockdown modes work | [Compatibility](compatibility.md) |
| build it, change it, add a Cell | [Development](development.md) |
| run unit tests, the kernel matrix or the detection fixtures | [Testing](testing.md) |

## One-paragraph summary

Zygarde is a single static Linux binary (x86_64 and arm64). It is split into **Cells**. Each Cell reads one thing two ways: the **kernel view**, taken with eBPF programs that walk kernel data structures directly, and the **userspace view**, what `ps`, `ls`, `lsmod`, `ss`, `bpftool` or `/proc` would show. A rootkit that hides something from userspace leaves a difference between the two. To keep the scanner itself from being fooled, it runs its Cells in a supervised child process and plants **canaries** (objects it created and knows must be visible) in every view it compares.

## Glossary

- **Cell**: one detection module (a Go package under `cells/`, usually with an eBPF C program next to it).
- **Kernel view / userspace view**: the two sources a Cell compares. A gap means something is filtering one of them.
- **Finding**: a SUSPICIOUS observation, always with evidence, *why* it indicates tampering and *benign causes* to rule out.
- **Observation**: context that is reported but is not suspicious on its own (for example a legitimate kprobe).
- **Canary**: an object Zygarde plants itself (process, file, BPF program, socket, hook) and expects to find. A missing canary means the view is filtered.
- **Limitation**: part of a Cell that could not run on this host. A clean verdict covers only what actually ran.
- **Attribution**: deciding whether a kernel address belongs to the kernel image, a visible module, a BPF program or a trampoline, or to nothing visible (a hidden module).
- **Worker**: the supervised child process that actually runs the Cells.
- **CO-RE / BTF**: Compile Once, Run Everywhere. The eBPF bytecode is relocated at load time against the running kernel's type information (`/sys/kernel/btf/vmlinux`).
