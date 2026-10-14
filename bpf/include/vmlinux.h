/* Selects the kernel type definitions matching the BPF target architecture.
 * bpf2go defines __TARGET_ARCH_<arch> for each -target it builds.
 *
 * x86/vmlinux.h   - dumped from a BTF-enabled x86_64 kernel
 * arm64/vmlinux.h - from github.com/libbpf/vmlinux.h (aarch64, Linux 6.19)
 *
 * CO-RE relocates field accesses at load time, so these headers only need to
 * contain the types we use; they don't have to match the target kernel.
 */
#if defined(__TARGET_ARCH_x86)
#include "x86/vmlinux.h"
#elif defined(__TARGET_ARCH_arm64)
#include "arm64/vmlinux.h"
#else
#error "unsupported BPF target architecture"
#endif
