// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Maximum length for file paths and module names
#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 64

// Minimal flavored declaration for older kernels exposing task_struct.state
struct task_struct___old {
    unsigned long state;
};

// Read-only configuration for monitored paths (populated by userspace if needed)
struct cfg_paths {
    bool use_custom_paths;               // if true, use prefixes below; otherwise built-in defaults
    __u32 prefix_count;                  // number of valid prefixes
    __u16 prefix_lens[8];                // length of each prefix
    char prefixes[8][MAX_PATH_LEN];      // up to 8 path prefixes
};

// Placed in .rodata so verifier treats as read-only constant memory
const struct cfg_paths zygarde_cfg SEC(".rodata") = {
    .use_custom_paths = false,
    .prefix_count = 0,
};
// ============================================================================
// Feature 1: System Call Table Integrity Check
// ============================================================================

// Event structure for syscall table entries
struct syscall_event {
	__u64 syscall_addr;  // Address read from sys_call_table
	__u32 syscall_num;   // Syscall number checked
};

// Ring buffer for syscall events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

// Configuration map: stores sys_call_table address and syscall number to check
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} syscall_config SEC(".maps");

// Kprobe with generic name; userspace overrides the attach point dynamically
SEC("kprobe/dummy")
int check_syscall_table(struct pt_regs *ctx)
{
	struct syscall_event *e;
	__u32 key0 = 0, key1 = 1;
	__u64 *sys_call_table_addr;
	__u64 *syscall_num_ptr;
	__u64 syscall_entry_addr;
	__u64 *table_entry_ptr;
	
	// Get the sys_call_table address from config
	sys_call_table_addr = bpf_map_lookup_elem(&syscall_config, &key0);
	if (!sys_call_table_addr)
		return 0;
	
	// Get the syscall number to check from config
	syscall_num_ptr = bpf_map_lookup_elem(&syscall_config, &key1);
	if (!syscall_num_ptr)
		return 0;
	
	// Calculate the address of the syscall entry in the table
	// sys_call_table[syscall_num]
	table_entry_ptr = (void *)(*sys_call_table_addr + (*syscall_num_ptr * sizeof(void *)));
	
	// Read the actual function pointer from the syscall table
	if (bpf_probe_read_kernel(&syscall_entry_addr, sizeof(syscall_entry_addr), table_entry_ptr) != 0)
		return 0;
	
	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&syscall_events, sizeof(*e), 0);
	if (!e)
		return 0;
	
	// Fill the event
	e->syscall_addr = syscall_entry_addr;
	e->syscall_num = (__u32)*syscall_num_ptr;
	
	// Submit the event
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

// ============================================================================
// Feature 2: Hidden Kernel Module Detection
// ============================================================================

// Note: BPF iterator for modules may not be available on all kernels
// This feature will be implemented in user-space using /proc/modules
// and comparing with kernel symbols from /proc/kallsyms

// ============================================================================
// Feature 3: Hidden File Detection in $PATH
// ============================================================================

// Event structure for file access tracking
struct file_access_event {
	__u32 pid;
	__u32 syscall_type;  // 0=execve, 1=openat, 2=open, 3=openat2
	char filename[MAX_PATH_LEN];
};

// Ring buffer for file access events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} execve_events SEC(".maps");

// Helper function to check if a path is in monitored directories
static __always_inline int should_monitor_path(const char *filename)
{
	// If configured, use read-only custom prefixes
	if (zygarde_cfg.use_custom_paths && zygarde_cfg.prefix_count > 0) {
		if (filename[0] != '/')
			return 0;
		#pragma unroll
		for (int i = 0; i < 8; i++) {
			if ((__u32)i >= zygarde_cfg.prefix_count)
				break;
			__u16 plen = zygarde_cfg.prefix_lens[i];
			if (plen == 0)
				continue;
			if (__builtin_memcmp(filename, zygarde_cfg.prefixes[i], plen) == 0)
				return 1;
		}
		return 0;
	}

	// Default set of common PATH directories
	if (filename[0] == '/') {
		if (__builtin_memcmp(filename, "/bin/", 5) == 0 ||
			__builtin_memcmp(filename, "/sbin/", 6) == 0 ||
			__builtin_memcmp(filename, "/usr/bin/", 9) == 0 ||
			__builtin_memcmp(filename, "/usr/sbin/", 10) == 0 ||
			__builtin_memcmp(filename, "/usr/local/bin/", 15) == 0 ||
			__builtin_memcmp(filename, "/usr/local/sbin/", 16) == 0 ||
			__builtin_memcmp(filename, "/opt/", 5) == 0) {
			return 1;
		}
	}
	return 0;
}

// Tracepoint for execve - captures all program executions
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct file_access_event *e;
	const char *filename_ptr;
	char filename[MAX_PATH_LEN];
	__u32 pid;
	int i;
	
	// Get the filename argument (first argument of execve)
	filename_ptr = (const char *)ctx->args[0];
	
	// Read the filename from user space
	if (bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr) < 0)
		return 0;
	
	// Check if this is a path we're monitoring
	if (!should_monitor_path(filename))
		return 0;
	
	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
	if (!e)
		return 0;
	
	// Fill the event
	pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;
	e->syscall_type = 0;  // execve
	
	// Copy filename
	#pragma unroll
	for (i = 0; i < MAX_PATH_LEN; i++) {
		e->filename[i] = filename[i];
		if (filename[i] == '\0')
			break;
	}
	
	// Submit the event
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

// Tracepoint for openat - captures file open operations with dirfd
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct file_access_event *e;
	const char *filename_ptr;
	char filename[MAX_PATH_LEN];
	__u32 pid;
	int i;
	
	// Get the filename argument (second argument of openat, after dirfd)
	filename_ptr = (const char *)ctx->args[1];
	
	// Read the filename from user space
	if (bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr) < 0)
		return 0;
	
	// Check if this is a path we're monitoring
	if (!should_monitor_path(filename))
		return 0;
	
	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
	if (!e)
		return 0;
	
	// Fill the event
	pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;
	e->syscall_type = 1;  // openat
	
	// Copy filename
	#pragma unroll
	for (i = 0; i < MAX_PATH_LEN; i++) {
		e->filename[i] = filename[i];
		if (filename[i] == '\0')
			break;
	}
	
	// Submit the event
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

// Tracepoint for open - captures legacy file open operations
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	struct file_access_event *e;
	const char *filename_ptr;
	char filename[MAX_PATH_LEN];
	__u32 pid;
	int i;
	
	// Get the filename argument (first argument of open)
	filename_ptr = (const char *)ctx->args[0];
	
	// Read the filename from user space
	if (bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr) < 0)
		return 0;
	
	// Check if this is a path we're monitoring
	if (!should_monitor_path(filename))
		return 0;
	
	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
	if (!e)
		return 0;
	
	// Fill the event
	pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;
	e->syscall_type = 2;  // open
	
	// Copy filename
	#pragma unroll
	for (i = 0; i < MAX_PATH_LEN; i++) {
		e->filename[i] = filename[i];
		if (filename[i] == '\0')
			break;
	}
	
	// Submit the event
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

// Tracepoint for openat2 - captures newer file open operations
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct file_access_event *e;
	const char *filename_ptr;
	char filename[MAX_PATH_LEN];
	__u32 pid;
	int i;
	
	// Get the filename argument (second argument of openat2, after dirfd)
	filename_ptr = (const char *)ctx->args[1];
	
	// Read the filename from user space
	if (bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr) < 0)
		return 0;
	
	// Check if this is a path we're monitoring
	if (!should_monitor_path(filename))
		return 0;
	
	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&execve_events, sizeof(*e), 0);
	if (!e)
		return 0;
	
	// Fill the event
	pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;
	e->syscall_type = 3;  // openat2
	
	// Copy filename
	#pragma unroll
	for (i = 0; i < MAX_PATH_LEN; i++) {
		e->filename[i] = filename[i];
		if (filename[i] == '\0')
			break;
	}
	
	// Submit the event
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

// ============================================================================
// Feature 4: Hidden Process Detection using Task Iterator
// ============================================================================

// Event structure for process/thread information
struct task_info {
	__u32 pid;           // Process ID (tgid)
	__u32 tid;           // Thread ID (pid)
	__u32 ppid;          // Parent process ID
	__u32 state;         // Task state
	char comm[16];       // Command name (limited to 16 chars in task_struct)
};

// BPF iterator to walk all tasks in the system
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_info info = {};
	long ret;
	
	// If task is NULL, we've finished iterating
	if (task == NULL)
		return 0;
	
	// Read task information using BPF CO-RE helpers
	// tgid is the PID (thread group ID), pid is the TID
	info.pid = BPF_CORE_READ(task, tgid);
	info.tid = BPF_CORE_READ(task, pid);
	
	// Get parent PID
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		info.ppid = BPF_CORE_READ(parent, tgid);
	else
		info.ppid = 0;
	
	// Get task state with CO-RE guards: __state (newer) or state (older)
    unsigned long st = 0;
    if (bpf_core_field_exists(((struct task_struct___old *)task)->state)) {
        st = BPF_CORE_READ((struct task_struct___old *)task, state);
    } else if (bpf_core_field_exists(task->__state)) {
        st = BPF_CORE_READ(task, __state);
    }
    info.state = st;	// Copy command name
	bpf_probe_read_kernel_str(&info.comm, sizeof(info.comm), &task->comm);
	
	// Submit the data to the iterator's seq_file
	ret = bpf_seq_write(seq, &info, sizeof(info));
	if (ret < 0) {
		// Returning a non-zero value can signal an error
		return 1;
	}
	
	return 0;
}

// ============================================================================
// Feature 5: sys_bpf Enumeration Interference Detection
// ============================================================================
// Detect attempts to prematurely terminate BPF object enumeration by forcing
// -ENOENT on NEXT_ID commands while objects still exist (e.g., hidden programs).

// Commands of interest (mirror linux/bpf.h) relevant to enumeration hiding
#define CMD_PROG_GET_NEXT_ID 11
#define CMD_MAP_GET_NEXT_ID  12
#define CMD_BTF_GET_NEXT_ID  23
#define CMD_LINK_GET_NEXT_ID 27

struct bpf_enter_ctx {
	__u32 cmd;
	__u32 start_id;
	__u64 attr_ptr;
};

struct bpf_enum_event {
	__u32 pid;
	__u32 cmd;
	__u32 start_id;
	__s32 ret;
	__u32 next_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct bpf_enter_ctx);
} bpf_enum_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024);
} bpf_enum_events SEC(".maps");

static __always_inline int is_enum_cmd(__u32 cmd) {
	if (cmd == CMD_PROG_GET_NEXT_ID || cmd == CMD_MAP_GET_NEXT_ID ||
		cmd == CMD_BTF_GET_NEXT_ID || cmd == CMD_LINK_GET_NEXT_ID) return 1;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_sys_enter_bpf(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 attr_ptr = ctx->args[1];
	__u32 cmd = (__u32)ctx->args[0];
	if (!is_enum_cmd(cmd))
		return 0;

	struct bpf_enter_ctx enter = {};
	enter.cmd = cmd;
	enter.attr_ptr = attr_ptr;
	__u32 start_id = 0;
	bpf_probe_read_user(&start_id, sizeof(start_id), (void *)attr_ptr);
	enter.start_id = start_id;
	bpf_map_update_elem(&bpf_enum_ctx, &pid, &enter, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_bpf")
int trace_sys_exit_bpf(struct trace_event_raw_sys_exit *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct bpf_enter_ctx *enter = bpf_map_lookup_elem(&bpf_enum_ctx, &pid);
	if (!enter)
		return 0;
	__s32 ret = (__s32)ctx->ret;

	struct bpf_enum_event *e = bpf_ringbuf_reserve(&bpf_enum_events, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&bpf_enum_ctx, &pid);
		return 0;
	}
	e->pid = pid;
	e->cmd = enter->cmd;
	e->start_id = enter->start_id;
	e->ret = ret;
	e->next_id = 0;
	if (ret == 0) {
		__u32 next_id = 0;
		bpf_probe_read_user(&next_id, sizeof(next_id), (void *)enter->attr_ptr);
		e->next_id = next_id;
	}
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&bpf_enum_ctx, &pid);
	return 0;
}
