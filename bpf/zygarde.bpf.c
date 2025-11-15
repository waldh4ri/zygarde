// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Maximum length for file paths and module names
#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 64

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

// Attach to a frequent, harmless syscall to trigger our check
SEC("kprobe/sys_getuid")
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

// Map to store monitored PATH directories (set by user-space)
// Note: Currently unused, kept for future enhancements
/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, __u8);
} monitored_paths SEC(".maps");
*/

// Helper function to check if a path is in monitored directories
static __always_inline int should_monitor_path(const char *filename)
{
	// Check if this is an absolute path in common PATH directories
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
	
	// Get task state
	info.state = BPF_CORE_READ(task, __state);
	
	// Copy command name
	bpf_probe_read_kernel_str(&info.comm, sizeof(info.comm), &task->comm);
	
	// Submit the data to the iterator's seq_file
	ret = bpf_seq_write(seq, &info, sizeof(info));
	if (ret < 0) {
		// Returning a non-zero value can signal an error
		return 1;
	}
	
	return 0;
}
