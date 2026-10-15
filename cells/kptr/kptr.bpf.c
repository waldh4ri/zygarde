//go:build ignore

// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Function pointer integrity: read the operation tables behind zygarde's own
// file descriptors (file_operations, inode_operations, seq_operations and
// procfs proc_ops), starting from the struct file the iterator hands us.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PROC_SUPER_MAGIC 0x9fa0
#define S_IFMT  00170000
#define S_IFREG 0100000

// ops_rec.flags
#define F_SEQ     1 // private_data is a seq_file (sop[] valid)
#define F_PDE     2 // procfs file backed by a proc_dir_entry (pops[] valid)
#define F_ITERATE 4 // file_operations still has ->iterate (before 6.6)

struct ops_rec {
	__u32 fd;
	__u32 flags;
	__u64 s_magic;
	__u64 file_ops;
	__u64 file_fn[6];  // llseek, read, read_iter, iterate, iterate_shared, open
	__u64 inode_ops;
	__u64 inode_fn[2]; // lookup, getattr
	__u64 seq_ops;
	__u64 seq_fn[4];   // start, next, stop, show
	__u64 pde;
	__u64 proc_ops;
	__u64 proc_fn[4];  // proc_open, proc_read, proc_read_iter, proc_lseek
	__u64 pde_seq;  // proc_dir_entry seq_ops/single_show union
	char fs_owner[56];
};

const struct ops_rec *unused_ops_rec __attribute__((unused));

// Removed in Linux 6.6.
struct file_operations___old {
	int (*iterate)(struct file *, struct dir_context *);
} __attribute__((preserve_access_index));

// procfs internals (fs/proc/internal.h), declared here because not every
// vmlinux.h carries them. CO-RE matches them to the running kernel by name.
struct proc_dir_entry___z {
	const struct proc_ops *proc_ops;
	const void *seq_ops;
} __attribute__((preserve_access_index));

struct proc_inode___z {
	struct proc_dir_entry___z *pde;
	struct inode vfs_inode;
} __attribute__((preserve_access_index));

// Only dereference values that look like kernel addresses. Every pointer
// followed here comes from the kernel's own structures, but a corrupted or
// tagged one must not be chased. On x86_64 the top 16 MiB (fixmap, vsyscall
// page) is excluded: reading the vsyscall page oopses some kernels.
static __always_inline bool kaddr(__u64 p)
{
#if defined(__TARGET_ARCH_x86)
	return p >= 0xff00000000000000ULL && p < 0xffffffffff000000ULL;
#else
	return p >= 0xff00000000000000ULL && p < 0xfffffffffffff000ULL;
#endif
}

SEC("iter/task_file")
int dump_ops(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct task_struct *self = (struct task_struct *)bpf_get_current_task();
	struct ops_rec rec = {};
	const struct file_operations *fop;
	const struct inode_operations *iop;
	struct inode *inode;
	struct super_block *sb;
	struct module *owner;
	void *priv;

	if (!task || !file)
		return 0;
	// Only zygarde's own descriptors: it reads the iterator itself.
	if (BPF_CORE_READ(task, tgid) != BPF_CORE_READ(self, tgid))
		return 0;
	rec.fd = ctx->fd;

	fop = BPF_CORE_READ(file, f_op);
	rec.file_ops = (__u64)fop;
	if (kaddr(rec.file_ops)) {
		rec.file_fn[0] = (__u64)BPF_CORE_READ(fop, llseek);
		rec.file_fn[1] = (__u64)BPF_CORE_READ(fop, read);
		rec.file_fn[2] = (__u64)BPF_CORE_READ(fop, read_iter);
		if (bpf_core_field_exists(((struct file_operations___old *)0)->iterate)) {
			rec.file_fn[3] = (__u64)BPF_CORE_READ((struct file_operations___old *)fop, iterate);
			rec.flags |= F_ITERATE;
		}
		rec.file_fn[4] = (__u64)BPF_CORE_READ(fop, iterate_shared);
		rec.file_fn[5] = (__u64)BPF_CORE_READ(fop, open);
	}

	inode = BPF_CORE_READ(file, f_inode);
	if (!kaddr((__u64)inode))
		goto out;
	iop = BPF_CORE_READ(inode, i_op);
	rec.inode_ops = (__u64)iop;
	if (kaddr(rec.inode_ops)) {
		rec.inode_fn[0] = (__u64)BPF_CORE_READ(iop, lookup);
		rec.inode_fn[1] = (__u64)BPF_CORE_READ(iop, getattr);
	}

	// The filesystem and the module implementing it (NULL when built in).
	sb = BPF_CORE_READ(inode, i_sb);
	if (kaddr((__u64)sb)) {
		rec.s_magic = BPF_CORE_READ(sb, s_magic);
		owner = BPF_CORE_READ(sb, s_type, owner);
		if (kaddr((__u64)owner))
			BPF_CORE_READ_STR_INTO(&rec.fs_owner, owner, name);
	}

	// seq_file: the kernel points seq_file->file back at the file it serves,
	// which tells a seq_file apart from other private data.
	priv = BPF_CORE_READ(file, private_data);
	if (kaddr((__u64)priv) && bpf_core_field_exists(((struct seq_file *)0)->file)) {
		struct seq_file *sf = priv;
		const struct seq_operations *sop;

		if ((__u64)BPF_CORE_READ(sf, file) == (__u64)file) {
			sop = BPF_CORE_READ(sf, op);
			rec.flags |= F_SEQ;
			rec.seq_ops = (__u64)sop;
			if (kaddr(rec.seq_ops)) {
				rec.seq_fn[0] = (__u64)BPF_CORE_READ(sop, start);
				rec.seq_fn[1] = (__u64)BPF_CORE_READ(sop, next);
				rec.seq_fn[2] = (__u64)BPF_CORE_READ(sop, stop);
				rec.seq_fn[3] = (__u64)BPF_CORE_READ(sop, show);
			}
		}
	}

	// procfs regular files: the proc_dir_entry's own operations, which the
	// generic proc_reg_* file operations forward to (PDE(inode)).
	if (rec.s_magic == PROC_SUPER_MAGIC &&
	    (BPF_CORE_READ(inode, i_mode) & S_IFMT) == S_IFREG &&
	    bpf_core_type_exists(struct proc_inode___z) &&
	    bpf_core_field_exists(((struct proc_dir_entry___z *)0)->proc_ops)) {
		struct proc_inode___z *pi = (void *)inode - bpf_core_field_offset(struct proc_inode___z, vfs_inode);
		struct proc_dir_entry___z *pde = BPF_CORE_READ(pi, pde);
		const struct proc_ops *pops;

		if (kaddr((__u64)pde)) {
			rec.flags |= F_PDE;
			rec.pde = (__u64)pde;
			pops = BPF_CORE_READ(pde, proc_ops);
			rec.proc_ops = (__u64)pops;
			if (kaddr(rec.proc_ops)) {
				rec.proc_fn[0] = (__u64)BPF_CORE_READ(pops, proc_open);
				rec.proc_fn[1] = (__u64)BPF_CORE_READ(pops, proc_read);
				if (bpf_core_field_exists(pops->proc_read_iter))
					rec.proc_fn[2] = (__u64)BPF_CORE_READ(pops, proc_read_iter);
				rec.proc_fn[3] = (__u64)BPF_CORE_READ(pops, proc_lseek);
			}
			if (bpf_core_field_exists(pde->seq_ops))
				rec.pde_seq = (__u64)BPF_CORE_READ(pde, seq_ops);
		}
	}

out:
	bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec));
	return 0;
}
