//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define FIM_MODIFY      (1 << 0)
#define FIM_ATTRIB      (1 << 1)
#define FIM_DELETE      (1 << 2)
#define FIM_MOVE        (1 << 3)

struct event {
    __u32 event_type;
    __u32 uid;
    __u32 pid;
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* Inodes provided by userspace CLI (path -> inode). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} watched_inodes SEC(".maps");

static __always_inline int is_watched_inode(struct inode *inode)
{
    __u64 ino;
    __u8 *watched;

    if (!inode)
        return 0;

    ino = BPF_CORE_READ(inode, i_ino);
    watched = bpf_map_lookup_elem(&watched_inodes, &ino);
    return watched != NULL;
}

static __always_inline void fill_meta(struct event *e, __u32 event_type)
{
    e->event_type = event_type;
    e->uid = bpf_get_current_uid_gid();
    e->pid = bpf_get_current_pid_tgid() >> 32;
}

SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx)
{
    struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
    struct inode *inode = BPF_CORE_READ(filp, f_inode);

    if (!is_watched_inode(inode))
        return 0;

    struct event e = {};
    fill_meta(&e, FIM_MODIFY);
    
    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, filp, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/notify_change")
int trace_setattr(struct pt_regs *ctx)
{
    /* notify_change(struct mnt_idmap *idmap, struct dentry *dentry, ...) */
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (!is_watched_inode(inode))
        return 0;

    struct event e = {};
    fill_meta(&e, FIM_ATTRIB);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/vfs_unlink")
int trace_delete(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (!is_watched_inode(inode))
        return 0;

    struct event e = {};
    fill_meta(&e, FIM_DELETE);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}


SEC("kprobe/vfs_rename")
int trace_move(struct pt_regs *ctx)
{
    /* vfs_rename(struct renamedata *rd) */
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
    struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
    struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);

    if (!is_watched_inode(inode))
        return 0;

    struct event e = {};
    fill_meta(&e, FIM_MOVE);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, old_dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
