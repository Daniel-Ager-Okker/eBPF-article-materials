//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define FIM_MODIFY      (1 << 0)
#define FIM_ATTRIB      (1 << 1)
#define FIM_DELETE      (1 << 2)
#define FIM_MOVE        (1 << 3)
#define FIM_CREATE_IN   (1 << 4)
#define FIM_DELETE_IN   (1 << 5)

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

SEC("kprobe/vfs_write")
int trace_modify_in(struct pt_regs *ctx)
{
    struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
    struct inode *dir = BPF_CORE_READ(filp, f_path.dentry, d_parent, d_inode);

    if (!is_watched_inode(dir))
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

SEC("kprobe/notify_change")
int trace_attrib_in(struct pt_regs *ctx)
{
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    struct inode *dir = BPF_CORE_READ(dentry, d_parent, d_inode);

    if (!is_watched_inode(dir))
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

/* security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
 * In 6.18 the open(O_CREAT) path calls ->create directly, bypassing
 * vfs_create, so the LSM hook is the only point covering all creation
 * routes. may_o_create() also invokes it for O_CREAT on existing files:
 * a positive dentry means no creation is pending. */
SEC("kprobe/security_inode_create")
int trace_create_in(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM1(ctx);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    if (BPF_CORE_READ(dentry, d_inode))
        return 0;

    if (!is_watched_inode(dir))
        return 0;

    struct event e = {};
    fill_meta(&e, FIM_CREATE_IN);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/vfs_mkdir")
int trace_mkdir_in(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM2(ctx);

    if (!is_watched_inode(dir))
        return 0;

    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);

    struct event e = {};
    fill_meta(&e, FIM_CREATE_IN);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/vfs_unlink")
int trace_delete_in(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM2(ctx);

    if (!is_watched_inode(dir))
        return 0;

    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);

    struct event e = {};
    fill_meta(&e, FIM_DELETE_IN);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/vfs_rmdir")
int trace_rmdir_in(struct pt_regs *ctx)
{
    struct inode *dir = (struct inode *)PT_REGS_PARM2(ctx);

    if (!is_watched_inode(dir))
        return 0;

    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);

    struct event e = {};
    fill_meta(&e, FIM_DELETE_IN);

    const unsigned char *name;
    BPF_CORE_READ_INTO(&name, dentry, d_name.name);
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("kprobe/vfs_rmdir")
int trace_rmdir_self(struct pt_regs *ctx)
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

char LICENSE[] SEC("license") = "GPL";
