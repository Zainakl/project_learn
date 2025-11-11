// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef MAY_EXEC
#define MAY_EXEC 0x00000001
#endif
#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif
#ifndef MAY_READ
#define MAY_READ  0x00000004
#endif

struct guard_cfg {
    __u64 host_mntns;
    __u64 host_cgid;
};
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, struct guard_cfg); } cfg_map SEC(".maps");

struct deny_event {
    __u64 ts, pid, cgid, mntns;
    __u32 mask;
    char fsname[16];
    char dname[64];
};
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<20); } events SEC(".maps");

static __always_inline __u64 get_current_mntns_inum(void) {
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    struct mnt_namespace *mntns = nsp ? BPF_CORE_READ(nsp, mnt_ns) : NULL;
    struct ns_common *ns = mntns ? &mntns->ns : NULL;
    return ns ? BPF_CORE_READ(ns, inum) : 0;
}

static __always_inline void safe_read_kstr(char *dst, const void *src, __u32 n) {
    if (!dst || !src || !n) return;
    long l = bpf_probe_read_kernel_str(dst, n, src);
    if (l < 0) dst[0] = '\0';
}
static __always_inline void get_fs_name(const struct file *file, char *buf, __u32 n) {
    const struct super_block *sb = file ? BPF_CORE_READ(file, f_inode, i_sb) : NULL;
    const struct file_system_type *t = sb ? BPF_CORE_READ(sb, s_type) : NULL;
    safe_read_kstr(buf, t ? BPF_CORE_READ(t, name) : NULL, n);
}
static __always_inline void get_dentry_name(const struct file *file, char *buf, __u32 n) {
    const struct dentry *de = file ? BPF_CORE_READ(file, f_path.dentry) : NULL;
    const struct qstr *q = de ? &de->d_name : NULL;
    safe_read_kstr(buf, q ? BPF_CORE_READ(q, name) : NULL, n);
}
static __always_inline bool starts_with(const char *s, const char *prefix) {
#pragma unroll
    for (int i = 0; i < 64; i++) {
        char c1 = s[i], c2 = prefix[i];
        if (c2 == '\0') return true;
        if (c1 != c2) return false;
        if (c1 == '\0') return false;
    }
    return false;
}
static __always_inline void emit_deny_event(const struct file *file, __u32 mask) {
    struct deny_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    e->ts    = bpf_ktime_get_ns();
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->cgid  = bpf_get_current_cgroup_id();
    e->mntns = get_current_mntns_inum();
    e->mask  = mask;
    get_fs_name(file, e->fsname, sizeof(e->fsname));
    get_dentry_name(file, e->dname, sizeof(e->dname));
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask) {
    __u32 k = 0;
    struct guard_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &k);
    __u64 mntns = get_current_mntns_inum();
    if (!cfg) return 0;
    if (mntns == cfg->host_mntns) return 0;

    char fs[16] = {};
    char name[64] = {};
    get_fs_name(file, fs, sizeof(fs));
    get_dentry_name(file, name, sizeof(name));

    if (starts_with(fs, "proc") && starts_with(name, "kcore")) {
        emit_deny_event(file, (__u32)mask);
        return -13; /* -EACCES */
    }
    if ((mask & MAY_WRITE) && starts_with(fs, "proc") && starts_with(name, "setns")) {
        emit_deny_event(file, (__u32)mask);
        return -13;
    }
    if ((mask & MAY_WRITE) && starts_with(fs, "sysfs")) {
        emit_deny_event(file, (__u32)mask);
        return -13;
    }
    if (starts_with(name, "host")) {
        emit_deny_event(file, (__u32)mask);
        return -13;
    }
    return 0;
}
