// SPDX-License-Identifier: GPL-2.0
/*
 * exec_deny.bpf.c
 *
 * 目标：
 *  - 宿主机（与 /proc/1/ns/net 同一 netns）一律放行；
 *  - 容器默认拦截（-EPERM），cgroup 白名单允许执行；
 *  - ringbuf 输出审计事件。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

char LICENSE[] SEC("license") = "GPL";

/* === 事件结构：用于 ringbuf 审计 === */
struct exec_event {
	__u64 ts;
	__u32 pid;
	__u32 pad;
	__u64 cgid;
	char  comm[16];
	char  filename[256];
};

/* === 审计 ringbuf === */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16MB */
} rb SEC(".maps");

/* === cgroup 白名单：key = cgid, val = allow(1)/deny(0) === */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u8);
} exec_allow_by_cgrp SEC(".maps");

/* === 宿主机 netns inode：ARRAY[0] 保存一个 u64 === */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} host_netns_ino SEC(".maps");

/* 读取当前任务所在的 netns inode（与 /proc/1/ns/net 比较即可） */
static __always_inline __u64 get_current_netns_ino(void)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct nsproxy *nsp = BPF_CORE_READ(t, nsproxy);
	if (!nsp)
		return 0;
	struct net *net = BPF_CORE_READ(nsp, net_ns);
	if (!net)
		return 0;
	return BPF_CORE_READ(net, ns.inum);
}

static __always_inline int check_and_maybe_deny(struct linux_binprm *bprm)
{
	/* 第 0 步：宿主机豁免（按 netns inode） */
	__u32 k0 = 0;
	__u64 *host_ino = bpf_map_lookup_elem(&host_netns_ino, &k0);
	__u64 cur_ino   = get_current_netns_ino();

	if (host_ino && cur_ino && *host_ino == cur_ino) {
		/* 宿主机进程直接放行 */
		return 0;
	}

	/* 第 1 步：cgroup 白名单判定 */
	__u64 cgid = bpf_get_current_cgroup_id();
	__u8 *allow = bpf_map_lookup_elem(&exec_allow_by_cgrp, &cgid);
	if (allow && *allow == 1) {
		return 0; /* 白名单放行 */
	}

	/* 第 2 步：审计并拒绝 */
	struct exec_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->ts   = bpf_ktime_get_ns();
		e->pid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
		e->pad  = 0;
		e->cgid = cgid;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));

		const char *fname = BPF_CORE_READ(bprm, filename);
		if (fname) {
			bpf_probe_read_str(e->filename, sizeof(e->filename), fname);
		} else {
			e->filename[0] = '\0';
		}
		bpf_ringbuf_submit(e, 0);
	}

	return -EPERM;
}

/* 兼容两种段名写法（不同内核/clang 组合可能需要其一） */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(on_bprm_check_s, struct linux_binprm *bprm)
{
	return check_and_maybe_deny(bprm);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(on_bprm_check, struct linux_binprm *bprm)
{
	return check_and_maybe_deny(bprm);
}
