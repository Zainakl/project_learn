// ctr_syscalls.bpf.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ctr_syscalls.h"   // 定义了 struct syscall_event、TASK_COMM_LEN

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --------------------------
// 只读数据：由用户态在 load 前设置
// --------------------------
const volatile __u64 target_cgroup_id = 0;

// --------------------------
// enter 阶段记录：按 TID 记录进入时间与 syscall 号
// --------------------------
struct start_val {
    __u64 ts_ns;
    __u32 id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);           // 增大容量，降低极端丢失概率
    __type(key, __u32);                  // key = TID (低32位)
    __type(value, struct start_val);
} starts SEC(".maps");

// --------------------------
// 事件 ringbuf：注意名字为 rb，和用户态 skel->maps.rb 对齐
// --------------------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// --------------------------
// 仅放行目标容器（cgroup v2）
// --------------------------
static __always_inline bool pass_container_filter(void)
{
    __u64 cur = bpf_get_current_cgroup_id();
    // target_cgroup_id=0 时允许所有（调试方便）；否则严格匹配
    return (target_cgroup_id == 0) || (cur == target_cgroup_id);
}

// --------------------------
// sys_enter：记录 TID 的进入时间与 id，并立即上报 enter 事件
// --------------------------
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!pass_container_filter())
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;         // TID
    __u32 tgid = pid_tgid >> 32;         // TGID
    __u32 id = (__u32)ctx->id;

    struct start_val sv = {
        .ts_ns = ts,
        .id    = id,
    };
    bpf_map_update_elem(&starts, &pid, &sv, BPF_ANY);

    // 上报 enter 事件：ret=-1, dur=0
    struct syscall_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns     = ts;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->tgid      = tgid;
    e->pid       = pid;                  // TID
    e->ret       = -1;                   // 约定：enter 用 -1
    e->id        = id;
    e->dur_ns    = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --------------------------
// sys_exit：计算耗时并上报；未配对则使用 ctx->id（方案A）
// --------------------------
SEC("tracepoint/raw_syscalls/sys_exit")
int tp_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!pass_container_filter())
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;         // TID
    __u32 tgid = pid_tgid >> 32;         // TGID

    __u64 dur = 0;
    __u32 id  = 0;

    // 用 TID 查配对的 enter 记录
    struct start_val *sv = bpf_map_lookup_elem(&starts, &pid);
    if (sv) {
        id  = sv->id;
        if (ts > sv->ts_ns)
            dur = ts - sv->ts_ns;
        bpf_map_delete_elem(&starts, &pid);
    } else {
        // 关键点：未配对时直接用 ctx->id，而不是 -1
        id  = (__u32)ctx->id;
        dur = 0; // 也可视为“未配对”的标记
    }

    struct syscall_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns     = ts;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->tgid      = tgid;
    e->pid       = pid;                  // TID
    e->ret       = ctx->ret;
    e->id        = id;                   // 保证为真实 syscall 号
    e->dur_ns    = dur;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
