// cc ctr_syscalls.c -o ctr_syscalls -I. -lbpf -lelf -lz
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "ctr_syscalls.h"
// 由 bpftool 生成（见 Makefile 步骤）
#include "ctr_syscalls.skel.h"
static int read_cgroup_v2_path_from_proc(pid_t pid, char *out, size_t outsz)
{
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/cgroup", pid);
    FILE *f = fopen(p, "re");
    if (!f) {
        perror("fopen /proc/PID/cgroup");
        return -1;
    }
    // cgroup v2 行形如：0::/kubepods.slice/.../containerid
    char *line = NULL; size_t n = 0;
    int ok = -1;
    while (getline(&line, &n, f) != -1) {
        // 找到 0:: 开头那行
        if (!strncmp(line, "0::", 3)) {
            char *path = line + 3;
            size_t len = strcspn(path, "\n");
            if (len >= outsz) len = outsz - 1;
            memcpy(out, path, len);
            out[len] = '\0';
            ok = 0;
            break;
        }
    }
    free(line);
    fclose(f);
    return ok;
}

static int get_cgroup_id_from_pid(pid_t pid, unsigned long long *out_id)
{
    char rel[PATH_MAX];
    if (read_cgroup_v2_path_from_proc(pid, rel, sizeof(rel)) < 0) {
        fprintf(stderr, "Cannot find cgroup v2 path (is the system on cgroup v2?).\n");
        return -1;
    }
    char abspath[PATH_MAX];
    // cgroup v2 根一般在 /sys/fs/cgroup
    snprintf(abspath, sizeof(abspath), "/sys/fs/cgroup%s", rel);
    struct stat st;
    if (stat(abspath, &st) != 0) {
        perror("stat cgroup path");
        fprintf(stderr, "Tried: %s\n", abspath);
        return -1;
    }
    *out_id = (unsigned long long)st.st_ino;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct syscall_event *e = data;
    printf("%-10d %-10d %-6u %-14lld %-12.3f %-16s cgid=%llu\n",
           e->tgid, e->pid, e->id, (long long)e->ret,
           e->dur_ns ? (e->dur_ns/1000.0) : 0.0, e->comm,
           (unsigned long long)e->cgroup_id);
    return 0;
}

static void handle_lost(void *ctx, int cpu, long long cnt)
{
    fprintf(stderr, "lost %lld events on cpu %d\n", cnt, cpu);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --pid <PID-in-container>\n"
        "  Example: nsenter -t $(pidof nginx) -n ...  (拿到容器里任一进程PID)\n"
        "Print columns: TGID TID SYSCALL RET DUR(us) COMM cgid\n", prog);
}

int main(int argc, char **argv)
{
    pid_t pid = 0;
    if (argc == 3 && !strcmp(argv[1], "--pid")) {
        pid = (pid_t)strtol(argv[2], NULL, 10);
    } else {
        usage(argv[0]);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL);

    unsigned long long cgid = 0;
    if (get_cgroup_id_from_pid(pid, &cgid) != 0) {
        fprintf(stderr, "Failed to resolve cgroup id from pid %d\n", pid);
        return 1;
    }
    printf("Target cgroup id = %llu (from PID %d)\n", cgid, pid);

    struct ctr_syscalls_bpf *skel = ctr_syscalls_bpf__open();
    if (!skel) {
        fprintf(stderr, "open skeleton failed\n");
        return 1;
    }
    skel->rodata->target_cgroup_id = cgid;

    if (ctr_syscalls_bpf__load(skel)) {
        fprintf(stderr, "load bpf failed\n");
        ctr_syscalls_bpf__destroy(skel);
        return 1;
    }
    if (ctr_syscalls_bpf__attach(skel)) {
        fprintf(stderr, "attach failed\n");
        ctr_syscalls_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                              handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        ctr_syscalls_bpf__destroy(skel);
        return 1;
    }

    printf("%-10s %-10s %-6s %-14s %-12s %-16s %s\n",
           "TGID","TID","ID","RET","DUR(us)","COMM","NOTE");

    while (1) {
        int err = ring_buffer__poll(rb, 200 /*ms*/);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    ctr_syscalls_bpf__destroy(skel);
    return 0;
}
