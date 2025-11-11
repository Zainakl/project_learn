// 用户态：装载、下发 host mntns、读 ringbuf
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsm_container_guard.skel.h"

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig){ (void)sig; exiting = 1; }

struct guard_cfg { uint64_t host_mntns; uint64_t host_cgid; };
struct deny_event {
    uint64_t ts,pid,cgid,mntns; uint32_t mask;
    char fsname[16]; char dname[64];
};

static unsigned long long get_self_mntns_inum(void){
    struct stat st;
    if (stat("/proc/self/ns/mnt", &st) == 0) return (unsigned long long)st.st_ino;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t size){
    (void)ctx; (void)size;
    const struct deny_event *e = data;
    printf("[DENY] pid=%llu cgid=%llu mntns=%llu mask=0x%x fs=%s name=%s\n",
           (unsigned long long)e->pid,
           (unsigned long long)e->cgid,
           (unsigned long long)e->mntns,
           e->mask, e->fsname, e->dname);
    return 0;
}

int main(void){
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT,on_sigint); signal(SIGTERM,on_sigint);

    struct lsm_container_guard_bpf *skel = lsm_container_guard_bpf__open();
    if (!skel){ fprintf(stderr,"open skel failed\n"); return 1; }
    int err = lsm_container_guard_bpf__load(skel);
    if (err){ fprintf(stderr,"load skel failed: %d\n", err); goto out; }

    struct guard_cfg cfg = { .host_mntns = get_self_mntns_inum(), .host_cgid = 0 };
    __u32 k = 0;
    int cfg_fd = bpf_map__fd(skel->maps.cfg_map);
    if (cfg_fd < 0){ fprintf(stderr,"cfg_map fd fail\n"); err = 1; goto out; }
    if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) != 0){
        fprintf(stderr,"set cfg_map failed\n"); err = 1; goto out;
    }

    if ((err = lsm_container_guard_bpf__attach(skel)) != 0){
        fprintf(stderr,"attach failed: %d\n", err); goto out;
    }

    int rbfd = bpf_map__fd(skel->maps.events);
    struct ring_buffer *rb = NULL;
    if (rbfd >= 0) rb = ring_buffer__new(rbfd, handle_event, NULL, NULL);

    printf("LSM attached. Host mntns=%llu\n", (unsigned long long)cfg.host_mntns);
    printf("Enforcing container-only rules. Ctrl+C 退出...\n");

    while (!exiting){
        if (rb) ring_buffer__poll(rb, 200);
        else usleep(200*1000);
    }
    if (rb) ring_buffer__free(rb);
    err = 0;
out:
    lsm_container_guard_bpf__destroy(skel);
    return err;
}
