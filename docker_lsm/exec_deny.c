// SPDX-License-Identifier: GPL-2.0
/*
 * exec_deny.c - 用户态控制与事件消费
 *
 * 用法：
 *   sudo ./exec_deny run
 *   sudo ./exec_deny allow <cgid>
 *   sudo ./exec_deny deny  <cgid>
 *   sudo ./exec_deny show
 *   sudo ./exec_deny get-cgid-of-pid  <pid>
 *   sudo ./exec_deny get-cgid-of-path <cgroup_path|/sys/fs/cgroup/...>
 */

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <limits.h>
#include <libgen.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "exec_deny.skel.h"

static volatile sig_atomic_t exiting = 0;

static void on_sigint(int signo)
{
	(void)signo;
	exiting = 1;
}

/* 与 BPF 侧保持完全一致的事件结构体定义 */
struct exec_event {
	__u64 ts;
	__u32 pid;
	__u32 pad;
	__u64 cgid;
	char  comm[16];
	char  filename[256];
};

static unsigned long long get_host_netns_inode(void)
{
	struct stat st = {0};
	if (stat("/proc/1/ns/net", &st) == 0)
		return (unsigned long long)st.st_ino;
	return 0ull;
}

static int write_host_netns_inode_to_map(struct exec_deny_bpf *skel)
{
	unsigned long long ino = get_host_netns_inode();
	__u32 k0 = 0;
	int mfd = bpf_map__fd(skel->maps.host_netns_ino);
	if (mfd < 0) {
		fprintf(stderr, "host_netns_ino map fd error\n");
		return -1;
	}
	if (!ino) {
		fprintf(stderr, "warn: cannot stat /proc/1/ns/net\n");
		return -1;
	}
	if (bpf_map_update_elem(mfd, &k0, &ino, BPF_ANY) < 0) {
		fprintf(stderr, "set host netns ino=%llu failed: %s\n",
		        ino, strerror(errno));
		return -1;
	}
	printf("[INIT] host netns inode = %llu (宿主机进程将豁免)\n", ino);
	return 0;
}

/* ============ cgroup id 解析工具 ============ */

/* 读取 /proc/<pid>/cgroup，获取 cgroup v2 的相对路径，如：/docker/<id> 或 /kubepods/...  */
static int read_cgroup_relpath_of_pid(pid_t pid, char *buf, size_t buflen)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
	FILE *f = fopen(path, "re");
	if (!f) return -1;

	char line[1024];
	int rc = -1;
	while (fgets(line, sizeof(line), f)) {
		/* cgroup v2 行的格式通常是：0::/.... */
		char *p = strstr(line, "0::/");
		if (!p) continue;
		p += 3; /* 跳过 0:: */
		size_t n = strcspn(p, "\n");
		if (n >= buflen) n = buflen - 1;
		memcpy(buf, p, n);
		buf[n] = '\0';
		rc = 0;
		break;
	}
	fclose(f);
	return rc;
}

/* 根据 cgroup 路径（相对或绝对）拿 inode：
 * - 若传入以 "/sys/fs/cgroup" 开头的绝对路径，直接 stat；
 * - 否则拼接 "/sys/fs/cgroup" + 相对路径；
 * 返回 inode 作为 cgid 的近似（cgroup v2 下与 bpf_get_current_cgroup_id 一致）。
 */
static unsigned long long get_cgid_of_cgroup_path(const char *p)
{
	char full[PATH_MAX];
	struct stat st;
	if (!p || !*p) return 0;

	if (strncmp(p, "/sys/fs/cgroup", 14) == 0) {
		snprintf(full, sizeof(full), "%s", p);
	} else {
		snprintf(full, sizeof(full), "/sys/fs/cgroup%s", p[0] == '/' ? p : "");
		if (p[0] != '/')
			strncat(full, p, sizeof(full) - strlen(full) - 1);
	}

	if (stat(full, &st) == 0)
		return (unsigned long long)st.st_ino;

	return 0ull;
}

static unsigned long long get_cgid_of_pid(pid_t pid)
{
	char rel[PATH_MAX];
	if (read_cgroup_relpath_of_pid(pid, rel, sizeof(rel)) < 0)
		return 0ull;
	return get_cgid_of_cgroup_path(rel);
}

/* ============ ringbuf 事件处理 ============ */

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	const struct exec_event *e = (const struct exec_event *)data;
	printf("[DENY] ts=%llu pid=%u cgid=%llu comm=%s filename=%s\n",
	       (unsigned long long)e->ts,
	       e->pid,
	       (unsigned long long)e->cgid,
	       e->comm,
	       e->filename);
	fflush(stdout);
	return 0;
}

/* 若需要可接入丢失回调；当前未使用 */
// static int handle_lost(void *ctx, size_t n)
// {
// 	(void)ctx;
// 	fprintf(stderr, "lost %zu events\n", n);
// 	return 0;
// }

/* ============ 允许/拒绝/展示 白名单 ============ */

static int map_allow_update(struct exec_deny_bpf *skel, unsigned long long cgid, __u8 allow)
{
	int mfd = bpf_map__fd(skel->maps.exec_allow_by_cgrp);
	if (mfd < 0) return -1;
	if (allow) {
		if (bpf_map_update_elem(mfd, &cgid, &allow, BPF_ANY) < 0) {
			perror("bpf_map_update_elem");
			return -1;
		}
		printf("[ALLOW] cgid=%llu\n", cgid);
	} else {
		if (bpf_map_delete_elem(mfd, &cgid) < 0) {
			perror("bpf_map_delete_elem");
			return -1;
		}
		printf("[DENY ] cgid=%llu (removed from whitelist)\n", cgid);
	}
	return 0;
}

static int map_allow_show(struct exec_deny_bpf *skel)
{
	int mfd = bpf_map__fd(skel->maps.exec_allow_by_cgrp);
	if (mfd < 0) return -1;

	__u64 key = 0, next_key = 0;
	__u8 val = 0;
	printf("=== whitelist (by cgroup id) ===\n");
	int cnt = 0;
	if (bpf_map_get_next_key(mfd, NULL, &key) == 0) {
		do {
			if (bpf_map_lookup_elem(mfd, &key, &val) == 0 && val == 1) {
				printf("  cgid=%llu allow=1\n", (unsigned long long)key);
				cnt++;
			}
		} while (bpf_map_get_next_key(mfd, &key, &next_key) == 0 && (key = next_key, 1));
	}
	if (!cnt) printf("  (empty)\n");
	return 0;
}

/* ============ run 模式：attach + 消费事件 ============ */

static int cmd_run(void)
{
	struct exec_deny_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 静音（可按需自定义回调）；错误时仍会返回错误码 */
	libbpf_set_print(NULL);

	skel = exec_deny_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed\n");
		return 1;
	}
	/* 写入宿主机 netns inode，确保豁免规则生效 */
	write_host_netns_inode_to_map(skel);

	err = exec_deny_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	printf("LSM attached. Default policy = DENY-ALL (containers unless CGID allowed).\n");
	printf("Press Ctrl+C to quit...\n");

	while (!exiting) {
		int r = ring_buffer__poll(rb, 200 /* ms */);
		if (r < 0 && errno != EINTR) {
			fprintf(stderr, "ring_buffer__poll: %d\n", r);
			break;
		}
		/* 心跳点（如需）：
		fprintf(stderr, ".");
		*/
	}

cleanup:
	ring_buffer__free(rb);
	exec_deny_bpf__destroy(skel);
	return err < 0 ? -err : err;
}

/* ============ 命令入口 ============ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s run\n"
		"  %s allow <cgid>\n"
		"  %s deny  <cgid>\n"
		"  %s show\n"
		"  %s get-cgid-of-pid  <pid>\n"
		"  %s get-cgid-of-path <cgroup_path|/sys/fs/cgroup/...>\n",
		prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	const char *cmd = argv[1];

	if (strcmp(cmd, "run") == 0) {
		return cmd_run();
	}

	/* 其余子命令需要 skeleton 打开（以便拿到 map fd） */
	struct exec_deny_bpf *skel = exec_deny_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed\n");
		return 1;
	}
	/* 同样写入 host netns inode，保证一致配置 */
	write_host_netns_inode_to_map(skel);

	int ret = 0;

	if (strcmp(cmd, "allow") == 0) {
		if (argc < 3) { usage(argv[0]); ret = 1; goto out; }
		unsigned long long cgid = strtoull(argv[2], NULL, 0);
		ret = map_allow_update(skel, cgid, 1);
		goto out;
	}

	if (strcmp(cmd, "deny") == 0) {
		if (argc < 3) { usage(argv[0]); ret = 1; goto out; }
		unsigned long long cgid = strtoull(argv[2], NULL, 0);
		ret = map_allow_update(skel, cgid, 0);
		goto out;
	}

	if (strcmp(cmd, "show") == 0) {
		ret = map_allow_show(skel);
		goto out;
	}

	if (strcmp(cmd, "get-cgid-of-pid") == 0) {
		if (argc < 3) { usage(argv[0]); ret = 1; goto out; }
		pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
		unsigned long long cgid = get_cgid_of_pid(pid);
		if (!cgid) {
			fprintf(stderr, "failed to get cgid of pid %d\n", pid);
			ret = 1;
		} else {
			printf("%llu\n", cgid);
		}
		goto out;
	}

	if (strcmp(cmd, "get-cgid-of-path") == 0) {
		if (argc < 3) { usage(argv[0]); ret = 1; goto out; }
		unsigned long long cgid = get_cgid_of_cgroup_path(argv[2]);
		if (!cgid) {
			fprintf(stderr, "failed to get cgid of path: %s\n", argv[2]);
			ret = 1;
		} else {
			printf("%llu\n", cgid);
		}
		goto out;
	}

	usage(argv[0]);
	ret = 1;

out:
	exec_deny_bpf__destroy(skel);
	return ret;
}
