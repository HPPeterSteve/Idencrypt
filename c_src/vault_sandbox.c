/*
 * vault_sandbox.c
 *
 * VAULT SECURITY SYSTEM — IdenVault Hardened Sandbox v2
 * Section 12 from legacy monolith
 *
 * Linux-only: 5-layer defense-in-depth sandbox
 *   1. User Namespace  — root in sandbox → nobody on host
 *   2. Mount + PID NS  — private process/fs view
 *   3. Pivot Root      — replaces chroot (more secure)
 *   4. Capability Drop — removes all Linux Caps + NO_NEW_PRIVS
 *   5. Seccomp-BPF     — minimal allowlist, KILL as default
 *
 * On Windows: stub that returns ERR_SYSTEM (sandbox not available).
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */

#include "vault_core.h"

#ifdef __linux__
#include <sys/sysmacros.h>

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_drop_caps(): Remove all Linux Capabilities
 * ───────────────────────────────────────────────────────────────────────── */
static int sandbox_drop_caps(void) {
    cap_t empty = cap_init();
    if (empty == NULL) {
        perror("[SANDBOX] cap_init");
        return -1;
    }

    if (cap_set_proc(empty) != 0) {
        perror("[SANDBOX] cap_set_proc");
        cap_free(empty);
        return -1;
    }
    cap_free(empty);

    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        perror("[SANDBOX] PR_SET_KEEPCAPS");
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("[SANDBOX] PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    /* Verify caps are empty */
    cap_t check = cap_get_proc();
    if (check != NULL) {
        char *text = cap_to_text(check, NULL);
        if (text && strcmp(text, "=") != 0) {
            fprintf(stderr, "[SANDBOX] residual caps after drop: %s\n", text);
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_pivot_root(): Pivot root to vault path
 * ───────────────────────────────────────────────────────────────────────── */
static int sandbox_pivot_root(const char *new_root) {
    if (new_root == NULL || new_root[0] == '\0') {
        fprintf(stderr, "[SANDBOX] pivot_root: new_root empty\n");
        return -1;
    }

    int ret = -1;
    char oldroot[64] = ".sandbox_XXXXXX";

    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) != 0) {
        perror("[SANDBOX] mount MS_BIND");
        return -1;
    }

    if (chdir(new_root) != 0) {
        perror("[SANDBOX] chdir new_root");
        goto cleanup_bind;
    }

    if (mkdtemp(oldroot) == NULL) {
        perror("[SANDBOX] mkdtemp oldroot");
        goto cleanup_bind;
    }

    struct stat st;
    if (lstat(oldroot, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[SANDBOX] oldroot is not a real directory\n");
        rmdir(oldroot);
        goto cleanup_bind;
    }

    if (syscall(SYS_pivot_root, ".", oldroot) != 0) {
        perror("[SANDBOX] pivot_root");
        rmdir(oldroot);
        goto cleanup_bind;
    }

    char oldroot_abs[80];
    snprintf(oldroot_abs, sizeof(oldroot_abs), "/%s", oldroot);

    umount2(oldroot_abs, MNT_DETACH);
    rmdir(oldroot_abs);

    if (chdir("/") != 0) {
        perror("[SANDBOX] chdir / after pivot_root");
        goto cleanup_bind;
    }

    ret = 0;
    goto done;

cleanup_bind:
    umount2(new_root, MNT_DETACH);

done:
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_prepare_mounts(): Minimal filesystem mounts
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_prepare_mounts(void) {
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("sandbox: MS_PRIVATE / (non-fatal)");

    if (mkdir("/proc", 0555) != 0 && errno != EEXIST)
        perror("sandbox: mkdir /proc (non-fatal)");

    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0)
        perror("sandbox: mount /proc (non-fatal)");

    if (mkdir("/tmp", 01777) != 0 && errno != EEXIST)
        perror("sandbox: mkdir /tmp (non-fatal)");

    if (mount("tmpfs", "/tmp", "tmpfs",
              MS_NOSUID | MS_NODEV,
              SANDBOX_TMP_SIZE) != 0)
        perror("sandbox: mount /tmp (non-fatal)");
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_limit_resources(): rlimits to prevent DoS
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_limit_resources(void) {
    struct rlimit rl;

    rl.rlim_cur = rl.rlim_max = 32;
    setrlimit(RLIMIT_NPROC, &rl);

    rl.rlim_cur = rl.rlim_max = 128 * 1024 * 1024;
    setrlimit(RLIMIT_AS, &rl);

    rl.rlim_cur = rl.rlim_max = 32 * 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rl);

    rl.rlim_cur = rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  apply_seccomp_policy(): Seccomp-BPF allowlist
 * ───────────────────────────────────────────────────────────────────────── */
static int apply_seccomp_policy(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) { perror("[SANDBOX] seccomp_init"); return -1; }

    /* I/O */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);

    /* Files */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

    /* Directories */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);

    /* Memory */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    /* Processes */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);

    /* Signals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0);

    /* Identity */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0);

    /* Sync */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

    /* Libc init */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);

    /* Time */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);

    /* Explicit blocks */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(chroot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setns), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(capset), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);

    int ret = seccomp_load(ctx);
    if (ret != 0) perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_write_uid_gid_map(): Write UID/GID maps for user namespace
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_write_uid_gid_map(pid_t child_pid) {
    char path[256];
    char map[64];
    int  fd;

    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)child_pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny", 4);
        close(fd);
    }

    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    snprintf(map,  sizeof(map),  "0 %d 1\n", SANDBOX_NOBODY_UID);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, map, strlen(map));
        close(fd);
    }

    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)child_pid);
    snprintf(map,  sizeof(map),  "0 %d 1\n", SANDBOX_NOBODY_GID);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, map, strlen(map));
        close(fd);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_prepare_jail(): Prepare jail structure inside vault path
 * ───────────────────────────────────────────────────────────────────────── */
static void vault_prepare_jail(const char *vault_path) {
    char marker[VAULT_PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/%s", vault_path, SANDBOX_JAIL_MARKER);

    struct stat st;
    if (stat(marker, &st) == 0) return;

    vault_log(LOG_INFO, "[SANDBOX] Preparing jail at '%s'", vault_path);

    char dir[VAULT_PATH_MAX];
    const char *subdirs[] = { "proc", "tmp", "dev", "bin", "lib", "lib64", NULL };
    for (int i = 0; subdirs[i]; i++) {
        snprintf(dir, sizeof(dir), "%s/%s", vault_path, subdirs[i]);
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            vault_log(LOG_WARN, "[SANDBOX] mkdir %s: %s", dir, strerror(errno));
    }

    if (geteuid() == 0) {
        char dev_null[VAULT_PATH_MAX], dev_zero[VAULT_PATH_MAX];
        snprintf(dev_null, sizeof(dev_null), "%s/dev/null", vault_path);
        snprintf(dev_zero, sizeof(dev_zero), "%s/dev/zero", vault_path);
        if (stat(dev_null, &st) != 0)
            mknod(dev_null, S_IFCHR | 0666, makedev(1, 3));
        if (stat(dev_zero, &st) != 0)
            mknod(dev_zero, S_IFCHR | 0666, makedev(1, 5));
    }

    int fd = open(marker, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0400);
    if (fd >= 0) {
        write(fd, "IdenVault Jail v2\n", 18);
        close(fd);
    } else {
        if (errno == ELOOP) {
            vault_log(LOG_ALERT, "[SANDBOX] Detected symlink on jail marker '%s' (ELOOP)", marker);
        } else {
            vault_log(LOG_WARN, "[SANDBOX] open(marker '%s'): %s", marker, strerror(errno));
        }
    }

    vault_log(LOG_AUDIT, "[SANDBOX] Jail prepared at '%s'", vault_path);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_sandbox_open() — IdenVault Hardened Sandbox v2
 * ───────────────────────────────────────────────────────────────────────── */
VaultError vault_sandbox_open(Vault *v, const char *password) {
    if (!v) return ERR_INVALID_ARGS;

    /* Authentication */
    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    if (v->path[0] == '\0') {
        vault_log(LOG_ERROR, "[SANDBOX] vault path empty");
        return ERR_PATH_INVALID;
    }

    vault_log(LOG_AUDIT, "[SANDBOX] Starting IdenVault Hardened Sandbox v2 "
              "for vault '%s' (id=%u)", v->name, v->id);

    vault_prepare_jail(v->path);

    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        vault_log(LOG_ERROR, "[SANDBOX] pipe failed: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        vault_log(LOG_ERROR, "[SANDBOX] fork failed: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    /* PARENT */
    if (pid > 0) {
        vault_auth_pid_add_ffi(pid);

        close(sync_pipe[0]);
        sandbox_write_uid_gid_map(pid);
        close(sync_pipe[1]);

        int status;
        waitpid(pid, &status, 0);

        vault_auth_pid_remove_ffi(pid);

        if (WIFSIGNALED(status)) {
            vault_log(LOG_ALERT,
                "[SANDBOX] Session of '%s' terminated by signal %d "
                "(possible seccomp violation)",
                v->name, WTERMSIG(status));
        } else {
            vault_log(LOG_AUDIT,
                "[SANDBOX] Session of '%s' ended (exit %d)",
                v->name, WEXITSTATUS(status));
        }

        return ERR_OK;
    }

    /* CHILD — SANDBOX */

    /* [Layer 1] User Namespace */
    if (unshare(CLONE_NEWUSER) != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWUSER): %s\n", strerror(errno));
        _exit(1);
    }

    /* Wait for parent to write uid_map/gid_map */
    {
        char c;
        close(sync_pipe[1]);
        read(sync_pipe[0], &c, 1);
        close(sync_pipe[0]);
    }

    /* [Layer 2] Mount + PID Namespace */
    if (unshare(CLONE_NEWNS | CLONE_NEWPID) != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWNS|CLONE_NEWPID): %s\n",
                strerror(errno));
        _exit(1);
    }

    pid_t ns_pid = fork();
    if (ns_pid < 0) {
        fprintf(stderr, "[SANDBOX][FATAL] fork PID NS: %s\n", strerror(errno));
        _exit(1);
    }
    if (ns_pid > 0) {
        int st;
        waitpid(ns_pid, &st, 0);
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    /* [Layer 3] Pivot Root */
    if (sandbox_pivot_root(v->path) != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] pivot_root failed\n");
        _exit(1);
    }

    sandbox_prepare_mounts();

    /* [Layer 4] Drop capabilities */
    if (sandbox_drop_caps() != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] cap drop failed\n");
        _exit(1);
    }

    sandbox_limit_resources();

    /* [Layer 5] Seccomp-BPF — LAST STEP */
    if (apply_seccomp_policy() != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] seccomp policy failed\n");
        _exit(1);
    }

    printf("\n");
    printf("  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │     IDENVAULT HARDENED SANDBOX v2                      │\n");
    printf("  │     Vault : %-43s│\n", v->name);
    printf("  │     Isolation: UserNS + PivotRoot + Caps + Seccomp-BPF │\n");
    printf("  │     Mode: Least Privilege · Deny by Default            │\n");
    printf("  │     Type 'exit' to end session.                        │\n");
    printf("  └─────────────────────────────────────────────────────────┘\n\n");

    execl("/bin/sh", "sh", "-i", NULL);

    fprintf(stderr,
        "[SANDBOX][FATAL] execl(/bin/sh) failed: %s\n"
        "  Hint: place a static /bin/sh (busybox) inside the vault.\n",
        strerror(errno));
    _exit(127);
}

#else /* _WIN32 */

/*
 * Windows stub: sandbox not available.
 * The Windows sandbox (AppContainer) is handled in Rust via vault.rs.
 */
VaultError vault_sandbox_open(Vault *v, const char *password) {
    (void)v;
    (void)password;
    vault_log(LOG_ERROR, "[SANDBOX] Not available on Windows — use Rust AppContainer");
    return ERR_SYSTEM;
}

#endif /* __linux__ */
