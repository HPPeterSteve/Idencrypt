/*
 * vault_ffi.c
 *
 * FFI wrappers for Rust ↔ C integration.
 * Exposes all vault functions with _ffi suffix for the Rust side.
 *
 * This file links against:
 *   vault_crypto.c, vault_catalog.c, vault_monitor.c, vault_sandbox.c
 *
 * All functions are non-static (public) so Rust can call them via FFI.
 *
 * Author: Peter Steve (architecture)
 * Rewritten: 2026-05-13
 */

#include "vault_core.h"

#ifdef __linux__
#include <dirent.h>
#include <pthread.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  INIT / SHUTDOWN — called by Rust on startup and exit
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * vault_ffi_init():
 *   - Creates catalog directory if needed
 *   - Initializes logging
 *   - Initializes OpenSSL
 *   - Loads catalog from disk
 *   - Initializes monitor context (fanotify on Linux, requires CAP_SYS_ADMIN/root)
 *   - Starts monitor thread (Linux only)
 *
 * Must be called ONCE before any other vault_*_ffi function.
 * Returns 0 on success, negative VaultError on failure.
 */

#ifdef __linux__
static pthread_t g_monitor_tid;
static bool      g_monitor_started = false;
#endif

int vault_ffi_init(void) {
    /* Create catalog directory */
    struct stat st;
    if (stat(VAULT_CATALOG_PATH, &st) != 0) {
        if (mkdir(VAULT_CATALOG_PATH, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "Cannot create catalog dir %s: %s\n",
                    VAULT_CATALOG_PATH, strerror(errno));
            return (int)ERR_IO;
        }
    }

    log_init();
    vault_log(LOG_INFO, "=== Vault Security System starting (FFI) ===");

    /* OpenSSL init */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load catalog from disk */
    VaultError err = catalog_load();
    if (err != ERR_OK) {
        vault_log(LOG_ERROR, "catalog_load failed: %s", vault_strerror(err));
        return (int)err;
    }

#ifdef __linux__
    /* Init monitor context */
    g_monitor.catalog     = &g_catalog;
    g_monitor.running     = true;
    g_monitor.fanotify_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);

    if (g_monitor.fanotify_fd < 0) {
        vault_log(LOG_WARN, "fanotify_init: %s (monitor disabled - run with CAP_SYS_ADMIN/root to enable)", strerror(errno));
        /* Non-fatal: continue without active blocking monitor */
    }

    if (pthread_mutex_init(&g_monitor.lock, NULL) != 0) {
        vault_log(LOG_ERROR, "pthread_mutex_init failed");
        return (int)ERR_SYSTEM;
    }

    /* Start monitor thread */
    if (g_monitor.fanotify_fd >= 0) {
        if (pthread_create(&g_monitor_tid, NULL, monitor_thread, &g_monitor) == 0) {
            g_monitor_started = true;
            vault_log(LOG_INFO, "Fanotify monitor thread started");
        } else {
            vault_log(LOG_WARN, "Failed to start monitor thread: %s", strerror(errno));
        }
    }

    /* Always whitelist ourself — IdenVault must be able to access its own files */
    vault_auth_pid_add_ffi(getpid());
    vault_log(LOG_INFO, "Self-whitelisted PID %d", (int)getpid());
#endif

    vault_log(LOG_INFO, "FFI init complete: %u vaults loaded", g_catalog.count);
    return (int)ERR_OK;
}

/*
 * vault_ffi_shutdown():
 *   - Stops monitor thread
 *   - Saves catalog to disk
 *   - Wipes sensitive data from memory
 *   - Cleans up OpenSSL
 *
 * Must be called on graceful exit (Ctrl+C, exit command, etc).
 * Returns 0 on success.
 */
int vault_ffi_shutdown(void) {
    vault_log(LOG_INFO, "=== Vault Security System shutting down (FFI) ===");

#ifdef __linux__
    g_monitor.running = false;
    g_running = false;

    if (g_monitor_started) {
        pthread_join(g_monitor_tid, NULL);
        g_monitor_started = false;
    }

    pthread_mutex_destroy(&g_monitor.lock);

    if (g_monitor.fanotify_fd >= 0) {
        close(g_monitor.fanotify_fd);
        g_monitor.fanotify_fd = -1;
    }
#endif

    /* Save catalog before exit */
    catalog_save();

    /* Wipe sensitive data from memory */
    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        explicit_bzero(v->salt, SALT_LEN);
        explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
        hashmap_clear(&v->hashmap);
    }
    explicit_bzero(&g_catalog, sizeof(g_catalog));

    EVP_cleanup();
    ERR_free_strings();

    if (g_logfp) {
        vault_log(LOG_INFO, "=== Vault Security System stopped ===");
        fclose(g_logfp);
        g_logfp = NULL;
    }

    return (int)ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  VAULT LIFECYCLE — FFI wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_create_ffi(
    const char *name,
    int         vault_type,
    const char *path,
    const char *password
) {
    VaultType vt = (vault_type == 1) ? VAULT_TYPE_PROTECTED : VAULT_TYPE_NORMAL;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultError err = vault_create(name, vt, path, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    return (int)err;
}

int vault_delete_ffi(uint32_t id, const char *password) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultError err = vault_delete(id, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_rename_ffi(uint32_t id, const char *new_name, const char *password) {
    if (!new_name || new_name[0] == '\0') return (int)ERR_INVALID_ARGS;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultError err = vault_rename(id, new_name, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_unlock_ffi(uint32_t id, const char *password) {
    if (!password || password[0] == '\0') return (int)ERR_PASS_REQUIRED;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultError err = vault_unlock(id, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass) {
    if (!old_pass || !new_pass) return (int)ERR_INVALID_ARGS;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultError err = vault_change_password(id, old_pass, new_pass);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CRYPTOGRAPHY — FFI wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_encrypt_ffi(uint32_t id, const char *password) {
    if (!password || password[0] == '\0') return (int)ERR_PASS_REQUIRED;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    if (!v->has_pass) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_PASS_REQUIRED;
    }

    VaultError auth_err = auth_verify_password(v, password);
    if (auth_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)auth_err;
    }

    uint8_t key[KEY_LEN];
    VaultError key_err = derive_key(password, v->salt, key);
    if (key_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)key_err;
    }

    vault_set_write_mode(v, true); // ALLOW WRITE
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) {
        explicit_bzero(key, KEY_LEN);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_IO;
    }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 10];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        size_t nlen = strlen(de->d_name);
        if (nlen > 4 && strcmp(de->d_name + nlen - 4, ".enc") == 0) continue;

        snprintf(inpath,  sizeof(inpath),  "%s/%s",     v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%s.enc", v->path, de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (encrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath);
            count++;
            vault_log(LOG_AUDIT, "[FFI] vault_encrypt_ffi: encrypted '%s'", de->d_name);
        } else {
            vault_log(LOG_ERROR, "[FFI] vault_encrypt_ffi: FAILED '%s'", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);

    vault_log(LOG_AUDIT, "[FFI] vault_encrypt_ffi: vault='%s' encrypted %d files", v->name, count);
    vault_set_write_mode(v, false); // RESTORE READ-ONLY
    pthread_mutex_unlock(&g_monitor.lock);
#else
    explicit_bzero(key, KEY_LEN);
    vault_log(LOG_WARN, "[FFI] vault_encrypt_ffi: file encryption not yet on Windows");
#endif

    return (int)ERR_OK;
}

int vault_decrypt_ffi(uint32_t id, const char *password) {
    if (!password || password[0] == '\0') return (int)ERR_PASS_REQUIRED;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    if (!v->has_pass) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_PASS_REQUIRED;
    }

    VaultError auth_err = auth_verify_password(v, password);
    if (auth_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)auth_err;
    }

    uint8_t key[KEY_LEN];
    VaultError key_err = derive_key(password, v->salt, key);
    if (key_err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)key_err;
    }

    vault_set_write_mode(v, true); // ALLOW WRITE
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) {
        explicit_bzero(key, KEY_LEN);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_IO;
    }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL) {
        size_t nlen = strlen(de->d_name);
        if (nlen <= 4 || strcmp(de->d_name + nlen - 4, ".enc") != 0) continue;

        snprintf(inpath,  sizeof(inpath),  "%s/%s",      v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%.*s",    v->path,
                 (int)(nlen - 4), de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (decrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath);
            count++;
            vault_log(LOG_AUDIT, "[FFI] vault_decrypt_ffi: decrypted '%s'", outpath);
        } else {
            vault_log(LOG_ERROR, "[FFI] vault_decrypt_ffi: FAILED '%s'", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);

    vault_log(LOG_AUDIT, "[FFI] vault_decrypt_ffi: vault='%s' decrypted %d files", v->name, count);
    vault_set_write_mode(v, false); // RESTORE READ-ONLY
    pthread_mutex_unlock(&g_monitor.lock);
#else
    explicit_bzero(key, KEY_LEN);
    vault_log(LOG_WARN, "[FFI] vault_decrypt_ffi: file decryption not yet on Windows");
#endif

    return (int)ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTEGRITY / MONITOR — FFI wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_scan_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    monitor_scan_vault(v);
    catalog_save();
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

int vault_scan_report_ffi(uint32_t id, char *out, size_t out_len) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    if (!out || out_len == 0) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_INVALID_ARGS;
    }

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    /* perform scan and persist catalog */
    monitor_scan_vault(v);
    catalog_save();

    int issues = 0;
    size_t pos = 0;
    /* iterate hashmap and collect modified entries */
    for (int b = 0; b < HASHMAP_BUCKETS; b++) {
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next) {
            if (e->modified) {
                issues++;
                if (pos < out_len - 1) {
                    int wrote = snprintf(out + pos, out_len - pos, "%s\n", e->filename);
                    if (wrote > 0) pos += (size_t)wrote;
                    if (pos >= out_len - 1) { pos = out_len - 1; out[pos] = '\0'; break; }
                }
            }
        }
        if (pos >= out_len - 1) break;
    }

    if (issues == 0) {
        snprintf(out, out_len, "No issues found\n");
    }

    vault_log(LOG_INFO, "[FFI] vault_scan_report: id=%u issues=%d", v->id, issues);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return issues;
}

int vault_resolve_ffi(uint32_t id, const char *password) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    VaultError err = alert_resolve(id, password);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DISPLAY — FFI wrappers (print to stdout from C)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* cmd_list, cmd_info, cmd_files — inline display functions */

static void ffi_cmd_list(void) {
    printf("\n  ┌────────────────────────────────────────────────────────────────┐\n");
    printf("  │  CATALOG: %-20s  (%u vaults)              │\n",
           g_catalog.category, g_catalog.count);
    printf("  ├──────┬──────────────────────────┬────────────┬────────────┬────┤\n");
    printf("  │  ID  │  Name                    │  Type      │  Status    │  P │\n");
    printf("  ├──────┼──────────────────────────┼────────────┼────────────┼────┤\n");

    if (g_catalog.count == 0)
        printf("  │  (no vaults)                                                  │\n");

    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        const char *status_s;
        switch (v->status) {
            case VAULT_STATUS_OK:      status_s = "OK      "; break;
            case VAULT_STATUS_LOCKED:  status_s = "LOCKED  "; break;
            case VAULT_STATUS_ALERT:   status_s = "ALERT   "; break;
            case VAULT_STATUS_DELETED: status_s = "DELETED "; break;
            default:                   status_s = "?       ";
        }
        printf("  │ %4u │ %-24s │ %-10s │ %-10s │ %s  │\n",
               v->id,
               v->name,
               v->type == VAULT_TYPE_PROTECTED ? "PROTECTED " : "NORMAL    ",
               status_s,
               v->has_pass ? "Y" : " ");
    }
    printf("  └──────┴──────────────────────────┴────────────┴────────────┴────┘\n\n");
}

static void ffi_cmd_info(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    char tbuf[32];
    struct tm *tm;

    printf("\n  -- Vault Info --------------------------------------------------\n");
    printf("  ID           : %u\n", v->id);
    printf("  Name         : %s\n", v->name);
    printf("  Type         : %s\n", v->type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL");
    printf("  Status       : ");
    switch (v->status) {
        case VAULT_STATUS_OK:      printf("OK\n");      break;
        case VAULT_STATUS_LOCKED:  printf("LOCKED\n");  break;
        case VAULT_STATUS_ALERT:   printf("ALERT\n");   break;
        case VAULT_STATUS_DELETED: printf("DELETED\n"); break;
    }
    printf("  Password     : %s\n", v->has_pass ? "Yes" : "No");
    printf("  Path         : %s\n", v->path);

    tm = localtime(&v->created_at);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("  Created      : %s\n", tbuf);

    tm = localtime(&v->last_check);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("  Last check   : %s\n", tbuf);

    printf("  Files tracked: %zu\n", v->hashmap.count);
    printf("  Fail attempts: %d\n", v->failed_attempts);

    if (v->status == VAULT_STATUS_ALERT) {
        printf("  Alert reason : %s\n", v->alert.reason);
        printf("  Alert count  : %zu\n", v->alert.alert_count);
    }
    printf("  ------------------------------------------------------------------\n\n");
}

static void ffi_cmd_files(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    printf("\n  Files in vault '%s':\n", v->name);
    printf("  %-40s  %-16s  %s\n", "Filename", "Last seen", "Modified");
    printf("  %s\n", "-------------------------------------------------------------");

    bool any = false;
    for (int b = 0; b < HASHMAP_BUCKETS; b++) {
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next) {
            char tbuf[32];
            struct tm *tm = localtime(&e->last_seen);
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", tm);
            printf("  %-40s  %-16s  %s\n",
                   e->filename, tbuf,
                   e->modified ? "YES !" : "no");
            any = true;
        }
    }
    if (!any) printf("  (no files tracked)\n");
    printf("\n");
}

void vault_info_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    ffi_cmd_info(id);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
}

void vault_list_ffi(void) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    ffi_cmd_list();
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
}

void vault_files_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    ffi_cmd_files(id);
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SANDBOX — FFI wrapper
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_sandbox_ffi(uint32_t id, const char *password) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    /* Unlock mutex BEFORE fork/execl — child would inherit the lock */
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    return (int)vault_sandbox_open(v, password);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  RULE ENGINE — FFI wrapper
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES) return (int)ERR_SYSTEM;
    rule_add(vault_id, max_fails, hour_from, hour_to);
    return (int)ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATUS — FFI wrapper
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_get_status_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }
    int status = (int)v->status;
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return status;
}

/* 
 * vault_export_file_ffi():
 *   Copies a file from the vault to an external destination.
 *   Uses Rust's rust_vault_copy_file (safe_copy) for the operation.
 */
int vault_export_file_ffi(uint32_t id, const char *filename, const char *dst_path) {
    if (!filename || !dst_path) return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    /* Build full source path */
    char src_full[VAULT_PATH_MAX + NAME_MAX + 2];
    snprintf(src_full, sizeof(src_full), "%s/%s", v->path, filename);

    /* Call back into Rust to perform the copy */
    int ret = rust_vault_copy_file(src_full, dst_path);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    if (ret == 0) {
        vault_log(LOG_AUDIT, "Vault EXPORT: id=%u file='%s' -> '%s'", id, filename, dst_path);
    }

    return ret;
}

int vault_export_and_decrypt_file_ffi(uint32_t id, const char *filename, const char *dst_path, const char *password) {
    if (!filename || !dst_path || !password) return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    VaultError err = auth_verify_password(v, password);
    if (err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)err;
    }

    uint8_t key[KEY_LEN];
    err = derive_key(password, v->salt, key);
    if (err != ERR_OK) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)err;
    }

    char src_full[VAULT_PATH_MAX + NAME_MAX + 2];
    snprintf(src_full, sizeof(src_full), "%s/%s", v->path, filename);

    err = decrypt_file(src_full, dst_path, key);
    explicit_bzero(key, KEY_LEN);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif

    if (err == ERR_OK) {
        vault_log(LOG_AUDIT, "Vault EXPORT DECRYPTED: id=%u file='%s' -> '%s'", id, filename, dst_path);
    } else {
        vault_log(LOG_ERROR, "Failed to decrypt during export: id=%u file='%s'", id, filename);
    }

    return (int)err;
}

int vault_get_real_path_ffi(uint32_t id, char *out_path, size_t out_len) {
    if (!out_path || out_len == 0) return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (!v) {
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return (int)ERR_VAULT_NOT_FOUND;
    }

    char engine_path[VAULT_PATH_MAX + 32];
    snprintf(engine_path, sizeof(engine_path), "%s/.engine_real", v->path);

    /* Check if .engine_real exists */
    struct stat st;
    if (stat(engine_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        strncpy(out_path, engine_path, out_len - 1);
    } else {
        strncpy(out_path, v->path, out_len - 1);
    }
    out_path[out_len - 1] = '\0';

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

int vault_is_protected_ffi(uint32_t id) {
    int ret = 0;
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif
    Vault *v = vault_find_by_id(id);
    if (v && v->type == VAULT_TYPE_PROTECTED) {
        ret = 1;
    }
#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENGINE DE ISOLAMENTO — FFI wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_apply_engine_ffi(const char *name, int engine_level) {
    if (!name || name[0] == '\0') {
        vault_log(LOG_ERROR, "[FFI] vault_apply_engine_ffi: nome NULL/vazio");
        return ERR_INVALID_ARGS;
    }
    if (engine_level < 1 || engine_level > ENGINE_LEVEL_MAX) {
        vault_log(LOG_ERROR, "[FFI] vault_apply_engine_ffi: nivel invalido %d", engine_level);
        return ERR_INVALID_ARGS;
    }

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_name(name);
    if (!v) {
        vault_log(LOG_ERROR, "[FFI] vault_apply_engine_ffi: vault '%s' nao encontrado", name);
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return ERR_VAULT_NOT_FOUND;
    }

    v->engine_level = engine_level;
    VaultError err = engine_apply(v);

    if (err == ERR_OK) {
        VaultError save_err = catalog_save();
        if (save_err != ERR_OK) {
            vault_log(LOG_ERROR, "[FFI] vault_apply_engine_ffi: catalog_save falhou: %d", save_err);
            err = save_err;
        } else {
            vault_log(LOG_AUDIT, "[FFI] Engine %d aplicado e salvo para vault '%s'",
                      engine_level, name);
        }
    }

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

int vault_validate_engine_ffi(uint32_t id) {
#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    Vault *v = vault_find_by_id(id);
    if (!v) {
        vault_log(LOG_ERROR, "[FFI] vault_validate_engine_ffi: vault id=%u nao encontrado", id);
#ifdef __linux__
        pthread_mutex_unlock(&g_monitor.lock);
#endif
        return ERR_VAULT_NOT_FOUND;
    }

    VaultError err = engine_validate(v);

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BULK VAULT LISTING — returns (id, resolved_path) for all active vaults
 * ═══════════════════════════════════════════════════════════════════════════ */

int vault_list_ids_ffi(VaultIdPath *out, uint32_t out_cap, uint32_t *out_count) {
    if (!out || !out_count || out_cap == 0) return (int)ERR_INVALID_ARGS;

#ifdef __linux__
    pthread_mutex_lock(&g_monitor.lock);
#endif

    uint32_t n = 0;
    for (uint32_t i = 0; i < g_catalog.count && n < out_cap; i++) {
        Vault *v = &g_catalog.vaults[i];
        out[n].id = v->id;

        /* Resolve .engine_real path if applicable (same logic as vault_get_real_path_ffi) */
        char engine_path[VAULT_PATH_MAX + 32];
        snprintf(engine_path, sizeof(engine_path), "%s/.engine_real", v->path);
        struct stat st;
        if (stat(engine_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            strncpy(out[n].path, engine_path, VAULT_PATH_MAX - 1);
        } else {
            strncpy(out[n].path, v->path, VAULT_PATH_MAX - 1);
        }
        out[n].path[VAULT_PATH_MAX - 1] = '\0';
        n++;
    }
    *out_count = n;

#ifdef __linux__
    pthread_mutex_unlock(&g_monitor.lock);
#endif
    return (int)ERR_OK;
}

uint32_t vault_count_ffi(void) {
    return g_catalog.count;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  STANDALONE MAIN (only when NOT compiled as FFI library)
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifndef VAULT_FFI_BUILD
int main(void) {
    printf("IdenVault Security Module\n");
    printf("Version: 0.9.0\n");
    printf("Compiled: %s %s\n", __DATE__, __TIME__);
    return 0;
}
#endif
