/*
 * vault_monitor.c
 *
 * VAULT SECURITY SYSTEM — File Integrity Monitor, Alerts, Rules
 * Sections 8, 9, 10, 11 from legacy monolith
 *
 * Contains:
 *   - File integrity scanning (SHA-256 per-file)
 *   - Alert system with temporal escalation
 *   - Rule engine (max fails, time windows)
 *   - fanotify monitor thread (Linux only) — PID-whitelist + kernel-level blocking
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */
 
#include "vault_core.h"
 
#ifdef __linux__
#include <dirent.h>
#endif
 
/* ─────────────────────────────────────────────────────────────────────────
 *  is_sandbox_internal() — Filter sandbox-internal paths from fanotify event processing
 *  setup itself (vault_prepare_jail + sandbox_pivot_root), preventing
 *  false-positive anti-ransomware alerts on our own internal files.
 *
 *  Files filtered:
 *    .idenvault_jail_ready  — jail marker written by vault_prepare_jail()
 *    .sandbox_*           — mkdtemp temp dir used by sandbox_pivot_root()
 *    proc / tmp / dev / bin / lib / lib64  — jail subdirectories
 * ───────────────────────────────────────────────────────────────────────── */
static inline bool is_sandbox_internal(const char *name) {
    if (!name || name[0] == '\0') return false;
    if (strcmp(name, SANDBOX_JAIL_MARKER) == 0)   return true;  /* .idenvault_jail_ready */
    if (strncmp(name, ".sandbox_", 9)  == 0)       return true;  /* .sandbox_XXXXXX     */
    /* Jail subdirectories created by vault_prepare_jail() */
    if (strcmp(name, "proc")  == 0) return true;
    if (strcmp(name, "tmp")   == 0) return true;
    if (strcmp(name, "dev")   == 0) return true;
    if (strcmp(name, "bin")   == 0) return true;
    if (strcmp(name, "lib")   == 0) return true;
    if (strcmp(name, "lib64") == 0) return true;
    return false;
}



 
/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 8: FILE INTEGRITY MONITOR
 * ═══════════════════════════════════════════════════════════════════════════ */
 
/* Enforces read-only permissions (0400) on all files in the vault */
void vault_enforce_readonly(Vault *v) {
    if (v->status == VAULT_STATUS_DELETED) return;
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) return;
 
    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);
        chmod(filepath, 0400); // Read-only for owner, none for others
    }
    closedir(dir);
    v->write_mode = false;
    vault_log(LOG_INFO, "[PROTECTION] Vault '%s' set to READ-ONLY mode", v->name);
#endif
}
 
/* Enables/Disables write mode (0600) for authorized operations */
void vault_set_write_mode(Vault *v, bool enable) {
    if (v->status == VAULT_STATUS_DELETED) return;
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) return;
 
    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);
        chmod(filepath, enable ? 0600 : 0400);
    }
    closedir(dir);
    v->write_mode = enable;
    vault_log(LOG_INFO, "[PROTECTION] Vault '%s' write_mode: %s", v->name, enable ? "ON" : "OFF");
#endif
}
 
void monitor_scan_vault(Vault *v) {
    if (v->status == VAULT_STATUS_DELETED) return;
 
#ifdef __linux__
    DIR *dir = opendir(v->path);
    if (!dir) {
        vault_log(LOG_ERROR, "Cannot scan vault '%s' at '%s': %s",
                  v->name, v->path, strerror(errno));
        return;
    }
 
    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];
 
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
 
        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);
 
        struct stat st;
        if (stat(filepath, &st) != 0) continue;
        if (!S_ISREG(st.st_mode))     continue;
 
        char new_hash[HASH_HEX_LEN];
        if (sha256_file(filepath, new_hash) != ERR_OK) continue;
 
        FileEntry *e = hashmap_find(&v->hashmap, de->d_name);
 
        if (!e) {
            e = hashmap_insert(&v->hashmap, de->d_name);
            if (e) {
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
                e->last_seen = time(NULL);
                e->modified  = false;
                vault_log(LOG_INFO, "[%s] New file registered: %s", v->name, de->d_name);
            }
        } else {
            if (CRYPTO_memcmp(e->hash, new_hash, HASH_HEX_LEN) != 0) {
                if (!e->modified) {
                    e->modified = true;
                    vault_log(LOG_ALERT, "[%s] File MODIFIED: %s", v->name, de->d_name);
                    char reason[256];
                    snprintf(reason, sizeof(reason), "File modified: %s", de->d_name);
                    alert_trigger(v, reason);
                }
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
            } else {
                e->modified = false;
            }
            e->last_seen = time(NULL);
        }
    }
 
    closedir(dir);
#endif /* __linux__ */
 
    v->last_check = time(NULL);
}
 
/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 9: ALERT SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════ */
 
void alert_trigger(Vault *v, const char *reason) {
    time_t now = time(NULL);
 
    if (v->alert.first_triggered == 0) {
        v->alert.first_triggered = now;
        v->alert.interval_idx    = 0;
    }
 
    strncpy(v->alert.reason, reason, 255);
    v->alert.reason[255] = '\0';
    v->status = VAULT_STATUS_ALERT;
 
    vault_log(LOG_ALERT, "ALERT [vault=%s id=%u]: %s", v->name, v->id, reason);
    catalog_save();
}
 
void alert_check_escalation(Vault *v) {
    if (v->status != VAULT_STATUS_ALERT) return;
 
    time_t now = time(NULL);
 
    if (v->alert.last_alerted == 0) {
        vault_log(LOG_ALERT, "REPEAT ALERT [%s] (count=%zu): %s",
                  v->name, ++v->alert.alert_count, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT *** [%s] %s\n\n", v->name, v->alert.reason);
        v->alert.last_alerted = now;
        return;
    }
 
    long interval = (v->alert.interval_idx < NUM_ALERT_INTERVALS)
                  ? ALERT_INTERVALS[v->alert.interval_idx]
                  : ALERT_INTERVALS[NUM_ALERT_INTERVALS - 1];
 
    if (now - v->alert.last_alerted >= interval) {
        v->alert.alert_count++;
        vault_log(LOG_ALERT, "REPEAT ALERT [%s] (count=%zu, interval=%lds): %s",
                  v->name, v->alert.alert_count, interval, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT (x%zu) *** [%s] %s\n\n",
                v->alert.alert_count, v->name, v->alert.reason);
 
        v->alert.last_alerted = now;
        if (v->alert.interval_idx < NUM_ALERT_INTERVALS - 1)
            v->alert.interval_idx++;
    }
}
 
VaultError alert_resolve(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;
 
    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }
 
    /* Clear modified flags */
    for (int b = 0; b < HASHMAP_BUCKETS; b++)
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next)
            e->modified = false;
 
    memset(&v->alert, 0, sizeof(v->alert));
    v->status = VAULT_STATUS_OK;
    vault_enforce_readonly(v);
 
    vault_log(LOG_AUDIT, "Alert RESOLVED for vault '%s' (id=%u)", v->name, v->id);
    return catalog_save();
}
 
/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 10: RULE ENGINE
 * ═══════════════════════════════════════════════════════════════════════════ */

void rule_add(uint32_t vault_id, int max_fails,
              int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES) {
        vault_log(LOG_WARN, "Rule table full");
        return;
    }
    g_rules[g_rule_count++] = (VaultRule){
        .vault_id            = vault_id,
        .max_failed_attempts = max_fails,
        .allowed_hour_from   = hour_from,
        .allowed_hour_to     = hour_to
    };
    vault_log(LOG_INFO, "Rule added for vault %u: max_fails=%d hours=%d-%d",
              vault_id, max_fails, hour_from, hour_to);
}

void rule_evaluate(Vault *v) {
    for (uint32_t i = 0; i < g_rule_count; i++) {
        VaultRule *r = &g_rules[i];
        if (r->vault_id != v->id) continue;

        if (r->max_failed_attempts > 0 &&
            v->failed_attempts >= r->max_failed_attempts &&
            v->status != VAULT_STATUS_LOCKED) {
            v->status = VAULT_STATUS_LOCKED;
            vault_log(LOG_ALERT, "[RULE] Vault '%s' LOCKED: %d failed attempts",
                      v->name, v->failed_attempts);
            catalog_save();
        }

        if (r->allowed_hour_from >= 0 && r->allowed_hour_to >= 0) {
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            int hour = tm->tm_hour;
            bool in_window = (r->allowed_hour_from <= r->allowed_hour_to)
                           ? (hour >= r->allowed_hour_from && hour < r->allowed_hour_to)
                           : (hour >= r->allowed_hour_from || hour < r->allowed_hour_to);
            if (!in_window) {
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "Access outside allowed time window (%02d:00-%02d:00), current hour=%02d",
                         r->allowed_hour_from, r->allowed_hour_to, hour);
                alert_trigger(v, reason);
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 11: FANOTIFY MONITOR THREAD (Linux only)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef __linux__

void monitor_add_vault_watches(MonitorCtx *ctx) {
    for (uint32_t i = 0; i < ctx->catalog->count; i++) {
        Vault *v = &ctx->catalog->vaults[i];
        if (v->status == VAULT_STATUS_DELETED) continue;

        /* Add a mark on the vault's directory.
           We want to intercept OPEN_PERM events (to block/allow open requests)
           and standard CLOSE_WRITE events (to trigger scans and database updates). */
        int ret = fanotify_mark(
            ctx->fanotify_fd,
            FAN_MARK_ADD,
            FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD,
            AT_FDCWD,
            v->path
        );

        if (ret < 0) {
            if (errno == EPERM || errno == EACCES) {
                // Not running as root — normal when running tests/unprivileged
            } else {
                vault_log(LOG_WARN, "fanotify_mark '%s' failed: %s", v->path, strerror(errno));
            }
        } else {
            vault_log(LOG_INFO, "fanotify watching vault '%s' path '%s'", v->name, v->path);
        }
    }
}

void *monitor_thread(void *arg) {
    MonitorCtx *ctx = (MonitorCtx *)arg;
    char buf[4096] __attribute__((aligned(8)));

    vault_log(LOG_INFO, "Monitor thread started (fanotify fd=%d)", ctx->fanotify_fd);

    /* Initial scan */
    pthread_mutex_lock(&ctx->lock);
    monitor_add_vault_watches(ctx);
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
        monitor_scan_vault(&ctx->catalog->vaults[i]);
    pthread_mutex_unlock(&ctx->lock);

    while (ctx->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->fanotify_fd, &rfds);
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};

        int ret = select(ctx->fanotify_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            vault_log(LOG_ERROR, "monitor select(): %s", strerror(errno));
            break;
        }

        pthread_mutex_lock(&ctx->lock);

        if (ret > 0 && FD_ISSET(ctx->fanotify_fd, &rfds)) {
            ssize_t len = read(ctx->fanotify_fd, buf, sizeof(buf));
            if (len < 0) {
                if (errno != EAGAIN && errno != EINTR)
                    vault_log(LOG_ERROR, "fanotify read: %s", strerror(errno));
            } else {
                struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata *)buf;
                while (FAN_EVENT_OK(metadata, len)) {
                    if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                        vault_log(LOG_ERROR, "Mismatch in fanotify metadata version!");
                        break;
                    }

                    // Resolve the target file path via /proc/self/fd/
                    char filepath[VAULT_PATH_MAX] = {0};
                    char procfd[64];
                    snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", metadata->fd);
                    ssize_t rlen = readlink(procfd, filepath, sizeof(filepath) - 1);
                    if (rlen > 0) {
                        filepath[rlen] = '\0';
                    }

                    // Identify which vault this file belongs to by prefix matching
                    Vault *v = NULL;
                    for (uint32_t i = 0; i < ctx->catalog->count; i++) {
                        Vault *candidate = &ctx->catalog->vaults[i];
                        if (candidate->status != VAULT_STATUS_DELETED &&
                            strncmp(filepath, candidate->path, strlen(candidate->path)) == 0) {
                            v = candidate;
                            break;
                        }
                    }

                    if (v && metadata->fd >= 0) {
                        const char *evname = filepath + strlen(v->path);
                        if (*evname == '/') evname++; // Skip leading slash

                        // Process permission request
                        if (metadata->mask & FAN_OPEN_PERM) {
                            struct fanotify_response response;
                            response.fd = metadata->fd;

                            // Core security check: Is the accessing PID whitelisted/authorized?
                            bool is_auth = vault_auth_pid_is_authorized_ffi(metadata->pid);
                            
                            // Also allow if write_mode is globally enabled for authorized actions
                            if (v->write_mode) {
                                is_auth = true;
                            }

                            // Also ignore internal sandbox paths
                            if (is_sandbox_internal(evname)) {
                                is_auth = true;
                            }

                            if (is_auth) {
                                response.response = FAN_ALLOW;
                            } else {
                                response.response = FAN_DENY;
                                
                                // Trigger alert ONLY ONCE to prevent log spam!
                                if (v->status != VAULT_STATUS_ALERT) {
                                    vault_log(LOG_ALERT, "[CRITICAL] BLOCKED UNAUTHORIZED ACCESS attempt on '%s' in vault '%s' by PID %d!",
                                              evname, v->name, metadata->pid);
                                    
                                    char reason[256];
                                    snprintf(reason, sizeof(reason), "Blocked unauthorized access on '%s' by PID %d", evname, metadata->pid);
                                    alert_trigger(v, reason);
                                    vault_enforce_readonly(v); // Instant lock
                                }
                            }

                            // Write response to Kernel to unlock/block the calling thread
                            write(ctx->fanotify_fd, &response, sizeof(response));
                        }

                        // Process closed after write (scans new files)
                        if (metadata->mask & FAN_CLOSE_WRITE) {
                            if (!is_sandbox_internal(evname)) {
                                vault_log(LOG_INFO, "[%s] File updated: %s", v->name, evname);
                                monitor_scan_vault(v);
                            }
                        }

                        rule_evaluate(v);
                    }

                    // Close the event file descriptor so we don't leak resources
                    if (metadata->fd >= 0) {
                        close(metadata->fd);
                    }

                    metadata = FAN_EVENT_NEXT(metadata, len);
                }
            }
        }

        /* Periodic alert escalation check */
        for (uint32_t i = 0; i < ctx->catalog->count; i++)
            alert_check_escalation(&ctx->catalog->vaults[i]);

        /* Re-add watches/marks for new vaults */
        monitor_add_vault_watches(ctx);

        pthread_mutex_unlock(&ctx->lock);
    }

    vault_log(LOG_INFO, "Monitor thread stopped");
    return NULL;
}

#endif /* __linux__ */
 
