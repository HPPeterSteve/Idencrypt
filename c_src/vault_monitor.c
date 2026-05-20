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
 *   - inotify monitor thread (Linux only)
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */
 
#include "vault_core.h"
 
#ifdef __linux__
#include <dirent.h>
#endif
 
/* ─────────────────────────────────────────────────────────────────────────
 *  is_sandbox_internal() — Filter inotify events caused by the sandbox
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

/* Helper: replenish per-file bucket credits */
static void replenish_file_bucket_if_needed(FileBucket *fb, time_t now) {
    if (!fb) return;
    if (fb->last_update == 0) {
        fb->credits = 3.0;
        fb->time_esgoted = 0;
        fb->credits_flash = 2;
        fb->last_update = now;
        return;
    }
    double elapsed = difftime(now, fb->last_update);
    fb->credits += elapsed * 0.025; /* Refill 0.1 credit per second */
    if (fb->credits > 3.0) fb->credits = 3.0;
    fb->last_update = now;
}

/* Helper: deduct credit and alert if exhausted */
static void deduct_credit_and_maybe_alert(Vault *v, FileBucket *fb, const char *evname) {
    if (!fb || !v) return;
    fb->credits -= 1.0;
    if (fb->credits <= 0.0) {
        fb->credits = 0.0;
        vault_log(LOG_ALERT, "[CRITICAL] Emergency! All credits exhausted for file '%s' in vault '%s'!", evname, v->name);
        char reason[256];
        snprintf(reason, sizeof(reason), "Emergency! All credits exhausted for file '%s'", evname, fb->time_esgoted > 0 ? "(multiple times)" : "");
        alert_trigger(v, reason);
        vault_enforce_readonly(v);
    } else if (fb->credits <= 1.0) {
    fb->time_esgoted++;
    vault_log(LOG_WARN, "[%s] Warning: Credits exhausted for file '%s' in vault '%s' (time_esgoted=%d)", v->name,
         evname, v->name, fb->time_esgoted);
    }
}
static void flash_credit_reduce(vault *v, FileBucket *fb, const char *evname) {
    if (!fb || !v) return;
    if (fb->credits_flash > 0) {
        fb->credits_flash--;
        fb->credits -= 0.5; // Flash deduction
        vault_log(LOG_WARN, "[%s] Flash deduction: -0.5 credits for file '%s' in vault '%s' (flash_credits left: %d)", v->name,
             evname, v->name, fb->credits_flash);
        if (fb->credits < 0.0) fb->credits = 0.0;
    }      
}

/* Handler: IN_ACCESS event */
static void handle_in_access_event(Vault *v, const char *evname, FileBucket *fb, time_t now) {
    if (!v || !evname) return;
    if (is_sandbox_internal(evname)) {
        vault_log(LOG_INFO, "[%s] Sandbox internal access (ignored): %s", v->name, evname);
        return;
    }
    FileEntry *e = hashmap_find(&v->hashmap, evname);
    FileEntry *sus = suspect_access(v, e, now);
    if (sus) {
        double credits = fb ? fb->credits : -1.0;
        vault_log(LOG_ALERT, "[%s] SUSPICIOUS ACCESS %s (credits=%.2f)", v->name, evname, credits);
        char reason[256];
        snprintf(reason, sizeof(reason), "Suspicious access: %s", evname);
        alert_trigger(v, reason);
    } else {
        double credits = fb ? fb->credits : v->bucket_credits;
        vault_log(LOG_INFO, "[%s] inotify: ACCESSED %s (Remaining credits: %.2f)", v->name, evname, credits);
    }
}

/* Handler: IN_MODIFY event */
static void handle_in_modify_event(Vault *v, const char *evname, bool is_sandbox, bool write_mode) {
    if (!v || !evname) return;
    if (is_sandbox) {
        vault_log(LOG_INFO, "[%s] Sandbox internal write (ignored): %s", v->name, evname);
    } else if (!write_mode) {
        vault_log(LOG_ALERT, "[CRITICAL] UNAUTHORIZED WRITE detected on '%s' in vault '%s'!", evname, v->name);
        char reason[256];
        snprintf(reason, sizeof(reason), "Unauthorized write (Ransomware attempt?): %s", evname);
        alert_trigger(v, reason);
        vault_enforce_readonly(v);
    } else {
        vault_log(LOG_INFO, "[%s] Authorized modification: %s", v->name, evname);
        monitor_scan_vault(v);
    }
}

/* Per-file bucket helpers */
static FileBucket *find_file_bucket(Vault *v, const char *path) {
    if (!v || !path) return NULL;
    FileBucket *fb = v->file_buckets;
    while (fb) {
        if (strncmp(fb->path, path, VAULT_PATH_MAX) == 0) return fb;
        fb = fb->next;
    }
    return NULL;
}

static FileBucket *create_file_bucket(Vault *v, const char *path) {
    if (!v || !path) return NULL;
    FileBucket *fb = (FileBucket *)calloc(1, sizeof(FileBucket));
    if (!fb) return NULL;
    strncpy(fb->path, path, VAULT_PATH_MAX - 1);
    fb->credits = 10.0;
    fb->last_update = time(NULL);
    fb->next = v->file_buckets;
    v->file_buckets = fb;
    return fb;
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
                if()
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
    // [FIX-5] Limpa a flag modified de todas as entradas do hashmap, não apenas das modificadas.
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next)
            e->modified = false;
    // [FIX-5] Reseta o estado de alerta e escalonamento, não apenas a razão.
    memset(&v->alert, 0, sizeof(v->alert));
    v->status = VAULT_STATUS_OK;
    vault_enforce_readonly(v);
    // [FIX-5] Log de resolução de alerta, incluindo o motivo original.
    vault_log(LOG_AUDIT, "Alert RESOLVED for vault '%s' (id=%u)", v->name, v->id);
    return catalog_save();
}
 
/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 10: RULE ENGINE
 * ═══════════════════════════════════════════════�        if (r->allowed_hour_from >= 0 && r->allowed_hour_to >= 0) {
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
 *  SECTION 11: INOTIFY MONITOR THREAD (Linux only)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef __linux__

void monitor_add_vault_watches(MonitorCtx *ctx) {
    for (uint32_t i = 0; i < ctx->catalog->count; i++) {
        Vault *v = &ctx->catalog->vaults[i];
        if (v->status == VAULT_STATUS_DELETED) continue;
        if (v->inotify_wd >= 0) continue;

        v->inotify_wd = inotify_add_watch(
            ctx->inotify_fd, v->path,
            IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE_SELF | IN_ATTRIB | IN_ACCESS
        );

        if (v->inotify_wd < 0)
            vault_log(LOG_WARN, "inotify_add_watch '%s': %s", v->path, strerror(errno));
        else
            vault_log(LOG_INFO, "inotify watching vault '%s' (wd=%d)", v->name, v->inotify_wd);
    }
}

static Vault *monitor_vault_by_wd(MonitorCtx *ctx, int wd) {
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
        if (ctx->catalog->vaults[i].inotify_wd == wd)
            return &ctx->catalog->vaults[i];
    return NULL;
}

void *monitor_thread(void *arg) {
    MonitorCtx *ctx = (MonitorCtx *)arg;
    char buf[INOTIFY_BUFSZ] __attribute__((aligned(8)));

    vault_log(LOG_INFO, "Monitor thread started (inotify fd=%d)", ctx->inotify_fd);

    /* Initial scan */
    pthread_mutex_lock(&ctx->lock);
    monitor_add_vault_watches(ctx);
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
        monitor_scan_vault(&ctx->catalog->vaults[i]);
    pthread_mutex_unlock(&ctx->lock);

    while (ctx->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->inotify_fd, &rfds);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

        int ret = select(ctx->inotify_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            vault_log(LOG_ERROR, "monitor select(): %s", strerror(errno));
            break;
        }

        pthread_mutex_lock(&ctx->lock);

        if (ret > 0 && FD_ISSET(ctx->inotify_fd, &rfds)) {
            ssize_t len = read(ctx->inotify_fd, buf, INOTIFY_BUFSZ);
            if (len < 0) {
                if (errno != EAGAIN)
                    vault_log(LOG_ERROR, "inotify read: %s", strerror(errno));
            } else {
                char *ptr = buf;
                while (ptr < buf + len) {
                    struct inotify_event *ev = (struct inotify_event *)ptr;

                    Vault *v = monitor_vault_by_wd(ctx, ev->wd);
                    if (v) {
                        const char *evname = (ev->len > 0) ? ev->name : "(unknown)";

                        /* Per-file Leaky Bucket: Replenish credits for this file */
                        FileBucket *fb = find_file_bucket(v, evname);
                        if (!fb) fb = create_file_bucket(v, evname);
                        time_t now = time(NULL);
                        replenish_file_bucket_if_needed(fb, now);

                        /* Deduct credit on unauthorized events for this file */
                        bool is_unauthorized_action = false;
                        if ((ev->mask & (IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)) && !v->write_mode) {
                            if (!is_sandbox_internal(evname)) {
                                is_unauthorized_action = true;
                            }
                        }

                        if (is_unauthorized_action && fb) {
                            deduct_credit_and_maybe_alert(v, fb, evname);
                        }

                        if (ev->mask & IN_MODIFY) {
                            handle_in_modify_event(v, evname, is_sandbox_internal(evname), v->write_mode);
                        } else if (ev->mask & IN_ACCESS) {
                            handle_in_access_event(v, evname, fb, now);
                        } else if (ev->mask & IN_ATTRIB) {
                            if (is_sandbox_internal(evname)) {
                                vault_log(LOG_INFO, "[%s] Sandbox internal attrib (ignored): %s", v->name, evname);
                            } else if (!v->write_mode) {
                                vault_log(LOG_ALERT, "[CRITICAL] UNAUTHORIZED ATTRIBUTE CHANGE detected on '%s' in vault '%s'!", evname, v->name);
                                char reason[256];
                                snprintf(reason, sizeof(reason), "Unauthorized attribute change (chmod/chown/utimes?): %s", evname);
                                alert_trigger(v, reason);
                                vault_enforce_readonly(v);
                            } else {
                                vault_log(LOG_INFO, "[%s] Authorized attribute change: %s", v->name, evname);
                            }
                        } else if (ev->mask & (IN_MOVE_SELF | IN_DELETE_SELF)) {
                            vault_log(LOG_ALERT, "[CRITICAL] VAULT DIRECTORY MOVED OR DELETED: %s (wd=%d)!", v->name, ev->wd);
                            char reason[256];
                            snprintf(reason, sizeof(reason), "Vault directory self moved or deleted!");
                            alert_trigger(v, reason);
                            vault_enforce_readonly(v);
                        } else if (ev->mask & IN_CREATE) {
                            if (is_sandbox_internal(evname)) {
                                vault_log(LOG_INFO, "[%s] Sandbox internal create (ignored): %s", v->name, evname);
                            } else {
                                vault_log(LOG_INFO, "[%s] inotify: CREATED %s", v->name, evname);
                                monitor_scan_vault(v);
                            }
                        } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                            if (is_sandbox_internal(evname)) {
                                /* pivot_root temp dir being cleaned up — not an attack */
                                vault_log(LOG_INFO, "[%s] Sandbox internal delete (ignored): %s", v->name, evname);
                            } else {
                                vault_log(LOG_ALERT, "[%s] inotify: DELETED/MOVED %s", v->name, evname);
                                char reason[256];
                                snprintf(reason, sizeof(reason), "File deleted/moved: %s", evname);
                                alert_trigger(v, reason);
                            }
                        }
                        rule_evaluate(v);
                    }

                    ptr += sizeof(struct inotify_event) + ev->len;
                }
            }
        }te ((ignored): "%s", v->name, evname);
                            } else {
                                vault_log(LOG_INFO, "[%s] inotify: CREATED %s", v->name, evname);
                                monitor_scan_vault(v);
                            }
                        } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                            if (is_sandbox_internal(evname)) {
                                /* pivot_root temp dir being cleaned up — not an attack */
                                vault_log(LOG_INFO, "[%s] Sandbox internal delete (ignored): %s", v->name, evname);
                            } else {
                                vault_log(LOG_ALERT, "[%s] inotify: DELETED/MOVED %s", v->name, evname);
                                char reason[256];
                                snprintf(reason, sizeof(reason), "File deleted/moved: %s", evname);
                                alert_trigger(v, reason);
                            }
                        }
                        rule_evaluate(v);
                    }
 
                    ptr += sizeof(struct inotify_event) + ev->len;
                }
            }
        }
 
        /* Periodic alert escalation check */
        for (uint32_t i = 0; i < ctx->catalog->count; i++)
            alert_check_escalation(&ctx->catalog->vaults[i]);
 
        /* Re-add watches for new vaults */
        monitor_add_vault_watches(ctx);
 
        pthread_mutex_unlock(&ctx->lock);
    }
 
    vault_log(LOG_INFO, "Monitor thread stopped");
    return NULL;
}
 
#endif /* __linux__ */
 
