# Security Review: vault_security.c

**Date:** 2026-04-18  
**Severity Levels:** CRITICAL | HIGH | MEDIUM | LOW

---

## CRITICAL VULNERABILITIES

### 1. ⚠️ CRITICAL: Missing Authenticated Encryption (AES-CBC without authentication)
**Location:** Lines 477-527 (`encrypt_file()`, `decrypt_file()`)  
**Issue:** Code uses AES-256-CBC mode without authentication tag. This is vulnerable to:
- **Padding Oracle Attacks**: Attackers can forge ciphertexts and determine plaintext through error responses
- **Tamper Detection**: No way to detect if encrypted files have been modified
- **Malleability**: Attackers can manipulate ciphertext to produce predictable plaintext changes

**Impact:** HIGH - File integrity not guaranteed; encrypted vault contents can be manipulated

**Recommendation:** Replace CBC with AES-256-GCM (Galois/Counter Mode):
```c
// Use EVP_aes_256_gcm() instead of EVP_aes_256_cbc()
// Add authentication tag: EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ...)
```

---

### 2. ⚠️ CRITICAL: Race Conditions in Vault State Modification
**Location:** Lines 1041-1095 (monitor_scan_vault), 1125 (alert_trigger), 1194 (alert_check_escalation)  
**Issue:** Vault structures are modified without synchronization:
- `monitor_scan_vault()` modifies vault hashmap and status from monitor thread
- `alert_trigger()` modifies alert state from monitor thread WITHOUT lock
- `alert_check_escalation()` modifies alert state WITHOUT lock
- Main thread reads vault state in `cmd_info()`, `cmd_files()` etc. WITHOUT lock

**Code Example (Line 1066-1067):**
```c
v->alert.reason[255] = '\0';  // No lock held!
v->status = VAULT_STATUS_ALERT;  // Race condition
catalog_save();  // Reads inconsistent state
```

**Impact:** CRITICAL - Data corruption, lost alerts, inconsistent catalog state

**Recommendation:** 
```c
// Protect all vault modifications:
pthread_mutex_lock(&g_monitor.lock);
alert_trigger(v, reason);
pthread_mutex_unlock(&g_monitor.lock);

// Also protect CLI commands that read vault state
```

---

### 3. ⚠️ CRITICAL: No Integrity Check on Catalog File
**Location:** Lines 820-900 (catalog_save/load)  
**Issue:** Binary catalog format has no HMAC or signature. An attacker can:
- Modify vault passwords by editing the binary file
- Change vault paths to point to attacker-controlled directories
- Disable password protection on protected vaults
- Modify failed_attempts counter

**Current Format (Line 798):** Just magic + version + raw binary data

**Recommendation:** Add HMAC-SHA256:
```c
#define CATALOG_VER 2  // Bump version for backward compatibility
// Add HMAC-SHA256 at end of catalog
uint8_t hmac_key[KEY_LEN];
derive_key("catalog_secret", salt, hmac_key);
HMAC(EVP_sha256(), hmac_key, KEY_LEN, catalog_data, catalog_len, 
     hmac_tag, NULL);
fwrite(hmac_tag, SHA256_DIGEST_LENGTH, 1, fp);
```

---

## HIGH SEVERITY VULNERABILITIES

### 4. ⚠️ HIGH: Buffer Overflow in Token Parser
**Location:** Lines 1144-1178 (tokenize function)  
**Issue:** While bounds are checked with `count < max`, the token parser can create long unquoted tokens without length validation

**Example Attack:**
```
vault> create $(printf 'A%.0s' {1..10000})
```

The token itself isn't length-checked, only count. Tokens are parsed from stack buffer `line[1024]` but tokens array just stores pointers.

**Impact:** MEDIUM - Not immediately exploitable but could cause issues with buffer overflow in later string operations

**Recommendation:** Add length validation per token

---

### 5. ⚠️ HIGH: Unsafe Path Traversal Check
**Location:** Lines 322-337 (validate_path)  
**Issue:** Path traversal check is incomplete:
```c
if (strstr(path, "/../") || (strlen(path) >= 3 && 
    strcmp(path + strlen(path) - 3, "/..") == 0))
```

This misses several attack vectors:
- `//` sequences (could bypass some canonicalization)
- `/./` sequences  
- Symlink-based attacks (not checked at all)
- Race condition: path could be changed between validation and use (TOCTOU)

**Better Approach:** Use `realpath()`:
```c
char resolved[PATH_MAX];
if (!realpath(path, resolved) || strncmp(resolved, VAULT_CATALOG_PATH, 
    strlen(VAULT_CATALOG_PATH)) != 0) {
    return ERR_PATH_INVALID;  // Path escapes catalog!
}
```

---

### 6. ⚠️ HIGH: Weak Umask for Vault Directory Creation
**Location:** Line 771 (vault_create)  
**Issue:** 
```c
if (mkdir(path_buf, 0700) != 0 && errno != EEXIST)
```

The actual directory permissions depend on process `umask`. If umask is 0077, directory will be 0700. But if umask is 0, directory will still be 0700 (good). However, if someone sets umask to 0027, directory becomes 0700 still due to AND operation, so this is actually OK.

But Line 842: `chmod(VAULT_CATALOG_FILE, 0600)` is good. However, `VAULT_LOG_FILE` is not restricted!

**Recommendation:** Also chmod the log file:
```c
chmod(VAULT_LOG_FILE, 0600);  // After fopen in log_init()
```

---

### 7. ⚠️ HIGH: Catalog File Created with Insecure Permissions
**Location:** Line 782 (catalog_save - atomic rename)  
**Issue:** The temporary file is created with `fopen(tmp, "wb")` which respects umask. If umask allows world-readable files, the temp catalog could be readable before it's moved.

**Recommendation:**
```c
int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
FILE *fp = fdopen(fd, "wb");
```

---

## MEDIUM SEVERITY ISSUES

### 8. ⚠️ MEDIUM: No Maximum Size Limits on String Operations
**Location:** Multiple string operations throughout  
**Issue:** While `VAULT_NAME_MAX` and `VAULT_PATH_MAX` are defined, many functions use `strncpy()` which doesn't guarantee null termination in some cases.

**Example (Line 709):**
```c
strncpy(v->name, name_buf, VAULT_NAME_MAX - 1);  // Good
// But then Line 721:
strncpy(v->path, path_buf, VAULT_PATH_MAX - 1);  // Good
```

Actually, these are OK because they subtract 1. But other places might not be.

**Better Practice:** Use safer string functions or always null-terminate explicitly.

---

### 9. ⚠️ MEDIUM: Password Input Not Validated Before Use
**Location:** Lines 1280-1320 (create command)  
**Issue:** When creating protected vault:
```c
char *p1 = read_password_silent("  Set vault password: ");
if (!p1 || !*p1) { printf("  Password required.\n"); return; }
strncpy(pass_buf, p1, MAX_PASS_LEN - 1);
```

The `read_password_silent()` function returns a pointer to a static buffer that's reused:
```c
static char buf[MAX_PASS_LEN];  // Line 1200
```

**Issue:** If `read_password_silent()` is called twice quickly (p1 and p2), the second call overwrites p1's data before strcmp is done.

**PoC:**
```c
char *p1 = read_password_silent("Pass 1: ");  // buf = "secret1"
char *p2 = read_password_silent("Pass 2: ");  // buf now = "secret2", p1 points to "secret2"!
if (strcmp(p1, p2) != 0) // Compares "secret2" with "secret2" - always matches!
```

**Impact:** HIGH - Protected vault password confirmation is bypassed!

**Recommendation:**
```c
static char p1_buf[MAX_PASS_LEN], p2_buf[MAX_PASS_LEN];
char *p1 = read_password_silent("Set password: ");
if (p1) strncpy(p1_buf, p1, MAX_PASS_LEN - 1);
char *p2 = read_password_silent("Confirm: ");
if (p2) strncpy(p2_buf, p2, MAX_PASS_LEN - 1);
if (strcmp(p1_buf, p2_buf) != 0) { ... }
explicit_bzero(p1_buf, sizeof(p1_buf));
explicit_bzero(p2_buf, sizeof(p2_buf));
```

---

### 10. ⚠️ MEDIUM: Missing Error Handling in Signal Handler
**Location:** Line 1451 (signal_handler)  
**Issue:** 
```c
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        vault_log(LOG_INFO, "Signal %d received...", sig);  // NOT SAFE!
        g_running = false;
        g_monitor.running = false;
    }
}
```

**Problem:** `vault_log()` calls `localtime()`, `strftime()`, `fprintf()`, and `fflush()` - NONE of these are async-signal-safe! This can crash the program.

**POSIX Async-Signal-Safe Functions:** Only a limited set like `write()`, `_exit()`, `signal()`, etc.

**Recommendation:**
```c
static void signal_handler(int sig) {
    // Only do async-signal-safe operations
    g_running = false;
    g_monitor.running = false;
    // Logging is NOT safe here
}
```

---

### 11. ⚠️ MEDIUM: Incomplete File Encryption (Not Atomic)
**Location:** Lines 1360-1385 (cmd_encrypt_vault)  
**Issue:** Files are encrypted and then deleted:
```c
if (encrypt_file(inpath, outpath, key) == ERR_OK) {
    unlink(inpath);  // If interrupted here, original file is gone but encryption incomplete
```

If the program crashes or is killed between `encrypt_file()` and `unlink()`, recovery is impossible.

**Recommendation:** Use rename-based atomic operation:
```c
if (encrypt_file(inpath, tmppath, key) == ERR_OK) {
    if (rename(tmppath, outpath) == 0) {
        unlink(inpath);
    }
}
```

---

### 12. ⚠️ MEDIUM: No Timeout on Password Entry
**Location:** Lines 1200-1220 (read_password_silent)  
**Issue:** If a user enters password and leaves it hanging, the terminal will remain with echo disabled until signal is received.

**Recommendation:** Add alarm/timeout with proper signal handling

---

## LOW SEVERITY ISSUES

### 13. ℹ️ LOW: Potential Integer Overflow in Alert Intervals
**Location:** Lines 90-94  
**Issue:** `ALERT_INTERVALS[]` uses `long` values. On 32-bit systems, values like `31536000` (1 year) could overflow in arithmetic.

**Recommendation:** Use `time_t` explicitly

---

### 14. ℹ️ LOW: Missing Validation of Vault Type in Commands
**Location:** Various command handlers  
**Issue:** Commands like `cmd_files()` don't validate that the vault exists and is accessible before reading its data.

---

### 15. ℹ️ LOW: Log File Not Rotated
**Location:** Lines 160-165 (log_init)  
**Issue:** Log file opens in append mode and never rotates. A long-running daemon could fill the disk.

**Recommendation:** Implement log rotation or use syslog

---

## SUMMARY TABLE

| ID | Severity | Type | Issue | Fix Difficulty |
|---|----------|------|-------|-----------------|
| 1 | CRITICAL | Crypto | No authenticated encryption | MEDIUM |
| 2 | CRITICAL | Threading | Race conditions in vault state | MEDIUM |
| 3 | CRITICAL | File | Unsigned catalog | MEDIUM |
| 4 | HIGH | Buffer | Token parser bounds | LOW |
| 5 | HIGH | Security | Path traversal incomplete | MEDIUM |
| 6 | HIGH | Permissions | Weak file permissions | LOW |
| 7 | HIGH | Permissions | Temp file permissions | LOW |
| 8 | MEDIUM | String | Missing size limits | LOW |
| 9 | MEDIUM | Logic | Password confirmation bypass | HIGH |
| 10 | MEDIUM | Signal | Async-signal-safety violation | MEDIUM |
| 11 | MEDIUM | Atomicity | Non-atomic encryption | MEDIUM |
| 12 | MEDIUM | UX | No password entry timeout | LOW |
| 13 | LOW | Overflow | Integer overflow risk | LOW |
| 14 | LOW | Logic | Missing validation | LOW |
| 15 | LOW | Ops | No log rotation | LOW |

---

## RECOMMENDATIONS (Priority Order)

1. **IMMEDIATE:** Fix race conditions (#2) - Use proper synchronization for all vault state modifications
2. **IMMEDIATE:** Fix password confirmation bypass (#9) - Use separate buffers
3. **HIGH:** Add authenticated encryption (#1) - Switch to AES-256-GCM
4. **HIGH:** Add catalog integrity (#3) - Add HMAC signature
5. **HIGH:** Fix path validation (#5) - Use realpath()
6. **MEDIUM:** Fix signal handler (#10) - Remove unsafe operations
7. **MEDIUM:** Fix file permissions (#6, #7) - Restrict permissions on sensitive files
8. **MEDIUM:** Make encryption atomic (#11) - Use atomic rename operations

---

## Testing Recommendations

- Add unit tests for cryptographic functions
- Use thread sanitizer (TSan) to detect race conditions
- Fuzzing for input validation functions
- Penetration testing of authentication logic
- Code audit by security specialist

