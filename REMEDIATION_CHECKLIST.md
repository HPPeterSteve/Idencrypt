# Security Audit Remediation Checklist

**Project:** VaranusCore Vault System  
**Audit Date:** April 18, 2026  
**Status:** Pending Implementation  

---

## CRITICAL VULNERABILITIES (Fix First)

### [ ] 1. Password Confirmation Bypass
- **File:** vault_security.c
- **Lines:** 1196-1220, 1280-1300
- **Issue:** Static buffer reuse causes confirmation bypass
- **Patch Source:** SECURITY_PATCHES.c - PATCH 1
- **Implementation:**
  - [ ] Create `read_password_into_buffer()` function
  - [ ] Update `cmd_create()` to use separate buffers
  - [ ] Test: Create protected vault with mismatched passwords (should fail)
  - [ ] Test: Create protected vault with matching passwords (should succeed)
- **Estimated Time:** 30 minutes
- **Reviewer Sign-off:** ___________

### [ ] 2. Race Conditions in Vault State
- **File:** vault_security.c
- **Lines:** 1041, 1066, 1194, 1328+
- **Issue:** Unprotected vault modifications from monitor thread
- **Patch Source:** SECURITY_PATCHES.c - PATCH 2
- **Implementation:**
  - [ ] Add `pthread_mutex_lock()` to monitor_thread main loop
  - [ ] Add `pthread_mutex_lock()` to cmd_list()
  - [ ] Add `pthread_mutex_lock()` to cmd_info()
  - [ ] Add `pthread_mutex_lock()` to cmd_files()
  - [ ] Add `pthread_mutex_lock()` to cmd_scan()
  - [ ] Add `pthread_mutex_lock()` to vault_create()
  - [ ] Add `pthread_mutex_lock()` to vault_delete()
  - [ ] Test with ThreadSanitizer: `gcc -fsanitize=thread ...`
  - [ ] Test: Run monitor + concurrent CLI commands
- **Estimated Time:** 3-4 hours
- **Reviewer Sign-off:** ___________

### [ ] 3. Unauthenticated Encryption (AES-CBC)
- **File:** vault_security.c
- **Lines:** 477-527 (encrypt_file/decrypt_file)
- **Issue:** No authentication tag on encrypted files
- **Patch Source:** SECURITY_PATCHES.c - PATCH 3
- **Implementation:**
  - [ ] Switch to EVP_aes_256_gcm()
  - [ ] Add GCM tag generation: EVP_CIPHER_CTX_ctrl(...EVP_CTRL_GCM_GET_TAG...)
  - [ ] Update file format to include 16-byte GCM tag
  - [ ] Update decrypt_file to verify GCM tag
  - [ ] Test: Encrypt/decrypt files, verify integrity
  - [ ] Test: Tamper with encrypted file, verify detection
  - [ ] Test: Decrypt with wrong key (should fail with integrity error)
- **Estimated Time:** 4-6 hours
- **Reviewer Sign-off:** ___________

### [ ] 4. Unsigned Catalog File
- **File:** vault_security.c
- **Lines:** 820-900 (catalog_save/load)
- **Issue:** Catalog can be modified offline without detection
- **Patch Source:** SECURITY_PATCHES.c - PATCH 3
- **Implementation:**
  - [ ] Add HMAC-SHA256 to catalog format
  - [ ] Update CATALOG_VER to 2
  - [ ] Add HMAC generation in catalog_save()
  - [ ] Add HMAC validation in catalog_load()
  - [ ] Handle version migration (v1 → v2)
  - [ ] Test: Create catalog, modify binary, verify rejection
  - [ ] Test: Normal load/save cycle
- **Estimated Time:** 2-3 hours
- **Reviewer Sign-off:** ___________

---

## HIGH SEVERITY ISSUES (Implement Within 1 Week)

### [ ] 5. Weak File Permissions
- **File:** vault_security.c
- **Lines:** 160-165, 782, 842
- **Issue:** Catalog and log files may have weak permissions
- **Patch Source:** SECURITY_PATCHES.c - PATCH 4
- **Implementation:**
  - [ ] Set umask(0077) before creating catalog temp file
  - [ ] Restore umask after file creation
  - [ ] Explicitly chmod catalog file to 0600
  - [ ] Explicitly chmod log file to 0600
  - [ ] Explicitly chmod vault directories to 0700
  - [ ] Test: Verify file permissions after creation: `ls -l /var/lib/vault_security/`
- **Estimated Time:** 1 hour
- **Reviewer Sign-off:** ___________

### [ ] 6. Signal Handler Unsafe Operations
- **File:** vault_security.c
- **Lines:** 1450-1456
- **Issue:** vault_log() called from signal handler (not async-signal-safe)
- **Patch Source:** SECURITY_PATCHES.c - PATCH 5
- **Implementation:**
  - [ ] Remove vault_log() from signal_handler()
  - [ ] Only set global flags in signal handler
  - [ ] Add logging after signal detection in main loop
  - [ ] Test: Send SIGTERM/SIGINT, verify graceful shutdown
  - [ ] Test: No crash or undefined behavior during shutdown
- **Estimated Time:** 30 minutes
- **Reviewer Sign-off:** ___________

### [ ] 7. Path Traversal Incomplete
- **File:** vault_security.c
- **Lines:** 322-337 (validate_path)
- **Issue:** Symlinks and TOCTOU attacks not handled
- **Patch Source:** SECURITY_PATCHES.c - PATCH 2
- **Implementation:**
  - [ ] Replace string-based checks with realpath()
  - [ ] Validate resolved path stays within VAULT_CATALOG_PATH
  - [ ] Test: Create symlink pointing outside catalog, verify rejection
  - [ ] Test: Normal paths still accepted
- **Estimated Time:** 1-2 hours
- **Reviewer Sign-off:** ___________

### [ ] 8. Non-Atomic File Encryption
- **File:** vault_security.c
- **Lines:** 1360-1385 (cmd_encrypt_vault)
- **Issue:** File deleted after partial encryption = data loss
- **Patch Source:** SECURITY_PATCHES.c - PATCH 6
- **Implementation:**
  - [ ] Encrypt to .tmp file first
  - [ ] Use atomic rename() to move .tmp → .enc
  - [ ] Only delete original after successful rename
  - [ ] Clean up .tmp on failure
  - [ ] Test: Interrupt encryption, verify recovery
  - [ ] Test: Normal encryption/decryption cycle
- **Estimated Time:** 1-2 hours
- **Reviewer Sign-off:** ___________

### [ ] 9. No Log Rotation
- **File:** vault_security.c
- **Lines:** 160-165
- **Issue:** Log file grows indefinitely, can fill disk
- **Implementation:**
  - [ ] Implement log rotation on file size > 100MB
  - [ ] Keep max 10 rotated logs
  - [ ] Add rotation timestamp to filenames
  - [ ] Test: Create large log, verify rotation
- **Estimated Time:** 2-3 hours
- **Reviewer Sign-off:** ___________

### [ ] 10. Token Parser Bounds
- **File:** vault_security.c
- **Lines:** 1144-1178 (tokenize)
- **Issue:** Individual tokens not length-checked
- **Implementation:**
  - [ ] Add MAX_TOKEN_LEN constant
  - [ ] Validate each token length
  - [ ] Reject tokens exceeding limit
  - [ ] Test: Very long tokens in commands
- **Estimated Time:** 1 hour
- **Reviewer Sign-off:** ___________

---

## MEDIUM SEVERITY ISSUES (Implement Within 2 Weeks)

### [ ] 11. Password Entry No Timeout
- **File:** vault_security.c
- **Lines:** 1200-1220 (read_password_silent)
- **Issue:** Terminal could hang with echo disabled
- **Implementation:**
  - [ ] Add alarm(30) before reading password
  - [ ] Handle SIGALRM gracefully
  - [ ] Restore terminal state on timeout
  - [ ] Test: Wait for timeout during password entry
- **Estimated Time:** 2 hours
- **Reviewer Sign-off:** ___________

### [ ] 12. No Catalog Encryption
- **Issue:** Catalog contains sensitive data unencrypted
- **Implementation:**
  - [ ] Consider encrypting sensitive fields in catalog
  - [ ] Or keep encrypted copy separate from main catalog
  - [ ] Add migration path for existing catalogs
- **Estimated Time:** 4-6 hours
- **Reviewer Sign-off:** ___________

---

## TESTING VERIFICATION

### Compilation & Static Analysis
- [ ] Compile without warnings: `gcc -Wall -Wextra -O2 ...`
- [ ] Run clang analyzer: `clang --analyze vault_security.c`
- [ ] Build with fortify: `gcc -D_FORTIFY_SOURCE=2 ...`
- [ ] Build with address sanitizer: `gcc -fsanitize=address ...`
- [ ] Build with thread sanitizer: `gcc -fsanitize=thread ...`

### Functional Testing
- [ ] Create normal vault
- [ ] Create protected vault with password
- [ ] List vaults
- [ ] View vault info
- [ ] Encrypt vault files
- [ ] Decrypt vault files
- [ ] Delete vault (with password prompt)
- [ ] Rename vault
- [ ] View file hashes
- [ ] Add security rules
- [ ] Test password change
- [ ] Test vault unlock after lockout

### Security Testing
- [ ] Attempt to create protected vault without password (should fail)
- [ ] Attempt password confirmation with mismatched passwords (should fail)
- [ ] Attempt to decrypt encrypted file with wrong password (should fail)
- [ ] Attempt path traversal in vault path (should fail)
- [ ] Verify catalog file permissions are 0600
- [ ] Verify log file permissions are 0600
- [ ] Verify vault directory permissions are 0700
- [ ] Send SIGTERM during operation (should gracefully shutdown)
- [ ] Tamper with catalog file (should detect corruption)
- [ ] Tamper with encrypted file (should fail to decrypt)

### Performance Testing
- [ ] Test with 100 vaults in catalog
- [ ] Test with 1000+ files in vault
- [ ] Monitor memory usage during operation
- [ ] Check for memory leaks: `valgrind --leak-check=full ...`

---

## Deployment Checklist

### Pre-Deployment
- [ ] All CRITICAL fixes implemented and tested
- [ ] All tests passing
- [ ] No compiler warnings
- [ ] Security audit sign-off obtained
- [ ] Documentation updated
- [ ] Deployment plan reviewed

### Deployment
- [ ] Backup existing catalog
- [ ] Stop running vault service
- [ ] Deploy new binary
- [ ] Verify catalog loads correctly
- [ ] Run initial test commands
- [ ] Monitor for errors in first hour
- [ ] Restore backup if issues found

### Post-Deployment
- [ ] Monitor system logs for errors
- [ ] Verify all vaults accessible
- [ ] Test new security features
- [ ] Document any issues found
- [ ] Plan follow-up security audit (30 days)

---

## Sign-Off Sheet

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | __________ | ________ | __________ |
| Security Lead | __________ | ________ | __________ |
| QA Lead | __________ | ________ | __________ |
| Release Manager | __________ | ________ | __________ |

---

**Audit Report Generated:** 2026-04-18  
**Audit Reference:** VaranusCore-2026-04  
**Status:** ⚠️ PENDING REMEDIATION

For detailed information, see:
- SECURITY_REVIEW.md (technical details)
- SECURITY_PATCHES.c (code patches)
- SECURITY_AUDIT_SUMMARY.md (executive summary)

