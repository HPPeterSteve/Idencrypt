# IdenVault

**IdenVault** is a hardened digital vault engine and restricted execution environment, built natively for Linux.

Written in **C** (security core) and **Rust** (CLI layer), it provides cryptographic file protection and kernel-level process sandboxing — extracting the full isolation capability of the Linux kernel rather than relying on userspace abstractions.

> Beta. Tested on Linux 5.15+. Contributions and pentest reports welcome.

---

## Architecture

The project operates on two independent subsystems:

**Vault subsystem** — encrypted directories protected with AES-256-GCM, key derivation via PBKDF2-HMAC-SHA256 (310,000 iterations, OWASP 2023), real-time integrity monitoring via inotify, binary catalog with HMAC-SHA256 tamper detection, and a rate-limited authentication engine with exponential backoff alerting.

**Sandbox subsystem** — five independent isolation layers where each layer assumes the previous one has been compromised:

```
Layer 1  User Namespace      — sandbox root maps to nobody (UID 65534) on host
Layer 2  Mount + PID NS      — isolated process tree and filesystem view
Layer 3  Pivot Root          — replaces chroot; old root unmounted with MNT_DETACH
Layer 4  Capability Drop     — all Linux capabilities removed + PR_SET_NO_NEW_PRIVS
Layer 5  Seccomp-BPF         — syscall allowlist, SCMP_ACT_KILL_PROCESS as default
```

---

## Security Properties

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | PBKDF2-HMAC-SHA256, 310 000 iterations |
| Password verification | CRYPTO_memcmp (constant-time) |
| Catalog integrity | HMAC-SHA256 over full payload |
| File integrity | SHA-256 per file, inotify-triggered rescan |
| Sandbox escape prevention | UserNS + PivotRoot + Caps + Seccomp-BPF |
| Memory hygiene | explicit_bzero on all key/password buffers |
| Auth lockout | Configurable max attempts + exponential alert backoff |

---

## Build

Dependencies:

```bash
sudo apt install libssl-dev libseccomp-dev libcap-dev
```

```bash
cargo build --release
./target/release/VaranusCore
```

The build script compiles the C core (`diamondVaults.c`) and links it into the Rust binary via FFI.

---

## Usage

### Vault operations

```
vault-create <name> <path> <type>     Create a vault (type: normal | protected)
vault-encrypt <id>                    Encrypt all files in vault (AES-256-GCM)
vault-decrypt <id>                    Decrypt vault files
vault-scan <id>                       Force integrity scan
vault-resolve <id>                    Resolve active alert
vault-info <id>                       Show vault details
vault-files <id>                      List tracked files and hash status
vault-rule <id> <max_fails> [h h]     Add security rule (lockout + time window)
vault-passwd <id>                     Change vault password
vault-unlock <id>                     Unlock after failed-attempt lockout
vault-delete <id>                     Delete vault
```

```bash
# Create a protected vault
vault-create secrets /home/user/vaults/secrets protected

# Move and encrypt a file into it
secure-copy /home/user/docs/private.pdf /home/user/vaults/secrets

# Encrypt everything inside
vault-encrypt 1

# Open vault in hardened sandbox shell
vault-sandbox 1
```

### Sandbox

```
vault-sandbox <id>     Open vault directory in isolated shell (5-layer sandbox)
run-in-sandbox <dir>   Run directory in sandbox
isolate-directory <dir> Apply isolation policies to directory
```

### Key derivation

```
derive-master-key      Derive master key from password + USB hardware key (hex)
```

---

## FFI Interface

The C security core exposes a stable FFI interface consumed by the Rust CLI layer via `build.rs`. The interface is designed to be callable from any language with C FFI support — C++, Python (ctypes), Go (cgo).

See `c_src/` for the C API and `src/vault.rs` for the Rust bindings.

---

## Security Documents

| Document | Description |
|---|---|
| `SECURITY_AUDIT_SUMMARY.md` | Full audit: 9 vulnerabilities identified and fixed |
| `VULNERABILITIES.md` | Detailed vulnerability breakdown by severity |
| `REMEDIATION_CHECKLIST.md` | Fix status per finding |
| `SECURITY_REVIEW.md` | Architecture security review |

---

## Status

- C core: feature-complete, hardened
- Rust CLI: feature-complete
- Module split (single-file → multi-file): in progress
- Windows support: not planned
- Pentest: in progress (external)

---

## License

MIT — see `LICENSE`.
