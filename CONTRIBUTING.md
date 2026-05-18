# Contributing to Komodo Core

Komodo Core is a security-focused project. Contributions are welcome, but the bar for correctness is high — especially in the C core, where mistakes have real security consequences.

Read this document before opening a pull request.

---

## What we need help with

Check the open issues. Issues labeled `good first issue` are self-contained and well-scoped. Issues labeled `security` require extra care and review.

Current priorities:
- Module split of `diamondVaults.c` into focused `.c/.h` pairs
- Expanding test coverage in `tests/`
- Documentation improvements
- Audit of the seccomp allowlist for completeness

---

## Setup

Dependencies (Linux only — this project does not support Windows):

```bash
sudo apt install build-essential libssl-dev libseccomp-dev libcap-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone and build:

```bash
git clone https://github.com/HPPeterSteve/Komodo-Core.git
cd Komodo-Core
cargo build
```

The build script (`build.rs`) compiles the C core automatically via `cc` and links it into the Rust binary.

---

## Code style

**C core (`c_src/`, `core_linux/`):**
- Follow the existing style — 4-space indent, braces on same line for functions
- Every function that can fail must return `VaultError`
- Every early return path that holds a key or password buffer must call `explicit_bzero` before returning
- No `malloc` without a corresponding free on every exit path
- Use `goto cleanup` pattern for multi-resource cleanup — see existing functions in `vault_crypto.c` as reference

**Rust layer (`src/`):**
- Standard `rustfmt` formatting — run `cargo fmt` before committing
- No `unwrap()` in production paths — use proper error propagation
- FFI calls to the C core must be in `unsafe` blocks with a comment explaining why it is safe

---

## Security guidelines

This is the most important section.

**If you are touching the C core:**
- Never use `strcpy`, `sprintf`, `gets` — use `strncpy` with explicit null termination, `snprintf`, `fgets`
- Never use `stat()` on paths inside a vault — use `lstat()` to avoid symlink following
- Never compare cryptographic values with `memcmp` or `==` — use `CRYPTO_memcmp`
- Always call `explicit_bzero` on key and password buffers, including error paths
- If you add a new syscall to the seccomp allowlist in `apply_seccomp_policy()`, explain why in a comment

**If you find a vulnerability:**
Do not open a public issue. Open a GitHub Security Advisory or email the maintainer directly. See `SECURITY.md`.

---

## Testing

Run the existing test suite:

```bash
cargo test
```

The tests in `tests/security_exploit.rs` call the C core directly via FFI and verify security boundaries — buffer overflow rejection, null pointer handling, authentication bypass prevention.

When adding a new feature, add a corresponding test. When fixing a bug, add a test that would have caught it.

---

## Pull request process

1. Create a branch from `main`:
```bash
git checkout -b fix/catalog-hmac-regression
```

2. Make your changes. Keep commits focused — one logical change per commit.

3. Write a clear commit message:
```bash
git commit -m "vault_catalog: reintroduce HMAC-SHA256 integrity check

Fixes regression introduced in refactor. catalog_save() now computes
HMAC-SHA256 over the serialized payload and appends it before close.
catalog_load() verifies with CRYPTO_memcmp before processing any byte.
Closes #3."
```

4. Run tests before pushing:
```bash
cargo test
cargo clippy
cargo fmt --check
```

5. Open a pull request with:
   - What the change does
   - Why it is necessary
   - Which issue it closes (if any)
   - Any security implications

---

## What gets rejected

- Changes that remove `explicit_bzero` calls
- Changes that replace `CRYPTO_memcmp` with standard comparison
- Changes that add syscalls to the seccomp allowlist without justification
- Untested changes to the authentication or encryption logic
- Generic improvements that don't fit the project's scope

---

## Questions

Open a discussion on GitHub or comment on the relevant issue.
