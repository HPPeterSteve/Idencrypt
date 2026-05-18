# Tools whitelist for restricted shell

This document explains how to provide a safe whitelist of allowed shell commands for the `idenvault-shell` wrapper.

Design:
- The wrapper can run in two modes:
  - Default: a minimal PATH (`/bin:/usr/bin`) providing a standard environment but still restricted.
  - Whitelist: use `tools/bin` inside the project; put only symlinks to allowed binaries there.

Setup example:

```sh
mkdir -p tools/bin
# allow only 'ls', 'cat', 'tail' (example)
ln -s /bin/ls tools/bin/ls
ln -s /bin/cat tools/bin/cat
ln -s /usr/bin/tail tools/bin/tail
```

Then run:

```sh
./scripts/idenvault-shell.sh --use-tools
```

Security notes:
- Even restricted shells can be escaped if dangerous programs are available in PATH. Only include well-understood utilities without shell execution features.
- Avoid adding editors, compilers, or utilities that can spawn subshells or open network connections.
- Prefer read-only tools and wrappers that validate arguments.

If you want, I can implement a safer, Go- or Rust-based sandboxed REPL that exposes a minimal set of functionality (e.g., `ls`, `cat`, `stat`) without launching a full shell.
