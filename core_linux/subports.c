/*

[ Target Process ]
        |
        v
[ Pre-Execution Validator ]
 (assinatura, hash, policy)
        |
        v
[ Fork + Drop Privileges ]
 (UID isolado, no root)
        |
        v
[ chroot + mount isolation ]
 (fs mínimo, noexec, nosuid)
        |
        v
[ Resource Limits ]
 (rlimit, cgroup: CPU, RAM, FD)
        |
        v
[ seccomp ]
 (syscalls whitelist)
        |
        v
[ network namespace ]
        |
        v
[ iptables / nftables ]
  - block loopback
  - force DNS
  - force proxy
  - block raw IP
        |
        v
[ DNS Validator ]
 (whitelist + fallback honeypot)
        |
        v
[ Proxy Sandbox ]
 (inspection + decision engine)
        |
   ├── Internet real
   ├── Honeypot fake
   └── Drop / Kill
        |
        v
[ Monitor + Logger ]
 (audit + alert + kill switch)
 */