**Linux Security Audit Tool**

A Python-based CLI tool that audits Linux systems for common security misconfigurations and reports findings with guidance.

**Overview**

This project explores how security audits can be automated on Linux systems. It inspects system configuration and permissions to identify common security weaknesses such as insecure SSH settings, misconfigured privileges, and weak file permissions.

The tool focuses on practical system hardening checks and produces clear audit-style output to help understand potential risks and recommended mitigations.

**Features**

- SSH hardening checks (root login, password authentication)
- Detection of additional UID 0 users
- Firewall status inspection (ufw, firewalld, nftables, iptables)
- World-writable file detection
- Sudo NOPASSWD rule detection
- Config-driven execution
- Optional JSON and text output
- Append-by-default audit logging with an optional overwrite flag (--clear)

**Usage**

This tool is intended to be run on a Linux environment (physical machine or virtual machine).

Run the audit:

```
python Main.py
```

Preview checks without executing them:

```
python Main.py --dry-run
```

Overwrite previous results instead of appending them:

```
python Main.py --clear
```

Some checks may require elevated privileges for full visibility.
