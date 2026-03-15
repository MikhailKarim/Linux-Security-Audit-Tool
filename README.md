**Linux Security Audit Tool**

A Python-based CLI tool that audits Linux systems for common security misconfigurations and reports findings with guidance.

**Overview**

This project detects suspicious SSH activity by analysing authentication logs and identifying repeated failed login attempts from the same IP address.

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
