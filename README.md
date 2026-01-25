# Linux Security Audit Tool

A Python-based CLI tool that audits Linux systems for common security misconfigurations and produces risk-ranked findings with remediation guidance.

## Features

- SSH hardening checks (root login, password authentication)
- Detection of additional UID 0 users
- Firewall status inspection (ufw, firewalld, nftables, iptables)
- World-writable file detection
- Sudo `NOPASSWD` rule detection
- Config-driven execution
- Optional JSON and text output
- Append-by-default audit logging with explicit overwrite control

## Usage

This tool is intended to be run on a **Linux environment** (physical machine or virtual machine).

Run the audit:
```bash
python Main.py
```

Preview checks without executing them:
```bash
python Main.py --dry-run
```

Overwrite previous results instead of appending:
```bash
python Main.py --clear
```

> Some checks may require elevated privileges for full visibility.
