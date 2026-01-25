import json
import os
import sys
import asyncio
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Callable, Awaitable

BASE = Path(__file__).resolve().parent
INP = BASE / "Input" / "Config.json"
OUT = BASE / "Output" / "Results.txt"
JOUT = BASE / "Output" / "Results.json"

class Finding:
    def __init__(self, severity: str, title: str, evidence: str, recommendation: str) -> None:
        self.severity = severity
        self.title = title
        self.evidence = evidence
        self.recommendation = recommendation

    def format(self) -> str:
        return (
            f"[{self.severity}] {self.title}\n"
            f"- Evidence: {self.evidence}\n"
            f"- Recommendation: {self.recommendation}\n"
            )


def load() -> Dict[str, bool]:
    if not INP.exists():
        return {}
    try:
        with INP.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return {}
        return {str(key): bool(val) for key, val in data.items()}
    except (OSError, json.JSONDecodeError):
        return {}


async def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        outb, errb = await proc.communicate()
        out = outb.decode("utf-8", errors="ignore").strip()
        err = errb.decode("utf-8", errors="ignore").strip()
        return proc.returncode, out, err
    except FileNotFoundError:
        return 127, "", "command not found"
    except Exception as exc:
        return 1, "", str(exc)


def read(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def flag(data: Dict[str, bool], name: str) -> bool:
    want = name.lower()
    for key, val in data.items():
        if key.lower() == want:
            return val is True
    return False


def parse() -> Dict[str, str]:
    data = {}
    paths = [Path("/etc/ssh/sshd_config")]
    confd = Path("/etc/ssh/sshd_config.d")
    if confd.is_dir():
        paths.extend(sorted(confd.glob("*.conf")))
    for path in paths:
        for line in read(path):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            items = text.split()
            if len(items) >= 2:
                data[items[0].lower()] = " ".join(items[1:])
    return data


def summ(counts: Dict[str, int], total: int, risk: str, stamp: str) -> str:
    return (
        f"[SUMMARY @ {stamp}]\n"
        f"- Findings: {total}\n"
        f"- High: {counts['HIGH']}\n"
        f"- Medium: {counts['MED']}\n"
        f"- Low: {counts['LOW']}\n"
        f"- Info: {counts['INFO']}\n"
        f"- Overall Risk: {risk}"
    )


def writetxt(results: List[Finding], summary: str, enabled: bool, clear: bool) -> None:
    if not enabled:
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join([item.format() for item in results])
    content = summary + "\n\n" + body + "\n\n"
    mode = "w" if clear else "a"
    with OUT.open(mode, encoding="utf-8") as handle:
        handle.write(content)


def writejson(results: List[Finding], stamp: str, summary: Dict[str, object], enabled: bool) -> None:
    if not enabled:
        return
    record = {
        "Timestamp": stamp,
        "Summary": summary,
        "Results": [
            {
                "Severity": item.severity,
                "Title": item.title,
                "Evidence": item.evidence,
                "Recommendation": item.recommendation,
            }
            for item in results
        ],
    }
    data = []
    try:
        if JOUT.exists():
            with JOUT.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        if not isinstance(data, list):
            data = []
    except (OSError, json.JSONDecodeError):
        data = []
    data.append(record)
    with JOUT.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


async def sshd() -> Dict[str, str]:
    code, out, err = await run(["sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"])
    if code == 0 and out:
        data = {}
        for line in out.splitlines():
            text = line.strip()
            if not text:
                continue
            items = text.split()
            if len(items) >= 2:
                data[items[0].lower()] = " ".join(items[1:])
        return data
    return parse()


async def root() -> Finding:
    config = await sshd()
    value = config.get("permitrootlogin")
    if value is None:
        return Finding(
            "INFO",
            "SSH root login setting not found",
            "PermitRootLogin not set in /etc/ssh/sshd_config",
            "Define PermitRootLogin no to prevent root SSH access",
        )
    if value.lower() in {"yes", "without-password", "prohibit-password"}:
        return Finding(
            "HIGH",
            "SSH root login enabled",
            f"PermitRootLogin {value}",
            "Disable SSH root login and use sudo instead",
        )
    return Finding(
        "INFO",
        "SSH root login disabled",
        f"PermitRootLogin {value}",
        "Keep root SSH login disabled",
    )


async def password() -> Finding:
    config = await sshd()
    value = config.get("passwordauthentication")
    if value is None:
        return Finding(
            "INFO",
            "SSH password authentication setting not found",
            "PasswordAuthentication not set in /etc/ssh/sshd_config",
            "Set PasswordAuthentication no and use SSH keys",
        )
    if value.lower() == "yes":
        return Finding(
            "MED",
            "SSH password authentication enabled",
            f"PasswordAuthentication {value}",
            "Disable SSH password authentication and use SSH keys",
        )
    return Finding(
        "INFO",
        "SSH password authentication disabled",
        f"PasswordAuthentication {value}",
        "Keep SSH password authentication disabled",
    )


async def uidzero() -> Finding:
    users = []
    for line in read(Path("/etc/passwd")):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
            users.append(parts[0])
    if users:
        return Finding(
            "HIGH",
            "Additional UID 0 users detected",
            f"UID 0 users: {', '.join(users)}",
            "Remove or change UID of non-root users with UID 0",
        )
    return Finding(
        "INFO",
        "No additional UID 0 users",
        "Only root has UID 0",
        "Maintain a single UID 0 account",
    )


async def firewall() -> Finding:
    code, out, err = await run(["ufw", "status"])
    if code == 0 and out:
        if "Status: active" in out:
            return Finding(
                "INFO",
                "Firewall active (ufw)",
                out.splitlines()[0],
                "Keep firewall enabled and review rules",
            )
        if "Status: inactive" in out:
            return Finding(
                "LOW",
                "Firewall inactive (ufw)",
                out.splitlines()[0],
                "Enable a firewall and restrict inbound traffic",
            )

    code, out, err = await run(["firewall-cmd", "--state"])
    if code == 0 and out:
        if out.strip() == "running":
            return Finding(
                "INFO",
                "Firewall active (firewalld)",
                "firewalld state: running",
                "Keep firewall enabled and review rules",
            )
        if out.strip() == "not running":
            return Finding(
                "LOW",
                "Firewall inactive (firewalld)",
                "firewalld state: not running",
                "Enable a firewall and restrict inbound traffic",
            )

    code, out, err = await run(["nft", "list", "ruleset"])
    if code == 0 and out:
        lines = [line for line in out.splitlines() if line.strip()]
        if lines:
            return Finding(
                "INFO",
                "Firewall rules present (nftables)",
                f"nftables rules: {len(lines)}",
                "Review nftables rules to ensure least privilege",
            )

    code, out, err = await run(["iptables", "-S"])
    if code == 0 and out:
        lines = out.splitlines()
        policies = [line for line in lines if line.startswith("-P")]
        rules = [line for line in lines if line.startswith("-A")]
        if rules:
            return Finding(
                "INFO",
                "Firewall rules present (iptables)",
                f"iptables rules: {len(rules)}",
                "Review iptables rules to ensure least privilege",
            )
        if policies and all(" ACCEPT" in line for line in policies):
            return Finding(
                "LOW",
                "Firewall appears inactive (iptables)",
                "iptables policies set to ACCEPT with no rules",
                "Configure firewall rules or enable ufw/firewalld",
            )

    return Finding(
        "INFO",
        "Firewall not detected",
        "No ufw, firewalld, nftables, or iptables output available",
        "Install and enable a firewall",
    )


async def world() -> Finding:
    roots = ["/etc", "/home", "/var", "/opt", "/usr/local"]
    found = []
    errors = 0
    for root in roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path, follow_symlinks=False)
                    if st.st_mode & 0o002:
                        found.append(path)
                        if len(found) >= 20:
                            break
                except PermissionError:
                    errors += 1
                except OSError:
                    continue
            if len(found) >= 20:
                break
        if len(found) >= 20:
            break

    if found:
        evidence = f"World-writable files found (showing up to 20): {', '.join(found)}"
        if errors:
            evidence += f"; permission errors: {errors}"
        return Finding(
            "MED",
            "World-writable files detected",
            evidence,
            "Remove world-writable permissions or restrict access",
        )

    evidence = "No world-writable files found in standard paths"
    if errors:
        evidence += f"; permission errors: {errors}"
    return Finding(
        "INFO",
        "No world-writable files detected",
        evidence,
        "Maintain least-privilege file permissions",
    )


async def sudo() -> Finding:
    paths = [Path("/etc/sudoers")]
    sudoersd = Path("/etc/sudoers.d")
    if sudoersd.is_dir():
        paths.extend([path for path in sudoersd.iterdir() if path.is_file()])

    matches = []
    unread = 0
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            unread += 1
            continue
        for line in lines:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if "NOPASSWD" in text:
                matches.append(f"{path}: {text}")

    if matches:
        evidence = "; ".join(matches[:10])
        if len(matches) > 10:
            evidence += f"; and {len(matches) - 10} more"
        return Finding(
            "HIGH",
            "Sudo NOPASSWD rules found",
            evidence,
            "Remove NOPASSWD or limit to trusted, auditable commands",
        )

    evidence = "No NOPASSWD entries found"
    if unread:
        evidence += f"; unreadable files: {unread}"
    return Finding(
        "INFO",
        "No sudo NOPASSWD rules",
        evidence,
        "Keep sudo requiring authentication",
    )


async def safe(key: str, func: Callable[[], Awaitable[Finding]]) -> Finding:
    try:
        return await func()
    except Exception as exc:
        return Finding(
            "INFO",
            f"Check failed: {key}",
            str(exc),
            "Review system permissions and try again",
        )


async def start() -> int:
    if "--dry-run" in sys.argv:
        config = load()
        if not config:
            print(f"Unable to read {INP}")
            return 1
        names = [
            "checkSshRootLogin",
            "checkSshPasswordAuth",
            "checkUidZeroUsers",
            "checkFirewallStatus",
            "checkWorldWritableFiles",
            "checkSudoNoPasswordRules",
        ]
        enabled = [key for key in names if flag(config, key)]
        print("Dry run: checks that would execute")
        for key in enabled:
            print(f"- {key}")
        if not enabled:
            print("No checks enabled in Config.json")
        return 0

    config = load()
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clear = "--clear" in sys.argv
    jsonon = flag(config, "writeJsonResults") or flag(config, "WriteJsonResults")
    texton = (
        flag(config, "WriteTextResults")
        or flag(config, "writeTextResults")
        or flag(config, "WriteTextResukts")
    )

    if not config:
        result = Finding(
            "INFO",
            "Configuration missing or invalid",
            f"Unable to read {INP}",
            "Create Input/Config.json with check flags",
        )
        counts = {"HIGH": 0, "MED": 0, "LOW": 0, "INFO": 1}
        summary = summ(counts, 1, "Info", stamp)
        writetxt([result], summary, texton, clear)
        writejson(
            [result],
            stamp,
            {"Results": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 1, "Overall Risk": "Info"},
            jsonon,
        )
        return 1

    checks: Dict[str, Callable[[], Awaitable[Finding]]] = {
        "checkSshRootLogin": root,
        "checkSshPasswordAuth": password,
        "checkUidZeroUsers": uidzero,
        "checkFirewallStatus": firewall,
        "checkWorldWritableFiles": world,
        "checkSudoNoPasswordRules": sudo,
    }

    jobs = [safe(key, func) for key, func in checks.items() if flag(config, key)]
    if not jobs:
        result = Finding(
            "INFO",
            "No checks executed",
            "All checks disabled in Config.json",
            "Enable checks to run the audit",
        )
        counts = {"HIGH": 0, "MED": 0, "LOW": 0, "INFO": 1}
        summary = summ(counts, 1, "Info", stamp)
        writetxt([result], summary, texton, clear)
        writejson(
            [result],
            stamp,
            {"Results": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 1, "Overall Risk": "Info"},
            jsonon,
        )
        return 0

    results = await asyncio.gather(*jobs)
    counts = {"HIGH": 0, "MED": 0, "LOW": 0, "INFO": 0}
    for item in results:
        counts[item.severity] = counts.get(item.severity, 0) + 1

    if counts["HIGH"] > 0:
        risk, code = "High", 3
    elif counts["MED"] > 0:
        risk, code = "Medium", 2
    elif counts["LOW"] > 0:
        risk, code = "Low", 1
    else:
        risk, code = "Info", 0

    total = len(results)
    summary = summ(counts, total, risk, stamp)
    writetxt(results, summary, texton, clear)
    writejson(
        results,
        stamp,
        {
            "Results": total,
            "High": counts["HIGH"],
            "Medium": counts["MED"],
            "Low": counts["LOW"],
            "Info": counts["INFO"],
            "Overall Risk": risk,
        },
        jsonon,
    )
    return code


if __name__ == "__main__":
    sys.exit(asyncio.run(start()))
