"""
modules/remote_scanner.py
Connects to a remote Ubuntu VM via SSH and runs all RootSentry detection
logic remotely: hidden processes, rootkit kernel modules, and hidden ports.

Usage:
    python3 modules/remote_scanner.py <HOST> <PASSWORD>
    python3 modules/remote_scanner.py 192.168.1.50 toor
"""

from __future__ import annotations

import sys
import json
import re
from typing import Optional

try:
    import paramiko
except ImportError:
    print("[!] paramiko not installed — run: pip install paramiko")
    sys.exit(1)

# ── Inline config (mirrors config.py values so the module is self-contained) ──
KNOWN_ROOTKITS = [
    "diamorphine", "reptile", "azazel", "beurk",
    "necurs", "suterusu", "adore-ng", "knark", "modhide", "kbeast",
]
SUSPICIOUS_KALLSYMS = [
    "sys_call_table", "ia32_sys_call_table", "do_fork",
    "tcp4_seq_show", "packet_rcv", "tpacket_rcv", "audit_log_exit",
]

# ── Risk thresholds ───────────────────────────────────────────────────────────
RISK_CLEAN      = 0
RISK_SUSPICIOUS = 2   # 1-2 threats
RISK_INFECTED   = 3   # 3+ threats


# ── SSH helpers ───────────────────────────────────────────────────────────────

def _exec(ssh: paramiko.SSHClient, cmd: str) -> str:
    """Run a command on the remote host, return stdout as a string."""
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=30)
        return stdout.read().decode(errors="replace")
    except Exception as exc:
        return f"__ERROR__: {exc}"


def connect(host: str, password: str, user: str = "root", port: int = 22,
            timeout: int = 10) -> paramiko.SSHClient:
    """Open an SSH connection. Raises on failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


# ── Detection: hidden processes ───────────────────────────────────────────────

def _scan_hidden_processes(ssh: paramiko.SSHClient) -> dict:
    """Compare /proc PIDs against `ps -e` — discrepancy = hidden process."""
    raw_proc = _exec(ssh, "ls /proc | grep -E '^[0-9]+$'")
    raw_ps   = _exec(ssh, "ps -e -o pid=")

    proc_pids: set[int] = set()
    for token in raw_proc.split():
        if token.isdigit():
            proc_pids.add(int(token))

    ps_pids: set[int] = set()
    for token in raw_ps.split():
        token = token.strip()
        if token.isdigit():
            ps_pids.add(int(token))

    # Exclude PID 1 / 2 which may differ depending on ns visibility
    hidden = sorted(proc_pids - ps_pids - {1, 2})
    findings = []
    for pid in hidden:
        cmdline = _exec(ssh, f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '").strip()
        findings.append({
            "type":    "hidden_process",
            "pid":     pid,
            "cmdline": cmdline or "(unknown)",
            "detail":  f"PID {pid} visible in /proc but absent from ps",
        })

    return {
        "module":       "process_scanner",
        "threat_count": len(findings),
        "findings":     findings,
        "summary": (
            f"{len(findings)} hidden process(es) detected."
            if findings else "No hidden processes detected."
        ),
    }


# ── Detection: rootkit kernel modules & kallsyms ──────────────────────────────

def _scan_syscalls(ssh: paramiko.SSHClient) -> dict:
    """Check /proc/modules for rootkit names and /proc/kallsyms for hooks."""
    raw_modules  = _exec(ssh, "cat /proc/modules 2>/dev/null")
    raw_kallsyms = _exec(ssh, "cat /proc/kallsyms 2>/dev/null")

    findings: list[dict] = []

    # --- /proc/modules ---
    for line in raw_modules.splitlines():
        parts = line.split()
        if not parts:
            continue
        name_lower = parts[0].lower()
        for rootkit in KNOWN_ROOTKITS:
            if rootkit in name_lower:
                findings.append({
                    "type":   "rootkit_module",
                    "module": parts[0],
                    "size":   parts[1] if len(parts) > 1 else "?",
                    "detail": f"Matches known rootkit signature: '{rootkit}'",
                })

    # --- /proc/kallsyms ---
    seen: set[str] = set()
    for line in raw_kallsyms.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, sym = parts[0], parts[2]
        sym_lower = sym.lower()

        for rootkit in KNOWN_ROOTKITS:
            if rootkit in sym_lower and sym not in seen:
                seen.add(sym)
                findings.append({
                    "type":   "suspicious_symbol",
                    "symbol": sym,
                    "addr":   addr,
                    "detail": f"Symbol contains rootkit string '{rootkit}'",
                })

        if addr == "0000000000000000":
            for hook in SUSPICIOUS_KALLSYMS:
                if hook in sym_lower and sym not in seen:
                    seen.add(sym)
                    findings.append({
                        "type":   "hidden_symbol",
                        "symbol": sym,
                        "addr":   addr,
                        "detail": "Address zeroed — likely hidden by rootkit",
                    })

    return {
        "module":       "syscall_inspector",
        "threat_count": len(findings),
        "findings":     findings,
        "summary": (
            f"{len(findings)} kernel-level hook(s)/rootkit module(s) detected."
            if findings else "No kernel hooks or rootkit modules detected."
        ),
    }


# ── Detection: hidden ports ───────────────────────────────────────────────────

def _parse_proc_net_tcp(raw: str) -> set[int]:
    """Extract LISTEN-state ports from /proc/net/tcp (hex format)."""
    ports: set[int] = set()
    lines = raw.strip().splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[3] != "0A":   # 0A = TCP_LISTEN
            continue
        local = parts[1]
        hex_port = local.split(":")[1]
        try:
            ports.add(int(hex_port, 16))
        except ValueError:
            pass
    return ports


def _get_ss_ports(ssh: paramiko.SSHClient) -> set[int]:
    """Get listening ports as reported by `ss -tlnp`."""
    ports: set[int] = set()
    raw = _exec(ssh, "ss -tlnp 2>/dev/null")
    lines = raw.strip().splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        addr_port = parts[3]
        if ":" in addr_port:
            port_str = addr_port.rsplit(":", 1)[-1]
            if port_str.isdigit():
                ports.add(int(port_str))
    return ports


def _scan_filesystem(ssh: paramiko.SSHClient) -> dict:
    """
    1. Compare /proc/net/tcp vs ss for hidden ports.
    2. Scan /tmp, /dev/shm, /var/tmp for suspicious files (SUID or shady names).
    3. Check for known rootkit indicator paths.
    """
    findings: list[dict] = []

    # ── Known rootkit paths ──────────────────────────────────────────────
    rootkit_paths = [
        "/proc/diamorphine",
        "/proc/reptile",
        "/proc/.azazel",
        "/dev/hda",           # fake device used by some rootkits
    ]
    for rpath in rootkit_paths:
        result = _exec(ssh, f"test -e {rpath} && echo EXISTS || echo ABSENT")
        if "EXISTS" in result:
            findings.append({
                "type":   "rootkit_path",
                "path":   rpath,
                "detail": f"Known rootkit indicator path found: {rpath}",
            })

    # ── Hidden ports ─────────────────────────────────────────────────────
    raw_tcp  = _exec(ssh, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
    proc_ports = _parse_proc_net_tcp(raw_tcp)
    ss_ports   = _get_ss_ports(ssh)
    hidden_ports = proc_ports - ss_ports
    for port in sorted(hidden_ports):
        findings.append({
            "type":   "hidden_port",
            "port":   port,
            "detail": f"Port {port} in /proc/net/tcp but absent from ss",
        })

    # ── Suspicious files in temp dirs ────────────────────────────────────
    suspicious_dirs = "/tmp /dev/shm /var/tmp"
    # SUID files
    suid_raw = _exec(
        ssh,
        f"find {suspicious_dirs} -perm -4000 -type f 2>/dev/null"
    )
    for raw_line in suid_raw.strip().splitlines():
        fpath = raw_line.strip()
        if fpath:
            findings.append({
                "type":   "suspicious_suid",
                "path":   fpath,
                "detail": f"SUID binary in temp directory: {fpath}",
            })

    # Files with suspicious names (dot-prefixed executables, common backdoor names)
    backdoor_pattern = r"\.\w+sh$|\.x$|\.elf$|backdoor|rootkit|exploit|shell"
    names_raw = _exec(
        ssh,
        f"find {suspicious_dirs} -maxdepth 3 -type f 2>/dev/null"
    )
    for raw_line in names_raw.strip().splitlines():
        fpath = raw_line.strip()
        if fpath and re.search(backdoor_pattern, fpath, re.IGNORECASE):
            findings.append({
                "type":   "suspicious_file",
                "path":   fpath,
                "detail": f"Suspicious filename pattern in temp dir: {fpath}",
            })

    threat_count = len(findings)
    return {
        "module":       "fs_checker",
        "threat_count": threat_count,
        "findings":     findings,
        "summary": (
            f"{threat_count} filesystem anomaly/anomalies detected."
            if findings else "No filesystem anomalies detected."
        ),
    }


# ── Risk aggregator ───────────────────────────────────────────────────────────

def _compute_risk(total_threats: int) -> str:
    if total_threats >= RISK_INFECTED:
        return "infected"
    if total_threats >= RISK_SUSPICIOUS:
        return "suspicious"
    return "clean"


# ── Public API ────────────────────────────────────────────────────────────────

def remote_scan(host: str, password: str, user: str = "root",
                port: int = 22) -> dict:
    """
    Full remote scan: connect via SSH and run all three detection modules.
    Returns a unified result dict.
    """
    print(f"[*] Connecting to {user}@{host}:{port} …")
    try:
        ssh = connect(host, password, user=user, port=port)
    except Exception as exc:
        print(f"[!] SSH connection failed: {exc}")
        return {
            "status": "error",
            "error":  str(exc),
            "host":   host,
        }

    print("[*] Running process scan …")
    proc_result = _scan_hidden_processes(ssh)

    print("[*] Running syscall / kernel module scan …")
    sys_result = _scan_syscalls(ssh)

    print("[*] Running filesystem scan …")
    fs_result = _scan_filesystem(ssh)

    ssh.close()

    total_threats = (
        proc_result["threat_count"]
        + sys_result["threat_count"]
        + fs_result["threat_count"]
    )
    risk = _compute_risk(total_threats)

    return {
        "status":        "done",
        "host":          host,
        "risk_level":    risk,
        "total_threats": total_threats,
        "modules": {
            "process_scanner":   proc_result,
            "syscall_inspector": sys_result,
            "fs_checker":        fs_result,
        },
    }


# ── CLI entry point ───────────────────────────────────────────────────────────

def _print_result(result: dict) -> None:
    """Pretty-print a scan result to the terminal."""
    # ── Error case: SSH connection failed ────────────────────────────────
    if result.get("status") == "error":
        print("\n" + "=" * 60)
        print(f"  Host       : {result.get('host', 'N/A')}")
        print(f"  Risk level : \033[91mERROR\033[0m")
        print(f"  Reason     : {result.get('error', 'Unknown error')}")
        print("=" * 60)
        print()
        print("  Troubleshooting tips:")
        print("    • Check the IP is reachable:  ping", result.get('host','?'))
        print("    • Check SSH is running:        ssh <user>@<host>")
        print("    • Wrong username? pass --user ubuntu  (or kali, etc.)")
        print("    • Wrong password? double-check credentials")
        print("    • Firewall? make sure port 22 is open on the target")
        print()
        return

    risk = result.get("risk_level", "unknown").upper()
    colours = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m",
               "INFECTED": "\033[91m"}
    reset  = "\033[0m"
    colour = colours.get(risk, "")

    print("\n" + "=" * 60)
    print(f"  Host       : {result.get('host', 'N/A')}")
    print(f"  Risk level : {colour}{risk}{reset}")
    print(f"  Threats    : {result.get('total_threats', 0)}")
    print("=" * 60)

    modules = result.get("modules", {})
    for mod_name, mod in modules.items():
        icon = "✘" if mod["threat_count"] else "✔"
        print(f"\n  [{icon}] {mod_name}: {mod['summary']}")
        for finding in mod.get("findings", []):
            detail = finding.get("detail", "")
            pid    = finding.get("pid", "")
            path   = finding.get("path", "")
            port   = finding.get("port", "")
            label  = pid or path or port or ""
            print(f"       • {label}  {detail}")

    print()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(
        description="RootSentry — remote rootkit scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 modules/remote_scanner.py 192.168.25.54 Achraf123\n"
            "  python3 modules/remote_scanner.py 192.168.25.54 Achraf123 --user ubuntu\n"
            "  python3 modules/remote_scanner.py 192.168.25.54 Achraf123 --user kali --port 2222\n"
        ),
    )
    p.add_argument("host",     help="Target IP or hostname")
    p.add_argument("password", help="SSH password")
    p.add_argument("--user",   default="root",
                   help="SSH username (default: root). Try 'ubuntu' or 'kali' if root fails.")
    p.add_argument("--port",   type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--no-save", action="store_true", help="Don't save JSON output to disk")
    args = p.parse_args()

    result = remote_scan(args.host, args.password, user=args.user, port=args.port)
    _print_result(result)

    if not args.no_save and result.get("status") != "error":
        out_file = f"remote_scan_{args.host.replace('.', '_')}.json"
        try:
            with open(out_file, "w") as fh:
                json.dump(result, fh, indent=2)
            print(f"[*] Full results saved to {out_file}")
        except OSError as exc:
            print(f"[!] Could not save JSON: {exc}")
