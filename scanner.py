"""
scanner.py — RootSentry main entry point
========================================
Runs all three detection modules (process_scanner, syscall_inspector,
fs_checker) either locally or against a remote host via SSH, then
aggregates the results into a risk level: clean / suspicious / infected.

Local scan:
    python3 scanner.py

Remote scan:
    python3 scanner.py --host 192.168.1.50 --password toor
    python3 scanner.py --host 192.168.1.50 --password toor --user root --port 22
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import os
import uuid
from typing import Optional

# ── Make sure the project root is on sys.path ─────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

# ── Internal modules ──────────────────────────────────────────────────────────
from modules.process_scanner  import scan_hidden_processes
from modules.syscall_inspector import scan_syscalls
from modules.fs_checker        import scan_filesystem

# ── Risk thresholds (mirrors config.py) ──────────────────────────────────────
RISK_CLEAN      = 0
RISK_SUSPICIOUS = 1   # 1–2 threats total
RISK_INFECTED   = 3   # 3+ threats total


# ── SSH connection helper ─────────────────────────────────────────────────────

def _open_ssh(host: str, password: str,
              user: str = "root", port: int = 22) -> "paramiko.SSHClient":
    try:
        import paramiko
    except ImportError:
        print("[!] paramiko is required for remote scans: pip install paramiko")
        sys.exit(1)

    print(f"[*] Connecting to {user}@{host}:{port} …")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host, port=port, username=user, password=password,
        timeout=10, allow_agent=False, look_for_keys=False,
    )
    return client


# ── Risk computation ──────────────────────────────────────────────────────────

def _compute_risk(total_threats: int) -> str:
    if total_threats >= RISK_INFECTED:
        return "infected"
    if total_threats > RISK_CLEAN:
        return "suspicious"
    return "clean"


# ── Pretty printer ────────────────────────────────────────────────────────────

COLOURS = {
    "clean":      "\033[92m",   # green
    "suspicious": "\033[93m",   # yellow
    "infected":   "\033[91m",   # red
}
RESET = "\033[0m"


def _print_result(result: dict) -> None:
    risk   = result["risk_level"]
    colour = COLOURS.get(risk, "")
    total  = result["total_threats"]

    print("\n" + "═" * 62)
    print(f"  {'RootSentry Scan Report':^58}")
    print("═" * 62)
    target = result.get("host", "localhost")
    print(f"  Target     : {target}")
    print(f"  Risk level : {colour}{risk.upper()}{RESET}")
    print(f"  Total threats : {total}")
    print("─" * 62)

    for mod_name, mod in result["modules"].items():
        icon = "✘" if mod["threat_count"] else "✔"
        print(f"\n  [{icon}] {mod_name}  —  {mod['summary']}")
        for finding in mod.get("findings", []):
            detail = finding.get("detail", "")
            label  = (
                finding.get("pid")
                or finding.get("path")
                or finding.get("port")
                or finding.get("module")
                or finding.get("symbol")
                or ""
            )
            print(f"        • {label}  {detail}")

    print("\n" + "═" * 62 + "\n")


# ── Core scan runner ──────────────────────────────────────────────────────────

def run_scan(host: Optional[str] = None, password: Optional[str] = None,
             user: str = "root", port: int = 22,
             progress_cb=None) -> dict:
    """
    Execute all three detection modules.
    If host/password are provided the scan runs remotely over SSH,
    otherwise it runs locally (requires root on Linux).

    progress_cb: optional callable(step: str) invoked before each phase so
                 callers (e.g. the web dashboard) can report real progress.
                 Step values: 'process_scanner', 'syscall_inspector',
                              'fs_checker', 'aggregating'.
    """
    def _cb(step: str):
        if progress_cb:
            try:
                progress_cb(step)
            except Exception:
                pass

    ssh = None
    if host and password:
        ssh = _open_ssh(host, password, user=user, port=port)

    _cb("process_scanner")
    print("[*] Scanning processes …")
    proc_result = scan_hidden_processes(ssh_client=ssh)

    _cb("syscall_inspector")
    print("[*] Scanning kernel syscalls / modules …")
    sys_result  = scan_syscalls(ssh_client=ssh)

    _cb("fs_checker")
    print("[*] Scanning filesystem …")
    fs_result   = scan_filesystem(ssh_client=ssh)

    if ssh:
        ssh.close()

    _cb("aggregating")
    total_threats = (
        proc_result["threat_count"]
        + sys_result["threat_count"]
        + fs_result["threat_count"]
    )
    risk = _compute_risk(total_threats)

    result = {
        "status":        "done",
        "host":          host or "localhost",
        "risk_level":    risk,
        "total_threats": total_threats,
        "timestamp":     datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "modules": {
            "process_scanner":   proc_result,
            "syscall_inspector": sys_result,
            "fs_checker":        fs_result,
        },
    }

    # ── Persist to scans/ so the web dashboard can load it ──────────────────
    from config import SCANS_DIR
    os.makedirs(SCANS_DIR, exist_ok=True)
    scan_id = str(uuid.uuid4())[:8]
    result["id"] = scan_id
    scan_file = os.path.join(SCANS_DIR, f"{scan_id}.json")
    try:
        with open(scan_file, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[*] Scan saved to {scan_file}")
    except OSError as exc:
        print(f"[!] Could not save scan: {exc}", file=sys.stderr)

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="RootSentry — Linux rootkit detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 scanner.py                               # local scan\n"
            "  python3 scanner.py --host 192.168.1.50 "
            "--password toor          # remote scan\n"
        ),
    )
    p.add_argument("--host",     help="Remote host IP or hostname")
    p.add_argument("--password", help="SSH password")
    p.add_argument("--user",     default="root", help="SSH user (default: root)")
    p.add_argument("--port",     type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--json",     action="store_true",
                   help="Print raw JSON result to stdout")
    p.add_argument("--output",   metavar="FILE",
                   help="Save JSON result to FILE")
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # Validate: remote scan needs both host AND password
    if bool(args.host) != bool(args.password):
        parser.error("--host and --password must be used together")

    result = run_scan(
        host=args.host,
        password=args.password,
        user=args.user,
        port=args.port,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_result(result)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                json.dump(result, fh, indent=2)
            print(f"[*] Results saved to {args.output}")
        except OSError as exc:
            print(f"[!] Could not save file: {exc}", file=sys.stderr)

    # Exit code reflects risk level
    exit_codes = {"clean": 0, "suspicious": 1, "infected": 2}
    sys.exit(exit_codes.get(result["risk_level"], 3))


if __name__ == "__main__":
    main()
