"""
modules/process_scanner.py
Detects hidden processes by comparing /proc entries against psutil and
the output of `ps`, then cross-referencing with common rootkit signals.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HiddenProcess:
    pid: int
    cmdline: Optional[str] = None
    status: Optional[str] = None
    reason: str = ""


def _get_proc_pids() -> set:
    """Read every numeric entry from /proc to get all visible PIDs."""
    pids = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except PermissionError:
        pass
    return pids


def _get_ps_pids() -> set:
    """Get PIDs reported by `ps aux`."""
    pids = set()
    try:
        result = subprocess.run(
            ["ps", "-e", "-o", "pid="],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line.isdigit():
                pids.add(int(line))
    except Exception:
        pass
    return pids


def _get_psutil_pids() -> set:
    """Get PIDs from psutil (reads /proc internally but via different path)."""
    try:
        import psutil
        return set(psutil.pids())
    except ImportError:
        return set()


def _read_proc_file(pid: int, fname: str) -> Optional[str]:
    """Safely read a single /proc/<pid>/<fname> file."""
    try:
        path = f"/proc/{pid}/{fname}"
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return None


def _explain_pid(pid: int) -> str:
    """Return a one-line explanation of what a PID looks like."""
    cmdline = _read_proc_file(pid, "cmdline")
    if cmdline:
        # cmdline is NUL-separated
        return cmdline.replace("\x00", " ").strip()
    comm = _read_proc_file(pid, "comm")
    return comm or "(unknown)"


def scan_hidden_processes(ssh_client=None) -> dict:
    """
    Run the hidden-process scan.

    If ssh_client is provided the scan runs on the remote host.
    Returns a dict compatible with the rest of the RootSentry result schema.
    """
    if ssh_client:
        return _remote_scan(ssh_client)
    return _local_scan()


# ── Local scan ───────────────────────────────────────────────────────────────

def _local_scan() -> dict:
    proc_pids   = _get_proc_pids()
    ps_pids     = _get_ps_pids()
    psutil_pids = _get_psutil_pids()

    # Processes visible in /proc but NOT in ps/psutil → rootkit hidden
    hidden_by_ps     = proc_pids - ps_pids     - {1, 2}   # ignore PID 1/2 differences
    hidden_by_psutil = proc_pids - psutil_pids - {1, 2}
    candidate_pids   = hidden_by_ps | hidden_by_psutil

    findings: List[HiddenProcess] = []
    for pid in sorted(candidate_pids):
        # Verify the PID still exists
        if not os.path.exists(f"/proc/{pid}"):
            continue
        reason_parts = []
        if pid in hidden_by_ps:
            reason_parts.append("hidden from ps")
        if pid in hidden_by_psutil:
            reason_parts.append("hidden from psutil")
        cmdline = _explain_pid(pid)
        status  = _read_proc_file(pid, "status")
        findings.append(HiddenProcess(
            pid=pid,
            cmdline=cmdline,
            status=status,
            reason=", ".join(reason_parts),
        ))

    return _build_result(findings)


# ── Remote scan (via SSH) ────────────────────────────────────────────────────

def _remote_scan(ssh) -> dict:
    """
    Run a lightweight hidden-process check on the remote host.
    We compare /proc PIDs against `ps -e` output over SSH.
    """
    # Get /proc pids
    _, stdout, _ = ssh.exec_command(
        "ls /proc | grep -E '^[0-9]+$'"
    )
    proc_pids = set(
        int(p) for p in stdout.read().decode().split() if p.isdigit()
    )

    # Get ps pids
    _, stdout, _ = ssh.exec_command("ps -e -o pid=")
    ps_pids = set(
        int(p.strip()) for p in stdout.read().decode().split()
        if p.strip().isdigit()
    )

    hidden = sorted(proc_pids - ps_pids - {1, 2})

    findings = []
    for pid in hidden:
        # Try to read cmdline
        _, stdout, _ = ssh.exec_command(
            f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '"
        )
        cmdline = stdout.read().decode().strip() or "(unknown)"
        findings.append(HiddenProcess(pid=pid, cmdline=cmdline,
                                      reason="hidden from ps (remote)"))

    return _build_result(findings)


# ── Shared result builder ────────────────────────────────────────────────────

def _build_result(findings: List[HiddenProcess]) -> dict:
    return {
        "module": "process_scanner",
        "threat_count": len(findings),
        "findings": [
            {
                "pid":     f.pid,
                "cmdline": f.cmdline,
                "reason":  f.reason,
            }
            for f in findings
        ],
        "summary": (
            f"{len(findings)} hidden process(es) detected."
            if findings else "No hidden processes detected."
        ),
    }
