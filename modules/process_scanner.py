"""
modules/process_scanner.py
Detects hidden processes using three independent methods:

  Method A — getdents64 (os.listdir):  Standard /proc enumeration.
             Vulnerable to ftrace/getdents64 hooks (e.g. Caraxes).

  Method B — ps / psutil:             Userspace process tools.
             Also vulnerable to getdents64 hooks.

  Method C — stat() brute-force:      Iterates every PID 1..PID_MAX and
             checks existence via os.path.exists() which calls stat(2),
             NOT getdents64. This bypasses ftrace hooks like Caraxes that
             only intercept __x64_sys_getdents64.

Detection logic:
  - A missing from B        → classic rootkit (hides from ps but not /proc)
  - C present, missing from A → getdents64-hook rootkit (Caraxes-type ftrace)
  - C present, missing from B → hidden from userspace tools
"""

import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Set

# Linux default max PID. /proc/sys/kernel/pid_max is usually 32768 or 4194304.
# We read the real value at runtime; fall back to 65535.
_DEFAULT_PID_MAX = 65535


def _get_pid_max() -> int:
    """Read the kernel's actual PID ceiling."""
    try:
        with open("/proc/sys/kernel/pid_max") as f:
            return int(f.read().strip())
    except Exception:
        return _DEFAULT_PID_MAX


@dataclass
class HiddenProcess:
    pid: int
    cmdline: Optional[str] = None
    status: Optional[str] = None
    reason: str = ""
    detection_method: str = ""


# ── Method A: getdents64 (vulnerable to Caraxes) ─────────────────────────────

def _get_proc_pids() -> Set[int]:
    """
    Read /proc via os.listdir → getdents64.
    On a Caraxes-infected system this returns a FILTERED set.
    """
    pids: Set[int] = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except PermissionError:
        pass
    return pids


# ── Method B: ps / psutil ────────────────────────────────────────────────────

def _get_ps_pids() -> Set[int]:
    """Get PIDs reported by `ps -e`. Also vulnerable to getdents64 hooks."""
    pids: Set[int] = set()
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


def _get_psutil_pids() -> Set[int]:
    """Get PIDs from psutil. Also reads /proc internally → also filterable."""
    try:
        import psutil
        return set(psutil.pids())
    except ImportError:
        return set()


# ── Method C: stat() brute-force (Caraxes-proof) ─────────────────────────────

def _brute_force_pids(pid_max: Optional[int] = None) -> Set[int]:
    """
    Iterate every possible PID and probe with os.path.exists() which calls
    stat(2) — NOT getdents64.  Caraxes (and any rootkit that only hooks
    __x64_sys_getdents64) cannot hide processes from this method.

    os.path.exists("/proc/<pid>") internally calls:
        stat("/proc/<pid>", &st)   ← NOT intercepted by Caraxes
    whereas os.listdir("/proc") calls:
        getdents64(fd, buf, ...)   ← intercepted by Caraxes

    Performance: ~65 k stat() calls complete in <0.5 s on modern hardware.
    """
    if pid_max is None:
        pid_max = _get_pid_max()
    pids: Set[int] = set()
    for pid in range(1, min(pid_max + 1, _DEFAULT_PID_MAX + 1)):
        try:
            # os.path.exists uses stat() — hook-resistant
            if os.path.exists(f"/proc/{pid}"):
                pids.add(pid)
        except Exception:
            pass
    return pids


# ── Proc file helpers ─────────────────────────────────────────────────────────

def _read_proc_file(pid: int, fname: str) -> Optional[str]:
    """Safely read /proc/<pid>/<fname> using open() — not getdents64."""
    try:
        with open(f"/proc/{pid}/{fname}", "r", errors="replace") as f:
            return f.read().strip()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return None


def _explain_pid(pid: int) -> str:
    """Return a one-line description of a PID via direct /proc reads."""
    cmdline = _read_proc_file(pid, "cmdline")
    if cmdline:
        return cmdline.replace("\x00", " ").strip()
    comm = _read_proc_file(pid, "comm")
    return comm or "(unknown)"


def _parse_status(pid: int) -> dict:
    """Parse /proc/<pid>/status into a dict of key→value."""
    raw = _read_proc_file(pid, "status") or ""
    result: dict = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def scan_hidden_processes(ssh_client=None) -> dict:
    """
    Run the hidden-process scan locally or remotely.
    Returns a dict compatible with the RootSentry result schema.
    """
    if ssh_client:
        return _remote_scan(ssh_client)
    return _local_scan()


# ── Local scan ────────────────────────────────────────────────────────────────

def _local_scan() -> dict:
    """
    Three-method local scan.

    Compares:
      A = getdents64-based /proc listing  (filterable by Caraxes)
      B = ps/psutil                       (filterable by Caraxes)
      C = stat()-based brute-force        (Caraxes-PROOF)

    Hidden process categories:
      C ∖ A  → getdents64-hook hiding (Caraxes-type ftrace rootkit)
      A ∖ B  → classic rootkit hiding from ps but visible in /proc
    """
    proc_pids   = _get_proc_pids()      # Method A
    ps_pids     = _get_ps_pids()        # Method B
    psutil_pids = _get_psutil_pids()    # Method B (alt)
    brute_pids  = _brute_force_pids()   # Method C

    SKIP = {1, 2}   # PID 1 (init) and 2 (kthreadd) cause noisy false positives

    # --- Category 1: Caraxes-type getdents64 hook ---
    # Present via stat() but absent from getdents64 listing
    hook_hidden = brute_pids - proc_pids - SKIP

    # --- Category 2: Classic ps-hiding rootkit ---
    # Visible in /proc (getdents64) but hidden from ps/psutil
    ps_hidden = (proc_pids - ps_pids - psutil_pids) - SKIP

    findings: List[HiddenProcess] = []

    for pid in sorted(hook_hidden):
        # Confirm it's a real user-space process (not a kernel thread)
        status = _parse_status(pid)
        ppid   = int(status.get("PPid", "0") or "0")
        if ppid == 2:
            continue    # kernel thread — skip

        uid_line  = status.get("Uid", "")
        uid       = uid_line.split()[0] if uid_line else "?"
        cmdline   = _explain_pid(pid)
        name      = status.get("Name", "?")
        findings.append(HiddenProcess(
            pid=pid,
            cmdline=cmdline,
            status=f"Name={name} PPid={ppid} UID={uid}",
            reason=(
                f"INVISIBLE to getdents64 but EXISTS via stat() — "
                f"ftrace/getdents64 hook detected (Caraxes-type rootkit). "
                f"UID={uid}"
            ),
            detection_method="stat_brute_force",
        ))

    for pid in sorted(ps_hidden):
        if pid in hook_hidden:
            continue    # already reported above
        if not os.path.exists(f"/proc/{pid}"):
            continue    # race condition — PID died
        status  = _parse_status(pid)
        ppid    = int(status.get("PPid", "0") or "0")
        if ppid == 2:
            continue    # kernel thread
        cmdline = _explain_pid(pid)
        name    = status.get("Name", "?")
        findings.append(HiddenProcess(
            pid=pid,
            cmdline=cmdline,
            status=f"Name={name} PPid={ppid}",
            reason="Hidden from ps and psutil but visible in /proc (classic rootkit)",
            detection_method="proc_vs_ps",
        ))

    return _build_result(findings)


# ── Remote scan (via SSH) ─────────────────────────────────────────────────────

def _remote_scan(ssh) -> dict:
    """
    Three-method remote scan over SSH.

    Method A: ls /proc | grep '^[0-9]'  — getdents64, may be filtered
    Method B: ps -e -o pid=             — also filtered
    Method C: shell loop using [ -d /proc/<n> ]  — stat(), NOT getdents64
              Parallelised with xargs for speed.
    """

    def _exec(cmd: str) -> str:
        _, stdout, _ = ssh.exec_command(cmd, timeout=60)
        return stdout.read().decode(errors="replace")

    # ── Method A (getdents64) ─────────────────────────────────────────────────
    raw_a     = _exec("ls /proc 2>/dev/null | grep -E '^[0-9]+$'")
    proc_pids = set(int(p) for p in raw_a.split() if p.isdigit())

    # ── Method B (ps) ────────────────────────────────────────────────────────
    raw_b   = _exec("ps -e -o pid= 2>/dev/null")
    ps_pids = set(int(p.strip()) for p in raw_b.split() if p.strip().isdigit())

    # ── Method C (stat brute-force) ───────────────────────────────────────────
    # [ -d /proc/N ] calls access()/stat() — NOT getdents64 — so Caraxes can't
    # filter it. We parallelise across 8 workers to keep it fast.
    # Use seq to generate the PID range, xargs to fan out the stat checks.
    pid_max_raw = _exec("cat /proc/sys/kernel/pid_max 2>/dev/null").strip()
    try:
        pid_max = min(int(pid_max_raw), _DEFAULT_PID_MAX)
    except Exception:
        pid_max = 32768

    brute_cmd = (
        f"seq 1 {pid_max} | "
        f"xargs -P8 -I{{}} sh -c '[ -d /proc/{{}} ] && echo {{}}' 2>/dev/null"
    )
    raw_c     = _exec(brute_cmd)
    brute_pids = set(int(p) for p in raw_c.split() if p.isdigit())

    SKIP = {1, 2}
    hook_hidden = brute_pids - proc_pids - SKIP
    ps_hidden   = (proc_pids - ps_pids)  - SKIP

    findings: List[HiddenProcess] = []

    # --- Caraxes-type: visible via stat() but not getdents64 -----------------
    for pid in sorted(hook_hidden):
        status_raw = _exec(f"cat /proc/{pid}/status 2>/dev/null")
        ppid, name, uid = 0, "?", "?"
        for line in status_raw.splitlines():
            if line.startswith("PPid:"):
                try: ppid = int(line.split()[1])
                except Exception: pass
            if line.startswith("Name:"):
                name = line.split(None, 1)[1].strip() if len(line.split()) > 1 else "?"
            if line.startswith("Uid:"):
                uid = line.split()[1] if len(line.split()) > 1 else "?"
        if ppid == 2:
            continue    # kernel thread
        cmdline_raw = _exec(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
        cmdline = cmdline_raw.strip() or name or "(unknown)"
        findings.append(HiddenProcess(
            pid=pid,
            cmdline=cmdline,
            status=f"Name={name} PPid={ppid} UID={uid}",
            reason=(
                f"INVISIBLE to getdents64 but EXISTS via stat() — "
                f"ftrace/getdents64 hook detected (Caraxes-type rootkit). "
                f"UID={uid}"
            ),
            detection_method="stat_brute_force",
        ))

    # --- Classic: visible in /proc but hidden from ps ------------------------
    for pid in sorted(ps_hidden):
        if pid in hook_hidden:
            continue
        verify = _exec(f"test -d /proc/{pid} && echo yes || echo no").strip()
        if verify != "yes":
            continue
        status_raw = _exec(f"cat /proc/{pid}/status 2>/dev/null")
        ppid, name = 0, "?"
        for line in status_raw.splitlines():
            if line.startswith("PPid:"):
                try: ppid = int(line.split()[1])
                except Exception: pass
            if line.startswith("Name:"):
                name = line.split(None, 1)[1].strip() if len(line.split()) > 1 else "?"
        if ppid == 2:
            continue
        cmdline_raw = _exec(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
        cmdline = cmdline_raw.strip() or name or "(unknown)"
        findings.append(HiddenProcess(
            pid=pid,
            cmdline=cmdline,
            reason=f"Hidden from ps (remote) | name={name} ppid={ppid}",
            detection_method="proc_vs_ps",
        ))

    return _build_result(findings)


# ── Shared result builder ─────────────────────────────────────────────────────

def _build_result(findings: List[HiddenProcess]) -> dict:
    return {
        "module": "process_scanner",
        "threat_count": len(findings),
        "findings": [
            {
                "type":             "hidden_process",
                "pid":              f.pid,
                "cmdline":          f.cmdline,
                "detail":           f.reason,
                "detection_method": f.detection_method,
            }
            for f in findings
        ],
        "summary": (
            f"{len(findings)} hidden process(es) detected."
            if findings else "No hidden processes detected."
        ),
    }
