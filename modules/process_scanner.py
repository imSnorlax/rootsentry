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
import time
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
    Iterate every possible PID and probe with os.stat() which calls stat(2)
    — NOT getdents64. Caraxes cannot hide from this.

    Performance optimisations:
    - Use os.stat() directly (slightly faster than os.path.exists)
    - Cap at min(pid_max, 32768) on VMs where pid_max may be 4M
    - Hard timeout: stop after 8 seconds to prevent scan stall
    """
    if pid_max is None:
        pid_max = _get_pid_max()
    # Cap: scanning beyond 32768 yields diminishing returns on typical systems
    # Real-world active PIDs are almost always < 32768
    cap = min(pid_max + 1, 32769)
    pids: Set[int] = set()
    deadline = time.monotonic() + 8.0   # hard 8-second timeout
    for pid in range(1, cap):
        if time.monotonic() > deadline:
            import logging
            logging.getLogger("rootsentry").warning(
                "_brute_force_pids: hit 8s deadline at PID %d (cap=%d)", pid, cap
            )
            break
        try:
            os.stat(f"/proc/{pid}")
            pids.add(pid)
        except (FileNotFoundError, ProcessLookupError):
            pass
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

    # Small delay then re-sample to discard transient spawn/exit processes
    # that appear hidden only because they died between our two reads.
    time.sleep(0.15)
    brute_pids2 = _brute_force_pids()
    proc_pids2  = _get_proc_pids()

    # Only use PIDs that were hidden in BOTH samples
    brute_pids  = brute_pids  & brute_pids2
    proc_pids   = proc_pids   | proc_pids2   # union: if it appeared at all it existed

    SKIP = {1, 2}   # PID 1 (init) and 2 (kthreadd) cause noisy false positives
    _KERNEL_PPIDS = {0, 2}  # Kernel threads have PPid 0 or 2

    # --- Category 1: Caraxes-type getdents64 hook ---
    hook_hidden = brute_pids - proc_pids - SKIP

    # --- Category 2: Classic ps-hiding rootkit ---
    ps_hidden = (proc_pids - ps_pids - psutil_pids) - SKIP

    findings: List[HiddenProcess] = []

    for pid in sorted(hook_hidden):
        status = _parse_status(pid)
        ppid   = int(status.get("PPid", "0") or "0")
        if ppid in _KERNEL_PPIDS:
            continue    # kernel thread — skip

        # Skip threads: Tgid != Pid means this is a thread, not a process.
        # stat("/proc/<tid>") succeeds for threads but os.listdir("/proc")
        # only returns process group leaders (where Tgid == Pid).
        try:
            tgid = int(status.get("Tgid", "0") or "0")
            if tgid != pid and tgid != 0:
                continue  # it's a thread, not a process
        except Exception:
            pass

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
        if ppid in _KERNEL_PPIDS:
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

    Method A: ls /proc | grep '^[0-9]'  — getdents64, may be filtered by rootkit
    Method B: ps -e -o pid=             — also filtered by some rootkits
    Method C: [ -d /proc/N ] in seq loop — stat(), NOT getdents64 (hook-resistant)

    Per-PID status/cmdline reads are BATCHED into single commands to avoid
    hitting SSH MaxSessions limits.
    """

    def _exec(cmd: str, timeout: int = 60) -> str:
        try:
            _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
            return stdout.read().decode(errors="replace")
        except Exception as exc:
            return ""

    # Run ALL 3 methods in ONE SSH call to eliminate timing-race false positives.
    # If each method is a separate exec_command, the bash process running method C
    # (brute-force) exists AFTER method A/B ran, so it appears in brute_pids but
    # not in proc_pids -> false "hidden process" finding.
    combined_cmd = (
        "echo ===PROC; "
        "ls /proc 2>/dev/null | grep -E '^[0-9]+$'; "
        "echo ===PS; "
        "ps -e -o pid= 2>/dev/null; "
        "echo ===BRUTE; "
        "for i in $(seq 1 32768); do [ -d /proc/$i ] && echo $i; done 2>/dev/null"
    )
    raw_all = _exec(combined_cmd, timeout=60)

    section = None
    proc_pids: set = set()
    ps_pids:   set = set()
    brute_pids: set = set()
    for line in raw_all.splitlines():
        line = line.strip()
        if line == "===PROC":  section = "proc"; continue
        if line == "===PS":    section = "ps";   continue
        if line == "===BRUTE": section = "brute"; continue
        if not line.isdigit(): continue
        pid = int(line)
        if section == "proc":  proc_pids.add(pid)
        elif section == "ps":  ps_pids.add(pid)
        elif section == "brute": brute_pids.add(pid)

    SKIP = {1, 2}
    hook_hidden = brute_pids - proc_pids - SKIP
    ps_hidden   = (proc_pids - ps_pids) - SKIP

    findings: List[HiddenProcess] = []

    # PERF FIX: batch all status reads for hook_hidden into ONE ssh call
    if hook_hidden:
        pids_str = " ".join(str(p) for p in sorted(hook_hidden))
        batch_status = _exec(
            f"for pid in {pids_str}; do "
            f"echo ===PID=$pid; "
            f"cat /proc/$pid/status 2>/dev/null; "
            f"echo ---CMD; "
            f"cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '; "
            f"echo; "
            f"done"
        )
        _parse_batch(batch_status, hook_hidden, findings,
                     reason_tmpl="INVISIBLE to getdents64 but EXISTS via stat() — "
                                 "ftrace/getdents64 hook detected (Caraxes-type rootkit). UID={uid}",
                     method="stat_brute_force")

    # PERF FIX: batch all status reads for ps_hidden into ONE ssh call
    remaining_ps = ps_hidden - {f.pid for f in findings if hasattr(f, 'pid')}
    remaining_ps = {p for p in remaining_ps if p not in hook_hidden}
    if remaining_ps:
        pids_str = " ".join(str(p) for p in sorted(remaining_ps))
        batch_status = _exec(
            f"for pid in {pids_str}; do "
            f"[ -d /proc/$pid ] || continue; "
            f"echo ===PID=$pid; "
            f"cat /proc/$pid/status 2>/dev/null; "
            f"echo ---CMD; "
            f"cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '; "
            f"echo; "
            f"done"
        )
        _parse_batch(batch_status, remaining_ps, findings,
                     reason_tmpl="Hidden from ps (remote) — name={{name}} ppid={{ppid}}",
                     method="proc_vs_ps")

    return _build_result(findings)


def _parse_batch(raw: str, pid_set: set, findings: list,
                 reason_tmpl: str, method: str) -> None:
    """Parse batched /proc/<pid>/status + cmdline output into findings."""
    current_pid = None
    status_lines: List[str] = []
    in_cmd = False
    cmdline = ""

    for line in raw.splitlines():
        if line.startswith("===PID="):
            # Flush previous
            if current_pid and status_lines:
                _emit_finding(current_pid, status_lines, cmdline,
                              reason_tmpl, method, findings)
            try:
                current_pid = int(line.split("===PID=")[1].strip())
            except (IndexError, ValueError):
                current_pid = None
            status_lines = []
            in_cmd = False
            cmdline = ""
        elif line == "---CMD":
            in_cmd = True
        elif in_cmd:
            cmdline += line + " "
        else:
            status_lines.append(line)

    # Flush last
    if current_pid and status_lines:
        _emit_finding(current_pid, status_lines, cmdline,
                      reason_tmpl, method, findings)


def _emit_finding(pid: int, status_lines: List[str], cmdline: str,
                  reason_tmpl: str, method: str, findings: list) -> None:
    ppid, name, uid, tgid, pid_val = 0, "?", "?", None, None
    for line in status_lines:
        if line.startswith("PPid:"):
            try: ppid = int(line.split()[1])
            except Exception: pass
        elif line.startswith("Name:"):
            parts = line.split(None, 1)
            name = parts[1].strip() if len(parts) > 1 else "?"
        elif line.startswith("Uid:"):
            parts = line.split()
            uid = parts[1] if len(parts) > 1 else "?"
        elif line.startswith("Tgid:"):
            try: tgid = int(line.split()[1])
            except Exception: pass
        elif line.startswith("Pid:"):
            try: pid_val = int(line.split()[1])
            except Exception: pass

    # CRITICAL: If Tgid != Pid, this entry is a THREAD not a process.
    # Linux stat("/proc/<tid>") succeeds for all threads, but ls /proc only
    # lists process group leaders (Tgid==Pid). Threads are NOT hidden processes.
    if tgid is not None and pid_val is not None and tgid != pid_val:
        return

    if ppid == 2:
        return  # kernel thread
    reason = reason_tmpl.format(uid=uid, name=name, ppid=ppid)
    findings.append(HiddenProcess(
        pid=pid,
        cmdline=cmdline.strip() or name or "(unknown)",
        status=f"Name={name} PPid={ppid} UID={uid}",
        reason=reason,
        detection_method=method,
    ))


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
