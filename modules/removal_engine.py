"""
modules/removal_engine.py
RootSentry — Removal / Remediation Engine
==========================================
Provides three remediation actions:
  1. kill_process(pid)        — send SIGKILL to a hidden process
  2. unload_module(name)      — rmmod a suspected rootkit kernel module
  3. clean_file(path)         — remove a suspicious file from the filesystem

All actions are logged to an in-memory action log and returned in the
remediation report so the caller / dashboard can display them.

Remote (SSH) variants are supported by passing an ssh_client object.
"""

from __future__ import annotations

import os
import signal
import subprocess
import datetime
from typing import Optional

# ── Action log ────────────────────────────────────────────────────────────────

_action_log: list[dict] = []


def _log(action: str, target: str, success: bool, detail: str = "") -> dict:
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "action":    action,
        "target":    target,
        "success":   success,
        "detail":    detail,
    }
    _action_log.append(entry)
    return entry


def get_action_log() -> list[dict]:
    """Return a copy of the action log."""
    return list(_action_log)


def clear_action_log() -> None:
    _action_log.clear()


# ── Process kill ──────────────────────────────────────────────────────────────

def kill_process(pid: int, ssh_client=None) -> dict:
    """
    Send SIGKILL to the given PID.
    Returns an action-log entry dict.
    """
    if ssh_client:
        _, stdout, stderr = ssh_client.exec_command(f"kill -9 {pid}")
        err = stderr.read().decode().strip()
        ok  = not err
        return _log("kill_process", str(pid), ok,
                    f"SSH kill -9 {pid}" + (f" — {err}" if err else " — OK"))
    else:
        try:
            os.kill(pid, signal.SIGKILL)
            return _log("kill_process", str(pid), True, f"SIGKILL sent to PID {pid}")
        except ProcessLookupError:
            return _log("kill_process", str(pid), False, f"PID {pid} not found")
        except PermissionError:
            return _log("kill_process", str(pid), False,
                        f"Permission denied killing PID {pid} — run as root")
        except Exception as exc:
            return _log("kill_process", str(pid), False, str(exc))


# ── Kernel module unload ──────────────────────────────────────────────────────

def unload_module(module_name: str, ssh_client=None) -> dict:
    """
    Attempt to unload a kernel module with `rmmod`.
    Returns an action-log entry dict.
    """
    cmd = ["rmmod", module_name]
    if ssh_client:
        _, stdout, stderr = ssh_client.exec_command(f"rmmod {module_name}")
        err = stderr.read().decode().strip()
        ok  = not err
        return _log("unload_module", module_name, ok,
                    f"SSH rmmod {module_name}" + (f" — {err}" if err else " — OK"))
    else:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            ok  = result.returncode == 0
            msg = result.stderr.strip() or "OK"
            return _log("unload_module", module_name, ok, msg)
        except FileNotFoundError:
            return _log("unload_module", module_name, False,
                        "rmmod not found — are you on Linux?")
        except Exception as exc:
            return _log("unload_module", module_name, False, str(exc))


# ── File removal ──────────────────────────────────────────────────────────────

def clean_file(path: str, ssh_client=None) -> dict:
    """
    Delete a suspicious file from the filesystem.
    Returns an action-log entry dict.
    """
    if ssh_client:
        _, stdout, stderr = ssh_client.exec_command(f"rm -f -- {path!r}")
        err = stderr.read().decode().strip()
        ok  = not err
        return _log("clean_file", path, ok,
                    f"SSH rm -f {path}" + (f" — {err}" if err else " — OK"))
    else:
        try:
            os.remove(path)
            return _log("clean_file", path, True, f"Deleted {path}")
        except FileNotFoundError:
            return _log("clean_file", path, False, f"File not found: {path}")
        except PermissionError:
            return _log("clean_file", path, False,
                        f"Permission denied removing {path} — run as root")
        except Exception as exc:
            return _log("clean_file", path, False, str(exc))


# ── Batch remediation ─────────────────────────────────────────────────────────

def remediate_scan(scan_result: dict, ssh_client=None,
                   kill_procs: bool = True,
                   unload_mods: bool = True,
                   clean_files: bool = True) -> dict:
    """
    Given a full scan_result dict (from scanner.py / remote_scanner.py),
    automatically remediate all detected threats.

    Returns a remediation report dict.
    """
    actions: list[dict] = []

    modules = scan_result.get("modules", {})

    # ── Kill hidden processes ──────────────────────────────────────────────
    if kill_procs:
        proc_mod = modules.get("process_scanner", {})
        for finding in proc_mod.get("findings", []):
            pid = finding.get("pid")
            if pid:
                actions.append(kill_process(int(pid), ssh_client))

    # ── Unload rootkit kernel modules ──────────────────────────────────────
    if unload_mods:
        sys_mod = modules.get("syscall_inspector", {})
        for finding in sys_mod.get("findings", []):
            if finding.get("type") == "rootkit_module":
                mod_name = finding.get("module")
                if mod_name:
                    actions.append(unload_module(mod_name, ssh_client))

    # ── Remove suspicious files ────────────────────────────────────────────
    if clean_files:
        fs_mod = modules.get("fs_checker", {})
        for finding in fs_mod.get("findings", []):
            ftype = finding.get("type", "")
            path  = finding.get("path")
            if path and ftype in ("suspicious_suid", "world_writable",
                                  "suspicious_file", "rootkit_path"):
                actions.append(clean_file(path, ssh_client))

    succeeded = sum(1 for a in actions if a["success"])
    failed    = len(actions) - succeeded

    return {
        "status":    "done",
        "host":      scan_result.get("host", "localhost"),
        "actions":   actions,
        "succeeded": succeeded,
        "failed":    failed,
        "summary":   (
            f"Remediation complete: {succeeded} action(s) succeeded, "
            f"{failed} failed."
        ),
    }
