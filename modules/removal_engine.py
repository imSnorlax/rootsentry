"""
modules/removal_engine.py
RootSentry — Aggressive Removal / Remediation Engine
=====================================================
Multi-stage rootkit removal:

  Stage 0  — Proactive blind rmmod on ALL known rootkits
  Stage 0.5 — Kill rootkit processes by NAME (catches respawned PIDs)
  Stage 1  — Kill processes   : SIGKILL by PID, and fuser -k by port
  Stage 2  — Block ports      : iptables DROP on hidden ports
  Stage 3  — Unload modules   : rmmod / modprobe -r / rmmod -f (force)
  Stage 4  — Delete files     : rm -f suspicious binaries / SUID / rootkit files
  Stage 5  — Clean persistence: crontabs, systemd units, rc.local, /etc/modules
  Stage 6  — Hunt and delete rootkit .ko files from disk

All actions are logged and returned in the remediation report.
"""

from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import datetime
import threading
from typing import Optional

# ── Per-call action log ───────────────────────────────────────────────────────

def _make_entry(action: str, target: str, success: bool, detail: str = "") -> dict:
    return {
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "action":    action,
        "target":    target,
        "success":   success,
        "detail":    detail,
    }


# ── Legacy compat shims ────────────────────────────────────────────────────────
_action_log: list[dict] = []
_log_lock = threading.Lock()


def _log(action: str, target: str, success: bool, detail: str = "") -> dict:
    """Deprecated global log — kept for external callers only."""
    entry = _make_entry(action, target, success, detail)
    with _log_lock:
        _action_log.append(entry)
    return entry


def get_action_log() -> list[dict]:
    with _log_lock:
        return list(_action_log)


def clear_action_log() -> None:
    with _log_lock:
        _action_log.clear()


# ── SSH helper ────────────────────────────────────────────────────────────────

def _exec(ssh, cmd: str) -> tuple[bool, str]:
    try:
        _, stdout, stderr = ssh.exec_command(cmd, timeout=30)
        out      = stdout.read().decode(errors="replace").strip()
        err      = stderr.read().decode(errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()
        combined  = out or err
        return (exit_code == 0, combined)
    except Exception as exc:
        return False, str(exc)


def _run_local(cmd: str) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, (r.stderr.strip() or r.stdout.strip())
    except Exception as exc:
        return False, str(exc)


def _run(ssh, cmd: str) -> tuple[bool, str]:
    return _exec(ssh, cmd) if ssh else _run_local(cmd)


# ── Stage 1: Kill processes ───────────────────────────────────────────────────

def kill_process(pid: int, ssh=None) -> dict:
    pid = int(pid)
    if ssh:
        ok, detail = _exec(ssh, f"kill -9 {pid} 2>&1")
        return _make_entry("kill_process", str(pid), ok, f"kill -9 {pid}: {detail or 'OK'}")
    else:
        try:
            os.kill(pid, signal.SIGKILL)
            return _make_entry("kill_process", str(pid), True, f"SIGKILL → PID {pid}")
        except ProcessLookupError:
            return _make_entry("kill_process", str(pid), False, f"PID {pid} not found")
        except PermissionError:
            return _make_entry("kill_process", str(pid), False, "Permission denied (need root)")
        except Exception as exc:
            return _make_entry("kill_process", str(pid), False, str(exc))


def kill_port_process(port: int, ssh=None) -> dict:
    cmd = f"fuser -k -n tcp {port} 2>&1; fuser -k -n udp {port} 2>&1; true"
    ok, detail = _run(ssh, cmd)
    return _make_entry("kill_port_process", str(port),
                       ok, f"fuser -k port {port}: {detail or 'OK'}")


def _block_port_iptables(port: int, ssh=None) -> dict:
    cmds = [
        f"iptables -A INPUT  -p tcp --dport {port} -j DROP 2>&1",
        f"iptables -A OUTPUT -p tcp --sport {port} -j DROP 2>&1",
        f"iptables -A INPUT  -p udp --dport {port} -j DROP 2>&1",
        f"iptables -A OUTPUT -p udp --sport {port} -j DROP 2>&1",
    ]
    details  = []
    all_ok   = True
    for c in cmds:
        ok, d = _run(ssh, c)
        if not ok:
            all_ok = False
        if d:
            details.append(d)
    return _make_entry("block_port_iptables", str(port), all_ok,
                       f"iptables DROP rules added for port {port}" +
                       (f" | {'; '.join(details)}" if details else ""))


# ── Stage 2: Unload kernel modules ───────────────────────────────────────────

def unload_module(module_name: str, ssh=None) -> dict:
    results  = []
    ok = ok2 = ok3 = False

    ok, out = _run(ssh, f"rmmod {shlex.quote(module_name)} 2>&1")
    if ok:
        results.append("rmmod OK")
    else:
        results.append(f"rmmod failed: {out}")
        ok2, out2 = _run(ssh, f"modprobe -r {shlex.quote(module_name)} 2>&1")
        if ok2:
            results.append("modprobe -r OK")
        else:
            results.append(f"modprobe -r: {out2}")
            ok3, out3 = _run(ssh, f"rmmod --force {shlex.quote(module_name)} 2>&1")
            results.append("rmmod --force OK" if ok3 else f"rmmod --force: {out3}")

    safe_pattern = re.escape(module_name)
    persist_cmd = (
        f"sed -i '\\|{safe_pattern}|d' /etc/modules 2>/dev/null; "
        f"rm -f /etc/modules-load.d/{shlex.quote(module_name + '.conf')} 2>/dev/null; true"
    )
    _run(ssh, persist_cmd)
    results.append("persistence cleaned")

    still_there_ok, still_there_out = _run(
        ssh, f"grep -qw {shlex.quote(module_name)} /proc/modules 2>/dev/null && echo LOADED || echo GONE"
    )
    if "LOADED" in still_there_out:
        results.append("WARNING: module still in /proc/modules — reboot required")
        overall_ok = False
    else:
        overall_ok = ok or ok2 or ok3

    detail = " | ".join(results)
    return _make_entry("unload_module", module_name, overall_ok, detail)


# ── Stage 3: Remove files ─────────────────────────────────────────────────────

def clean_file(path: str, ssh=None) -> dict:
    quoted = shlex.quote(path)
    cmd    = f"chattr -i {quoted} 2>/dev/null; rm -f -- {quoted} 2>&1"
    ok, detail = _run(ssh, cmd)
    return _make_entry("clean_file", path, ok, detail or f"Deleted {path}")


# ── Stage 4: Persistence cleanup ─────────────────────────────────────────────

def _clean_persistence(ssh=None, known_rootkits: list[str] | None = None) -> list[dict]:
    """
    Bug fix: all entries now use _make_entry() (not global _log()),
    collected into a LOCAL list to prevent concurrent remediation bleed.
    """
    if known_rootkits is None:
        from config import KNOWN_ROOTKITS
        known_rootkits = KNOWN_ROOTKITS

    actions = []
    pattern = "|".join(known_rootkits)

    # Crontabs (root + all users)
    cmd = (
        f"for user in root $(cut -f1 -d: /etc/passwd); do "
        f"  crontab -u $user -l 2>/dev/null | grep -Ei '{pattern}' && "
        f"  crontab -u $user -r 2>/dev/null && echo \"Cleared crontab for $user\"; "
        f"done; true"
    )
    ok, out = _run(ssh, cmd)
    if out:
        actions.append(_make_entry("clean_crontab", "crontab", ok, out[:200]))

    # Systemd units
    cmd2 = (
        f"grep -rl '{pattern}' /etc/systemd /lib/systemd /usr/lib/systemd 2>/dev/null | "
        f"xargs -I{{}} sh -c 'systemctl disable --now $(basename {{}} .service) 2>/dev/null; rm -f {{}}'; true"
    )
    ok2, out2 = _run(ssh, cmd2)
    if out2:
        actions.append(_make_entry("clean_systemd", "systemd units", ok2, out2[:200]))

    # rc.local
    cmd3 = (
        f"grep -Ei '{pattern}' /etc/rc.local 2>/dev/null && "
        f"sed -iE 's/.*({pattern}).*//g' /etc/rc.local 2>/dev/null; true"
    )
    ok3, out3 = _run(ssh, cmd3)
    if out3:
        actions.append(_make_entry("clean_rclocal", "/etc/rc.local", ok3, out3[:200]))

    # Suspicious dropper files in temp dirs
    cmd4 = (
        f"find /tmp /dev/shm /var/tmp -type f \\( "
        f"-perm -4000 -o -name '*.sh' -o -name '*.elf' -o -name '*.so' \\) 2>/dev/null | "
        f"xargs -I{{}} sh -c 'chattr -i {{}} 2>/dev/null; rm -f {{}} && echo \"Deleted: {{}}\"'; true"
    )
    ok4, out4 = _run(ssh, cmd4)
    if out4:
        actions.append(_make_entry("clean_dropper_files", "/tmp /dev/shm /var/tmp", ok4, out4[:300]))

    # /etc/ld.so.preload (common rootkit injection vector)
    cmd5 = (
        f"if [ -f /etc/ld.so.preload ]; then "
        f"chattr -i /etc/ld.so.preload 2>/dev/null; "
        f"cat /etc/ld.so.preload; "
        f"> /etc/ld.so.preload && echo 'Cleared /etc/ld.so.preload'; fi; true"
    )
    ok5, out5 = _run(ssh, cmd5)
    if out5:
        actions.append(_make_entry("clean_ld_preload", "/etc/ld.so.preload", ok5, out5[:200]))

    return actions


# ── Stage 5: Proactive blind-unload of all known rootkit modules ──────────────

def _kill_by_name(ssh=None, known_rootkits: list[str] | None = None) -> list[dict]:
    if known_rootkits is None:
        from config import KNOWN_ROOTKITS
        known_rootkits = KNOWN_ROOTKITS

    actions = []
    pattern = "|".join(re.escape(n) for n in known_rootkits)

    pkill_cmd = f"pkill -9 -f '{pattern}' 2>&1; true"
    ok, out = _run(ssh, pkill_cmd)
    if out:
        actions.append(_make_entry("pkill_by_name", pattern[:60], ok,
                                   f"pkill -9 -f: {out[:120]}"))

    proc_cmd = (
        f"for pid in $(ls /proc | grep -E '^[0-9]+$'); do "
        f"  cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '); "
        f"  comm=$(cat /proc/$pid/comm 2>/dev/null); "
        f"  if echo \"$cmdline $comm\" | grep -Eqi '{pattern}'; then "
        f"    kill -9 $pid 2>/dev/null && echo \"Killed PID $pid ($comm)\"; "
        f"  fi; "
        f"done; true"
    )
    ok2, out2 = _run(ssh, proc_cmd)
    if out2:
        actions.append(_make_entry("kill_by_name", "rootkit_procs", ok2, out2[:300]))

    return actions


def _force_unload_all_known(ssh=None, known_rootkits: list[str] | None = None) -> list[dict]:
    if known_rootkits is None:
        from config import KNOWN_ROOTKITS
        known_rootkits = KNOWN_ROOTKITS

    actions = []
    for name in known_rootkits:
        ok, out = _run(ssh, f"rmmod {shlex.quote(name)} 2>&1")
        if ok:
            actions.append(_make_entry("force_unload", name, True,
                                       "Blind rmmod succeeded — module was hidden from scanner"))
            safe = re.escape(name)
            _run(ssh, (
                f"sed -i '\\|{safe}|d' /etc/modules 2>/dev/null; "
                f"rm -f /etc/modules-load.d/{shlex.quote(name + '.conf')} 2>/dev/null; true"
            ))
    return actions


# ── Stage 6: Hunt and delete rootkit .ko files ────────────────────────────────

def _delete_ko_files(ssh=None, known_rootkits: list[str] | None = None) -> list[dict]:
    if known_rootkits is None:
        from config import KNOWN_ROOTKITS
        known_rootkits = KNOWN_ROOTKITS

    actions = []
    name_pattern = "|".join(re.escape(n) for n in known_rootkits)
    cmd = (
        f"find /lib/modules /tmp /dev/shm /var/tmp /opt /home /root "
        f"-name '*.ko' -type f 2>/dev/null | "
        f"grep -Ei '{name_pattern}'"
    )
    ok, out = _run(ssh, cmd)
    if out:
        for path in out.strip().splitlines():
            path = path.strip()
            if path:
                actions.append(clean_file(path, ssh))
    return actions


# ── Main batch remediation ────────────────────────────────────────────────────

def remediate_scan(scan_result: dict, ssh_client=None,
                   kill_procs: bool = True,
                   unload_mods: bool = True,
                   clean_files: bool = True,
                   clean_persistence: bool = True,
                   block_ports: bool = True) -> dict:
    """
    Fully aggressive remediation of all findings from a scan result.
    All action entries are built with _make_entry() in a LOCAL list — no shared
    global state, safe for concurrent calls.
    """
    actions: list[dict] = []
    ssh = ssh_client
    mods = scan_result.get("modules", {})

    # 0. Proactive blind-unload (catches hidden/self-hiding modules)
    actions.extend(_force_unload_all_known(ssh))

    # 0.5. Kill rootkit processes by NAME
    actions.extend(_kill_by_name(ssh))

    # 1. Kill hidden processes (by stale PID from scan)
    if kill_procs:
        proc_mod = mods.get("process_scanner", {})
        for finding in proc_mod.get("findings", []):
            pid = finding.get("pid")
            if pid is not None:
                try:
                    actions.append(kill_process(int(pid), ssh))
                except (ValueError, TypeError):
                    pass

    # 2. Kill + block hidden ports
    fs_mod = mods.get("fs_checker", {})
    for finding in fs_mod.get("findings", []):
        if finding.get("type") == "hidden_port":
            port = finding.get("port")
            if port is not None:
                try:
                    port = int(port)
                    if kill_procs:
                        actions.append(kill_port_process(port, ssh))
                    if block_ports:
                        actions.append(_block_port_iptables(port, ssh))
                except (ValueError, TypeError):
                    pass

    # 3. Unload rootkit modules
    if unload_mods:
        sys_mod = mods.get("syscall_inspector", {})
        for finding in sys_mod.get("findings", []):
            if finding.get("type") == "rootkit_module":
                mod_name = finding.get("module")
                if mod_name:
                    actions.append(unload_module(mod_name, ssh))

    # 4. Delete suspicious files
    if clean_files:
        _DELETABLE_TYPES = {
            "suspicious_suid", "world_writable",
            "suspicious_file", "rootkit_path",
        }
        for finding in fs_mod.get("findings", []):
            ftype = finding.get("type", "")
            path  = finding.get("path")
            if path and ftype in _DELETABLE_TYPES:
                actions.append(clean_file(path, ssh))

    # 5. Clean persistence
    if clean_persistence:
        actions.extend(_clean_persistence(ssh))

    # 6. Delete rootkit .ko files from disk
    if clean_files:
        actions.extend(_delete_ko_files(ssh))

    succeeded = sum(1 for a in actions if a["success"])
    failed    = len(actions) - succeeded

    mod_unload_failed = any(
        not a["success"] and a["action"] in ("unload_module", "force_unload")
        for a in actions
    )
    reboot_note = (
        " ⚠ One or more kernel modules could not be unloaded — "
        "REBOOT the target to evict them from memory."
        if mod_unload_failed else ""
    )

    return {
        "status":    "done",
        "host":      scan_result.get("host", "localhost"),
        "actions":   actions,
        "succeeded": succeeded,
        "failed":    failed,
        "summary":   (
            f"Aggressive remediation complete: {succeeded} action(s) succeeded, "
            f"{failed} failed across {len(actions)} total operations.{reboot_note}"
        ),
    }
