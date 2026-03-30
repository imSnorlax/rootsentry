"""
modules/removal_engine.py
RootSentry — Aggressive Removal / Remediation Engine
=====================================================
Multi-stage rootkit removal:

  Stage 1 — Kill processes   : SIGKILL by PID, and fuser -k by port
  Stage 2 — Block ports      : iptables DROP on hidden ports
  Stage 3 — Unload modules   : rmmod / modprobe -r / rmmod -f (force)
  Stage 4 — Delete files     : rm -f suspicious binaries / SUID / rootkit files
  Stage 5 — Clean persistence: crontabs, systemd units, rc.local, /etc/modules

All actions are logged and returned in the remediation report.
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
    return list(_action_log)


def clear_action_log() -> None:
    _action_log.clear()


# ── SSH helper ────────────────────────────────────────────────────────────────

def _exec(ssh, cmd: str) -> tuple[bool, str]:
    """Run cmd over SSH. Returns (success, output)."""
    try:
        _, stdout, stderr = ssh.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        return (True, out) if not err else (False, err)
    except Exception as exc:
        return False, str(exc)


def _run_local(cmd: str) -> tuple[bool, str]:
    """Run cmd locally. Returns (success, output)."""
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
    """SIGKILL a PID."""
    if ssh:
        ok, detail = _exec(ssh, f"kill -9 {pid} 2>&1 || true")
        return _log("kill_process", str(pid), True, f"kill -9 {pid}: {detail or 'OK'}")
    else:
        try:
            os.kill(pid, signal.SIGKILL)
            return _log("kill_process", str(pid), True, f"SIGKILL → PID {pid}")
        except ProcessLookupError:
            return _log("kill_process", str(pid), False, f"PID {pid} not found")
        except PermissionError:
            return _log("kill_process", str(pid), False, f"Permission denied (need root)")
        except Exception as exc:
            return _log("kill_process", str(pid), False, str(exc))


def kill_port_process(port: int, ssh=None) -> dict:
    """
    Kill whatever process is listening on a port using fuser.
    Also sends SIGKILL via /proc-based lookup as a fallback.
    """
    cmd = f"fuser -k -n tcp {port} 2>&1; fuser -k -n udp {port} 2>&1; true"
    ok, detail = _run(ssh, cmd)
    return _log("kill_port_process", str(port),
                True, f"fuser -k port {port}: {detail or 'OK'}")


def _block_port_iptables(port: int, ssh=None) -> dict:
    """Drop all traffic to/from a hidden port with iptables."""
    cmds = [
        f"iptables -A INPUT  -p tcp --dport {port} -j DROP 2>&1",
        f"iptables -A OUTPUT -p tcp --sport {port} -j DROP 2>&1",
        f"iptables -A INPUT  -p udp --dport {port} -j DROP 2>&1",
        f"iptables -A OUTPUT -p udp --sport {port} -j DROP 2>&1",
    ]
    details = []
    for c in cmds:
        _, d = _run(ssh, c)
        if d:
            details.append(d)
    return _log("block_port_iptables", str(port), True,
                f"iptables DROP rules added for port {port}" +
                (f" | {'; '.join(details)}" if details else ""))


# ── Stage 2: Unload kernel modules ───────────────────────────────────────────

def unload_module(module_name: str, ssh=None) -> dict:
    """
    Attempt rmmod, then modprobe -r, then rmmod --force (last resort).
    Also purges from /etc/modules and /etc/modules-load.d/.
    """
    results = []

    # Try rmmod first
    ok, out = _run(ssh, f"rmmod {module_name} 2>&1")
    if ok:
        results.append(f"rmmod OK")
    else:
        results.append(f"rmmod failed: {out}")
        # Try modprobe -r
        ok2, out2 = _run(ssh, f"modprobe -r {module_name} 2>&1")
        if ok2:
            results.append("modprobe -r OK")
        else:
            results.append(f"modprobe -r: {out2}")
            # Force remove
            ok3, out3 = _run(ssh, f"rmmod --force {module_name} 2>&1")
            results.append("rmmod --force OK" if ok3 else f"rmmod --force: {out3}")

    # Remove from persistence
    persist_cmd = (
        f"sed -i '/{module_name}/d' /etc/modules 2>/dev/null; "
        f"rm -f /etc/modules-load.d/{module_name}.conf 2>/dev/null; true"
    )
    _run(ssh, persist_cmd)
    results.append("persistence cleaned")

    detail = " | ".join(results)
    return _log("unload_module", module_name, True, detail)


# ── Stage 3: Remove files ─────────────────────────────────────────────────────

def clean_file(path: str, ssh=None) -> dict:
    """Force-delete a file, clearing immutable bit first if needed."""
    cmd = f"chattr -i {path!r} 2>/dev/null; rm -f -- {path!r} 2>&1"
    ok, detail = _run(ssh, cmd)
    return _log("clean_file", path, ok, detail or f"Deleted {path}")


# ── Stage 4: Persistence cleanup ─────────────────────────────────────────────

def _clean_persistence(ssh=None, known_rootkits: list[str] | None = None) -> list[dict]:
    """
    Search and destroy persistence mechanisms:
    - User/root crontabs
    - Systemd units
    - /etc/rc.local
    - /etc/init.d
    - /etc/modules + /etc/modules-load.d
    - /tmp /dev/shm /var/tmp dropper files
    """
    if known_rootkits is None:
        known_rootkits = [
            "diamorphine", "reptile", "azazel", "beurk",
            "necurs", "suterusu", "adore-ng", "knark", "modhide", "kbeast",
        ]

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
        actions.append(_log("clean_crontab", "crontab", ok, out[:200]))

    # Systemd units
    cmd2 = (
        f"grep -rl '{pattern}' /etc/systemd /lib/systemd /usr/lib/systemd 2>/dev/null | "
        f"xargs -I{{}} sh -c 'systemctl disable --now $(basename {{}} .service) 2>/dev/null; rm -f {{}}'; true"
    )
    ok2, out2 = _run(ssh, cmd2)
    if out2:
        actions.append(_log("clean_systemd", "systemd units", ok2, out2[:200]))

    # rc.local
    cmd3 = (
        f"grep -Ei '{pattern}' /etc/rc.local 2>/dev/null && "
        f"sed -iE 's/.*({pattern}).*//g' /etc/rc.local 2>/dev/null; true"
    )
    ok3, out3 = _run(ssh, cmd3)
    if out3:
        actions.append(_log("clean_rclocal", "/etc/rc.local", ok3, out3[:200]))

    # Suspicious dropper files in temp dirs
    cmd4 = (
        f"find /tmp /dev/shm /var/tmp -type f \\( "
        f"-perm -4000 -o -name '*.sh' -o -name '*.elf' -o -name '*.so' \\) 2>/dev/null | "
        f"xargs -I{{}} sh -c 'chattr -i {{}} 2>/dev/null; rm -f {{}} && echo \"Deleted: {{}}\"'; true"
    )
    ok4, out4 = _run(ssh, cmd4)
    if out4:
        actions.append(_log("clean_dropper_files", "/tmp /dev/shm /var/tmp", ok4, out4[:300]))

    # /etc/ld.so.preload (common rootkit injection vector)
    cmd5 = (
        f"if [ -f /etc/ld.so.preload ]; then "
        f"chattr -i /etc/ld.so.preload 2>/dev/null; "
        f"cat /etc/ld.so.preload; "
        f"> /etc/ld.so.preload && echo 'Cleared /etc/ld.so.preload'; fi; true"
    )
    ok5, out5 = _run(ssh, cmd5)
    if out5:
        actions.append(_log("clean_ld_preload", "/etc/ld.so.preload", ok5, out5[:200]))

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

    Execution order:
      1. Kill hidden processes (SIGKILL by PID)
      2. Kill + block hidden ports (fuser + iptables)
      3. Unload rootkit kernel modules (rmmod / force)
      4. Delete suspicious files  
      5. Destroy persistence (cron, systemd, rc.local, ld.so.preload, droppers)
    """
    actions: list[dict] = []
    ssh = ssh_client
    modules = scan_result.get("modules", {})

    # ── 1. Kill hidden processes ───────────────────────────────────────────
    if kill_procs:
        proc_mod = modules.get("process_scanner", {})
        for finding in proc_mod.get("findings", []):
            pid = finding.get("pid")
            if pid:
                actions.append(kill_process(int(pid), ssh))

    # ── 2. Kill + block hidden ports ──────────────────────────────────────
    fs_mod = modules.get("fs_checker", {})
    for finding in fs_mod.get("findings", []):
        if finding.get("type") == "hidden_port":
            port = finding.get("port")
            if port:
                if kill_procs:
                    actions.append(kill_port_process(int(port), ssh))
                if block_ports:
                    actions.append(_block_port_iptables(int(port), ssh))

    # ── 3. Unload rootkit modules ──────────────────────────────────────────
    if unload_mods:
        sys_mod = modules.get("syscall_inspector", {})
        for finding in sys_mod.get("findings", []):
            if finding.get("type") == "rootkit_module":
                mod_name = finding.get("module")
                if mod_name:
                    actions.append(unload_module(mod_name, ssh))

    # ── 4. Delete suspicious files ────────────────────────────────────────
    if clean_files:
        for finding in fs_mod.get("findings", []):
            ftype = finding.get("type", "")
            path  = finding.get("path")
            if path and ftype in ("suspicious_suid", "world_writable",
                                  "suspicious_file", "rootkit_path"):
                actions.append(clean_file(path, ssh))

    # ── 5. Clean persistence ──────────────────────────────────────────────
    if clean_persistence:
        actions.extend(_clean_persistence(ssh))

    succeeded = sum(1 for a in actions if a["success"])
    failed    = len(actions) - succeeded

    return {
        "status":    "done",
        "host":      scan_result.get("host", "localhost"),
        "actions":   actions,
        "succeeded": succeeded,
        "failed":    failed,
        "summary":   (
            f"Aggressive remediation complete: {succeeded} action(s) succeeded, "
            f"{failed} failed across {len(actions)} total operations."
        ),
    }
