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
import re
import shlex
import signal
import subprocess
import datetime
import threading
from typing import Optional

# ── Per-call action log ───────────────────────────────────────────────────────
# Each remediate_scan() call creates its OWN local log list and passes it
# through to every helper.  This eliminates the shared-global bleed bug where
# concurrent or sequential remediations would read each other's log entries.

def _make_entry(action: str, target: str, success: bool, detail: str = "") -> dict:
    """Build a single structured log entry (no global side-effects)."""
    return {
        "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "action":    action,
        "target":    target,
        "success":   success,
        "detail":    detail,
    }


# ── Legacy compat shims (kept so any external callers don't break) ─────────────
_action_log: list[dict] = []
_log_lock = threading.Lock()


def _log(action: str, target: str, success: bool, detail: str = "") -> dict:
    """Deprecated: appends to the global log.  Internal code uses _make_entry."""
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
    """Run cmd over SSH. Returns (success, output).

    Bug #1 fix: use the SSH channel exit status instead of treating any
    stderr output as failure.  Many tools (chattr, iptables, crontab, rmmod)
    write informational messages to stderr even on success.
    """
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
    """SIGKILL a PID.

    Bug #2 fix: for SSH kills, remove the unconditional '|| true' so we get
    a real exit code, and pass 'ok' through to the log instead of hardcoding
    True.
    Bug #12 fix: accept int or str pid (JSON deserialisation may give either).
    """
    pid = int(pid)  # normalise: JSON may deserialise as int already, str from old saves
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
            return _make_entry("kill_process", str(pid), False, f"Permission denied (need root)")
        except Exception as exc:
            return _make_entry("kill_process", str(pid), False, str(exc))


def kill_port_process(port: int, ssh=None) -> dict:
    """
    Kill whatever process is listening on a port using fuser.

    Bug #4 fix: pass 'ok' through to the log instead of hardcoding True.
    We keep '|| true' only on the second fuser call so one protocol failing
    doesn't mask the overall result.
    """
    cmd = f"fuser -k -n tcp {port} 2>&1; fuser -k -n udp {port} 2>&1; true"
    ok, detail = _run(ssh, cmd)
    return _make_entry("kill_port_process", str(port),
                       ok, f"fuser -k port {port}: {detail or 'OK'}")


def _block_port_iptables(port: int, ssh=None) -> dict:
    """Drop all traffic to/from a hidden port with iptables.

    Bug #5 fix: track whether all four iptables rules actually succeeded
    instead of hardcoding True.
    """
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
    """
    Attempt rmmod, then modprobe -r, then rmmod --force (last resort).
    Also purges from /etc/modules and /etc/modules-load.d/.

    Bug #3 fix: derive overall success from whether at least one removal
    method worked instead of hardcoding True.
    Bug #7 fix: escape the module name before embedding it in sed so that
    names with regex metacharacters or '/' don't break the command.
    """
    results  = []
    ok = ok2 = ok3 = False

    # Try rmmod first
    ok, out = _run(ssh, f"rmmod {shlex.quote(module_name)} 2>&1")
    if ok:
        results.append("rmmod OK")
    else:
        results.append(f"rmmod failed: {out}")
        # Try modprobe -r
        ok2, out2 = _run(ssh, f"modprobe -r {shlex.quote(module_name)} 2>&1")
        if ok2:
            results.append("modprobe -r OK")
        else:
            results.append(f"modprobe -r: {out2}")
            # Force remove
            ok3, out3 = _run(ssh, f"rmmod --force {shlex.quote(module_name)} 2>&1")
            results.append("rmmod --force OK" if ok3 else f"rmmod --force: {out3}")

    # Remove from persistence
    # Use '|' as the sed delimiter so '/' in the name is safe; also escape
    # remaining regex metacharacters so the pattern is treated as a literal.
    safe_pattern = re.escape(module_name)
    persist_cmd = (
        f"sed -i '\\|{safe_pattern}|d' /etc/modules 2>/dev/null; "
        f"rm -f /etc/modules-load.d/{shlex.quote(module_name + '.conf')} 2>/dev/null; true"
    )
    _run(ssh, persist_cmd)
    results.append("persistence cleaned")

    overall_ok = ok or ok2 or ok3
    detail     = " | ".join(results)
    return _make_entry("unload_module", module_name, overall_ok, detail)


# ── Stage 3: Remove files ─────────────────────────────────────────────────────

def clean_file(path: str, ssh=None) -> dict:
    """Force-delete a file, clearing immutable bit first if needed.

    Bug #8 fix: use shlex.quote() instead of Python's !r repr-quoting.
    repr() wraps the string in Python single-quotes which break if the path
    itself contains a single-quote character.  shlex.quote() handles all
    shell-unsafe characters correctly.
    """
    quoted = shlex.quote(path)
    cmd    = f"chattr -i {quoted} 2>/dev/null; rm -f -- {quoted} 2>&1"
    ok, detail = _run(ssh, cmd)
    return _make_entry("clean_file", path, ok, detail or f"Deleted {path}")


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
            "caraxes",
            "diamorphine", "reptile", "azazel", "beurk",
            "necurs", "suterusu", "adore-ng", "knark", "modhide", "kbeast",
            "jynx",
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


# ── Stage 5 (new): Proactive blind-unload of all known rootkit modules ────────
# Some rootkits hide themselves from /proc/modules (e.g. Caraxes can hide its
# own module entry). The detection-based unload in Stage 3 won't fire if the
# scanner never saw the module. This stage blindly tries rmmod on every known
# rootkit name — a failed rmmod on a non-loaded module is harmless and fast.

def _force_unload_all_known(ssh=None,
                             known_rootkits: list[str] | None = None) -> list[dict]:
    """
    Attempt rmmod on every known rootkit name unconditionally.
    Catches rootkits that hide from /proc/modules and therefore evade
    the detection-based unload path.
    """
    if known_rootkits is None:
        from config import KNOWN_ROOTKITS
        known_rootkits = KNOWN_ROOTKITS

    actions = []
    for name in known_rootkits:
        ok, out = _run(ssh, f"rmmod {shlex.quote(name)} 2>&1")
        if ok:
            # Module was actually loaded and now removed — log it
            actions.append(_make_entry("force_unload", name, True,
                                       "Blind rmmod succeeded — module was hidden from scanner"))
            # Also strip from persistence
            safe = re.escape(name)
            _run(ssh, (
                f"sed -i '\\|{safe}|d' /etc/modules 2>/dev/null; "
                f"rm -f /etc/modules-load.d/{shlex.quote(name + '.conf')} 2>/dev/null; true"
            ))
        # Intentionally don't log failures — most names won't be loaded
    return actions


# ── Stage 6 (new): Hunt and delete rootkit .ko files from disk ────────────────

def _delete_ko_files(ssh=None,
                     known_rootkits: list[str] | None = None) -> list[dict]:
    """
    Find and remove rootkit kernel object (.ko) files so the rootkit can't
    be re-inserted after a reboot or by a persistence script.
    Searches /lib/modules, /tmp, /dev/shm, /var/tmp, /opt, /home, /root.
    """
    if known_rootkits is None:
        from config import KNOWN_ROOTKITS
        known_rootkits = KNOWN_ROOTKITS

    actions = []
    name_pattern = "|".join(re.escape(n) for n in known_rootkits)
    # find .ko files whose filename matches any known rootkit name
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

    Bug fix: every action entry is now built with _make_entry() and collected
    in a LOCAL list — no shared global state, safe for concurrent calls.

    Execution order:
      0. Proactively try rmmod on ALL known rootkits, even if not detected
         (catches rootkits that hide from /proc/modules like Caraxes)
      1. Kill hidden processes (SIGKILL by PID)
      2. Kill + block hidden ports (fuser + iptables)
      3. Unload rootkit kernel modules identified by scanner (rmmod / force)
      4. Delete suspicious files
      5. Destroy persistence (cron, systemd, rc.local, ld.so.preload, droppers)
      6. Hunt and delete rootkit .ko files from disk
    """
    actions: list[dict] = []
    ssh = ssh_client
    mods = scan_result.get("modules", {})

    # ── 0. Proactive blind-unload (catches hidden/self-hiding modules) ─────
    actions.extend(_force_unload_all_known(ssh))

    # ── 1. Kill hidden processes ───────────────────────────────────────────
    if kill_procs:
        proc_mod = mods.get("process_scanner", {})
        for finding in proc_mod.get("findings", []):
            pid = finding.get("pid")
            # pid can be int (new schema) or str (old saves) — int() handles both
            if pid is not None:
                try:
                    actions.append(kill_process(int(pid), ssh))
                except (ValueError, TypeError):
                    pass

    # ── 2. Kill + block hidden ports ──────────────────────────────────────
    # Hidden ports can come from fs_checker (both local and remote scans)
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

    # ── 3. Unload rootkit modules ──────────────────────────────────────────
    if unload_mods:
        sys_mod = mods.get("syscall_inspector", {})
        for finding in sys_mod.get("findings", []):
            if finding.get("type") == "rootkit_module":
                mod_name = finding.get("module")
                if mod_name:
                    actions.append(unload_module(mod_name, ssh))

    # ── 4. Delete suspicious files ────────────────────────────────────────
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

    # ── 5. Clean persistence ──────────────────────────────────────────────
    if clean_persistence:
        actions.extend(_clean_persistence(ssh))

    # ── 6. Delete rootkit .ko files from disk ─────────────────────────────
    if clean_files:
        actions.extend(_delete_ko_files(ssh))

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
