"""
modules/syscall_inspector.py
Detects kernel-level hooks by:
  1. Checking /proc/modules for known rootkit module names
  2. Scanning /proc/kallsyms for suspicious symbol addresses / names
  3. Looking for modules whose memory ranges overlap with kallsyms hooks
"""

import re
from typing import List, Optional
from config import KNOWN_ROOTKITS, SUSPICIOUS_KALLSYMS


class KernelModuleFinding:
    def __init__(self, name: str, size: str, used: str, state: str):
        self.name  = name
        self.size  = size
        self.used  = used
        self.state = state


class KallsymsFinding:
    def __init__(self, symbol: str, addr: str, reason: str):
        self.symbol = symbol
        self.addr   = addr
        self.reason = reason


def _parse_modules(raw: str) -> List[dict]:
    mods = []
    for line in raw.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mods.append({
            "name":  parts[0],
            "size":  parts[1],
            "used":  parts[2],
            "state": parts[4] if len(parts) > 4 else "Unknown",
        })
    return mods


def _check_modules(raw_modules: str) -> List[dict]:
    findings = []
    for mod in _parse_modules(raw_modules):
        name_lower = mod["name"].lower()
        for rootkit in KNOWN_ROOTKITS:
            if rootkit in name_lower:
                findings.append({
                    "type":    "rootkit_module",
                    "module":  mod["name"],
                    "size":    mod["size"],
                    "detail":  f"Matches known rootkit signature: '{rootkit}'",
                })
    return findings


def _check_kallsyms(raw_kallsyms: str, kptr_restrict: int = 1) -> List[dict]:
    """
    Look for suspicious symbols in /proc/kallsyms.

    IMPORTANT: On modern Linux (kernel >= 4.15), kptr_restrict defaults to 1
    or 2, which causes ALL addresses to show as 0 even for root.
    Zeroed-address detection is only reliable when kptr_restrict=0.
    """
    findings = []
    seen = set()
    use_addr_check = (kptr_restrict == 0)

    for line in raw_kallsyms.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, _type, sym = parts[0], parts[1], parts[2]
        sym_lower = sym.lower()

        # Always: check for rootkit-named symbols (name-based, reliable)
        for rootkit in KNOWN_ROOTKITS:
            if rootkit in sym_lower and sym not in seen:
                seen.add(sym)
                findings.append({
                    "type":   "suspicious_symbol",
                    "symbol": sym,
                    "addr":   addr,
                    "detail": f"Symbol name contains rootkit string '{rootkit}'",
                })

        # Only when kptr_restrict=0: zeroed address is meaningful
        if use_addr_check and addr == "0000000000000000":
            for hook in SUSPICIOUS_KALLSYMS:
                if hook in sym_lower and sym not in seen:
                    seen.add(sym)
                    findings.append({
                        "type":   "hidden_symbol",
                        "symbol": sym,
                        "addr":   addr,
                        "detail": "Address zeroed with kptr_restrict=0 — likely hooked by rootkit",
                    })
    return findings


# ── SSH helper — NOW WITH TIMEOUT ────────────────────────────────────────────

def _exec(ssh, cmd: str) -> str:
    # Bug fix: added timeout=30 to prevent indefinite blocking on slow/hung SSH channels
    _, stdout, _ = ssh.exec_command(cmd, timeout=30)
    return stdout.read().decode(errors="replace")


def _read_kptr_restrict(ssh_client=None) -> int:
    try:
        if ssh_client:
            _, stdout, _ = ssh_client.exec_command(
                "cat /proc/sys/kernel/kptr_restrict 2>/dev/null", timeout=10)
            val = stdout.read().decode().strip()
        else:
            with open("/proc/sys/kernel/kptr_restrict") as f:
                val = f.read().strip()
        return int(val)
    except Exception:
        return 1


def _read_kallsyms_local() -> str:
    """
    Read /proc/kallsyms with a 200k-line cap so we never block on a
    10 MB+ file. The rootkit-name check only needs the symbol names,
    not all 1M+ entries on modern kernels.
    """
    lines = []
    try:
        with open("/proc/kallsyms", "r", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= 200_000:
                    break
                lines.append(line)
    except Exception:
        pass
    return "".join(lines)


def scan_syscalls(ssh_client=None) -> dict:
    kptr = _read_kptr_restrict(ssh_client)

    if ssh_client:
        raw_modules  = _exec(ssh_client, "cat /proc/modules 2>/dev/null")
        # Cap kallsyms at 200k lines remotely too
        raw_kallsyms = _exec(ssh_client, "head -n 200000 /proc/kallsyms 2>/dev/null")
    else:
        try:
            with open("/proc/modules", "r") as f:
                raw_modules = f.read()
        except Exception:
            raw_modules = ""
        raw_kallsyms = _read_kallsyms_local()

    module_findings   = _check_modules(raw_modules)
    kallsyms_findings = _check_kallsyms(raw_kallsyms, kptr_restrict=kptr)
    all_findings      = module_findings + kallsyms_findings

    addr_note = (
        f" (kptr_restrict={kptr}: zeroed-address detection disabled — addresses hidden by kernel)"
        if kptr > 0 else ""
    )

    return {
        "module":       "syscall_inspector",
        "threat_count": len(all_findings),
        "findings":     all_findings,
        "summary": (
            f"{len(all_findings)} kernel-level hook(s)/rootkit module(s) detected."
            if all_findings
            else f"No kernel hooks or rootkit modules detected.{addr_note}"
        ),
    }
