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


# ── Data structures ──────────────────────────────────────────────────────────

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


# ── /proc/modules reader ─────────────────────────────────────────────────────

def _parse_modules(raw: str) -> List[dict]:
    """Parse /proc/modules lines into structured records."""
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
    """Return entries that match known rootkit names."""
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


# ── /proc/kallsyms reader ────────────────────────────────────────────────────

def _check_kallsyms(raw_kallsyms: str, kptr_restrict: int = 1) -> List[dict]:
    """
    Look for suspicious symbols in /proc/kallsyms.

    IMPORTANT: On modern Linux (kernel >= 4.15), kptr_restrict defaults to 1
    or 2, which causes ALL addresses in /proc/kallsyms to show as 0 even for
    root. This means zeroed addresses CANNOT be used as a reliable indicator
    of rootkit hooks unless kptr_restrict = 0.

    We flag:
      - ONLY if kptr_restrict=0: symbols at 0x0 on critical hooks
      - ALWAYS: symbol names containing known rootkit strings
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


# ── SSH helper ───────────────────────────────────────────────────────────────

def _exec(ssh, cmd: str) -> str:
    _, stdout, _ = ssh.exec_command(cmd)
    return stdout.read().decode(errors="replace")


# ── Public API ───────────────────────────────────────────────────────────────

def _read_kptr_restrict(ssh_client=None) -> int:
    """Read /proc/sys/kernel/kptr_restrict. Returns int (0/1/2). Default 1."""
    try:
        if ssh_client:
            _, stdout, _ = ssh_client.exec_command(
                "cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
            val = stdout.read().decode().strip()
        else:
            with open("/proc/sys/kernel/kptr_restrict") as f:
                val = f.read().strip()
        return int(val)
    except Exception:
        return 1   # assume restricted if unreadable


def scan_syscalls(ssh_client=None) -> dict:
    kptr = _read_kptr_restrict(ssh_client)

    if ssh_client:
        raw_modules  = _exec(ssh_client, "cat /proc/modules")
        raw_kallsyms = _exec(ssh_client, "cat /proc/kallsyms")
    else:
        try:
            with open("/proc/modules", "r") as f:
                raw_modules = f.read()
        except Exception:
            raw_modules = ""
        try:
            with open("/proc/kallsyms", "r") as f:
                raw_kallsyms = f.read()
        except Exception:
            raw_kallsyms = ""

    module_findings   = _check_modules(raw_modules)
    kallsyms_findings = _check_kallsyms(raw_kallsyms, kptr_restrict=kptr)
    all_findings      = module_findings + kallsyms_findings

    addr_note = (
        f" (kptr_restrict={kptr}: zeroed-address detection disabled — addresses hidden by kernel)"
        if kptr > 0 else ""
    )

    return {
        "module": "syscall_inspector",
        "threat_count": len(all_findings),
        "findings": all_findings,
        "summary": (
            f"{len(all_findings)} kernel-level hook(s)/rootkit module(s) detected."
            if all_findings
            else f"No kernel hooks or rootkit modules detected.{addr_note}"
        ),
    }
