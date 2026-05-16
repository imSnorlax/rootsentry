"""
modules/kernel_integrity.py
============================
Kernel memory integrity verification:

  1. Read /proc/kallsyms to extract addresses of critical kernel functions
  2. Compute a hash (SHA-256) over the sorted symbol→address table
  3. Store baseline in scans/kernel_baseline.json
  4. On subsequent runs compare against baseline — changed addresses
     indicate function hooking (rootkit installed hooks)
  5. Also detect duplicate symbol names (rootkit injected a copy)
     and symbols at 0x0 when kptr_restrict=0 (hidden hooks)

Works both locally and over SSH (remote baseline stored server-side
in a file the user must pre-generate).
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import List, Optional

# Critical symbols whose addresses should never change after boot
_CRITICAL_SYMBOLS = {
    "sys_call_table",
    "ia32_sys_call_table",
    "do_sys_open",
    "do_sys_openat2",
    "tcp4_seq_show",
    "udp4_seq_show",
    "packet_rcv",
    "tpacket_rcv",
    "audit_log_exit",
    "getdents64",
    "filldir64",
    "security_file_open",
    "security_bpf",
    "commit_creds",
    "prepare_kernel_cred",
}

_BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scans", "kernel_baseline.json"
)


def _exec_ssh(ssh, cmd: str) -> str:
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=60)
        return stdout.read().decode(errors="replace")
    except Exception as exc:
        return ""


def _read_kallsyms(ssh=None) -> str:
    if ssh:
        return _exec_ssh(ssh, "cat /proc/kallsyms 2>/dev/null")
    try:
        with open("/proc/kallsyms", "r") as f:
            return f.read()
    except Exception:
        return ""


def _read_kptr_restrict(ssh=None) -> int:
    try:
        if ssh:
            raw = _exec_ssh(ssh, "cat /proc/sys/kernel/kptr_restrict 2>/dev/null").strip()
        else:
            with open("/proc/sys/kernel/kptr_restrict") as f:
                raw = f.read().strip()
        return int(raw)
    except Exception:
        return 1


def _parse_kallsyms(raw: str) -> dict:
    """Return {symbol_name: address_hex} for all symbols."""
    table = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, _type, sym = parts[0], parts[1], parts[2]
        table[sym] = addr
    return table


def _hash_critical(table: dict) -> str:
    """SHA-256 of sorted critical symbols and their addresses."""
    payload = json.dumps(
        {k: table.get(k, "MISSING") for k in sorted(_CRITICAL_SYMBOLS)},
        sort_keys=True
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _save_baseline(data: dict) -> None:
    os.makedirs(os.path.dirname(_BASELINE_FILE), exist_ok=True)
    with open(_BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _load_baseline() -> Optional[dict]:
    if not os.path.exists(_BASELINE_FILE):
        return None
    try:
        with open(_BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def scan_kernel_integrity(ssh_client=None) -> dict:
    """
    Analyse kernel symbol table integrity.
    Returns a dict compatible with the RootSentry result schema.
    """
    findings: List[dict] = []
    kptr = _read_kptr_restrict(ssh_client)
    raw  = _read_kallsyms(ssh_client)

    if not raw or "__ERROR__" in raw:
        return {
            "module":       "kernel_integrity",
            "threat_count": 0,
            "findings":     [],
            "summary":      "Could not read /proc/kallsyms (permission denied or unavailable).",
        }

    table = _parse_kallsyms(raw)
    current_hash = _hash_critical(table)

    # ── Check 1: addresses zeroed when kptr_restrict=0 (hooked symbols) ──
    if kptr == 0:
        for sym in _CRITICAL_SYMBOLS:
            addr = table.get(sym)
            if addr == "0000000000000000":
                findings.append({
                    "type":   "hidden_symbol",
                    "symbol": sym,
                    "addr":   addr,
                    "detail": f"Critical symbol '{sym}' has zeroed address with kptr_restrict=0 — likely hooked by rootkit",
                })

    # ── Check 2: duplicate symbol names ──────────────────────────────────
    seen_syms: dict = {}
    dup_count = 0
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym = parts[2]
        if sym in _CRITICAL_SYMBOLS:
            seen_syms[sym] = seen_syms.get(sym, 0) + 1
    for sym, count in seen_syms.items():
        if count > 1 and dup_count < 10:
            dup_count += 1
            findings.append({
                "type":   "hidden_symbol",
                "symbol": sym,
                "addr":   table.get(sym, "?"),
                "detail": f"Symbol '{sym}' appears {count} times in kallsyms — rootkit may have injected a hook copy",
            })

    # ── Check 3: baseline comparison ─────────────────────────────────────
    baseline = _load_baseline()
    if baseline is None:
        # First run — save baseline
        _save_baseline({
            "hash":    current_hash,
            "symbols": {k: table.get(k, "MISSING") for k in _CRITICAL_SYMBOLS},
        })
        baseline_note = " (baseline created — future scans will detect changes)"
    else:
        baseline_note = ""
        if baseline.get("hash") != current_hash:
            old_syms = baseline.get("symbols", {})
            for sym in _CRITICAL_SYMBOLS:
                old_addr = old_syms.get(sym, "MISSING")
                new_addr = table.get(sym, "MISSING")
                if old_addr != new_addr:
                    findings.append({
                        "type":   "suspicious_symbol",
                        "symbol": sym,
                        "addr":   new_addr,
                        "detail": f"Critical symbol '{sym}' address changed: {old_addr} → {new_addr} — possible kernel hook installed",
                    })
            # Update baseline after reporting
            _save_baseline({
                "hash":    current_hash,
                "symbols": {k: table.get(k, "MISSING") for k in _CRITICAL_SYMBOLS},
            })

    threat_count = len(findings)
    kptr_note = f" (kptr_restrict={kptr}: address-zero detection {'active' if kptr == 0 else 'disabled'})"
    return {
        "module":       "kernel_integrity",
        "threat_count": threat_count,
        "findings":     findings,
        "summary": (
            f"{threat_count} kernel integrity issue(s) detected.{baseline_note}"
            if threat_count
            else f"Kernel symbol integrity OK.{kptr_note}{baseline_note}"
        ),
    }
