"""
modules/net_analyzer.py
=======================
Network socket analysis detecting rootkit communications:

  1. Enumerate ALL open TCP/UDP sockets from /proc/net/tcp(6)/udp(6)
  2. Correlate each socket to the owning process via /proc/<pid>/fd -> inodes
  3. Flag sockets with no owning process (hidden connection)
  4. Detect C2 port usage and sockets hidden from ss

Works both locally and over SSH.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from typing import List, Optional, Set

_C2_PORTS: Set[int] = {
    4444, 4445, 4446, 5555, 5556, 6666, 6667, 6668, 6669,
    1337, 31337, 8888, 9999, 2222, 3333,
    65535, 65534, 65533, 12345, 54321,
}


def _exec_ssh(ssh, cmd: str) -> str:
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=30)
        return stdout.read().decode(errors="replace")
    except Exception as exc:
        return f"__ERROR__: {exc}"


def _run_local(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return r.stdout
    except Exception:
        return ""


def _parse_proc_net(raw: str) -> List[dict]:
    records = []
    for line in raw.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_hex  = parts[1]
            remote_hex = parts[2]
            state      = parts[3]
            uid        = int(parts[7])
            inode      = parts[9]

            def _decode(hex_addr: str):
                if ":" not in hex_addr:
                    return "?", 0
                addr_h, port_h = hex_addr.rsplit(":", 1)
                port = int(port_h, 16)
                if len(addr_h) == 8:
                    addr_bytes = bytes.fromhex(addr_h)[::-1]
                    ip = ".".join(str(b) for b in addr_bytes)
                else:
                    ip = addr_h
                return ip, port

            lip, lport = _decode(local_hex)
            rip, rport = _decode(remote_hex)
            records.append({
                "local_ip": lip, "local_port": lport,
                "remote_ip": rip, "remote_port": rport,
                "state": state, "uid": uid, "inode": inode,
            })
        except Exception:
            continue
    return records


def _build_inode_to_pid_map(ssh=None) -> dict:
    """
    Build {inode_str: pid} map.
    Remote: uses 'seq 1 32768' NOT 'ls /proc' — rootkits hook getdents64
    which filters ls output. seq is a builtin iteration, unaffected.
    Batches all fd reads into a single shell command for speed.
    """
    inode_map: dict = {}
    if ssh:
        # CRITICAL FIX: use seq not ls /proc — ls uses getdents64 which
        # rootkits hook to hide their processes. seq is hook-resistant.
        raw = _exec_ssh(ssh,
            "for pid in $(seq 1 32768); do "
            "  [ -d /proc/$pid/fd ] || continue; "
            "  for fd in /proc/$pid/fd/*; do "
            "    t=$(readlink $fd 2>/dev/null); "
            "    case $t in socket:*) "
            "      i=${t#socket:[}; i=${i%]}; "
            "      echo $i $pid;; "
            "    esac; "
            "  done; "
            "done 2>/dev/null")
        for line in raw.strip().splitlines():
            p = line.split()
            if len(p) == 2 and p[0].isdigit() and p[1].isdigit():
                inode_map[p[0]] = int(p[1])
    else:
        deadline = time.monotonic() + 3.0
        try:
            for entry in os.listdir("/proc"):
                if time.monotonic() > deadline:
                    break
                if not entry.isdigit():
                    continue
                pid = int(entry)
                fd_dir = f"/proc/{pid}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            target = os.readlink(f"{fd_dir}/{fd}")
                            m = re.match(r"socket:\[(\d+)\]", target)
                            if m:
                                inode_map[m.group(1)] = pid
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
    return inode_map


def _get_cmdline(pid: int, ssh=None) -> str:
    if ssh:
        raw = _exec_ssh(ssh, f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
        return raw.strip() or "(unknown)"
    try:
        with open(f"/proc/{pid}/cmdline", "r", errors="replace") as f:
            return f.read().replace("\x00", " ").strip() or "(unknown)"
    except Exception:
        return "(unknown)"


def _get_ss_inodes(ssh=None) -> Set[str]:
    inodes: Set[str] = set()
    raw = _exec_ssh(ssh, "ss -anp 2>/dev/null") if ssh else _run_local("ss -anp 2>/dev/null")
    for m in re.finditer(r'\bino:(\d+)\b', raw):
        inodes.add(m.group(1))
    return inodes


def _analyse(ssh=None) -> List[dict]:
    findings: List[dict] = []
    if ssh:
        raw_tcp = _exec_ssh(ssh, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
        raw_udp = _exec_ssh(ssh, "cat /proc/net/udp /proc/net/udp6 2>/dev/null")
    else:
        parts = []
        for f in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]:
            try:
                with open(f) as fh:
                    parts.append(fh.read())
            except Exception:
                parts.append("")
        raw_tcp = "\n".join(parts[:2])
        raw_udp = "\n".join(parts[2:])

    all_sockets = _parse_proc_net(raw_tcp) + _parse_proc_net(raw_udp)
    inode_map  = _build_inode_to_pid_map(ssh)
    ss_inodes  = _get_ss_inodes(ssh)
    seen: Set[str] = set()

    for sock in all_sockets:
        inode = sock["inode"]
        lport = sock["local_port"]
        rip   = sock["remote_ip"]
        rport = sock["remote_port"]
        state = sock["state"]
        if lport == 0:
            continue

        pid     = inode_map.get(inode)
        cmdline = _get_cmdline(pid, ssh) if pid else "(no owning process)"

        # Only flag orphan sockets that are LISTEN or ESTABLISHED.
        # TIME_WAIT (0x06), CLOSE_WAIT (0x08), FIN_WAIT etc. legitimately
        # have no owning process on clean systems — skip them.
        active_states = {"0A", "01"}   # LISTEN, ESTABLISHED
        if inode != "0" and pid is None and state in active_states:
            key = f"orphan:{inode}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type": "suspicious_socket", "local_port": lport,
                    "remote_addr": f"{rip}:{rport}", "state": state,
                    "pid": None, "cmdline": "(no owning process)",
                    "detail": f"Port {lport} inode {inode} has no owner — possible hidden rootkit socket",
                })

        if inode and inode != "0" and ss_inodes and inode not in ss_inodes:
            key = f"hidden_ss:{inode}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type": "suspicious_socket", "local_port": lport,
                    "remote_addr": f"{rip}:{rport}", "state": state,
                    "pid": pid, "cmdline": cmdline,
                    "detail": f"Socket port {lport} (inode {inode}) visible in /proc/net but hidden from ss",
                })

        if state == "0A" and lport in _C2_PORTS:
            key = f"c2port:{lport}"
            if key not in seen:
                seen.add(key)
                proc_info = f"PID {pid} ({cmdline})" if pid else "unknown process"
                findings.append({
                    "type": "suspicious_socket", "local_port": lport,
                    "remote_addr": f"{rip}:{rport}", "state": state,
                    "pid": pid, "cmdline": cmdline,
                    "detail": f"Listener on known C2/backdoor port {lport} owned by {proc_info}",
                })
    return findings


def scan_network(ssh_client=None) -> dict:
    try:
        findings = _analyse(ssh=ssh_client)
    except Exception as exc:
        findings = [{"type": "error", "detail": f"net_analyzer error: {exc}"}]

    threat_count = sum(1 for f in findings if f.get("type") == "suspicious_socket")
    return {
        "module":       "net_analyzer",
        "threat_count": threat_count,
        "findings":     findings,
        "summary": (
            f"{threat_count} suspicious socket(s) detected "
            f"(orphan connections, C2 ports, or hidden sockets)."
            if threat_count
            else "No suspicious network sockets detected."
        ),
    }
