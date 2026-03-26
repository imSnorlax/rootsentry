"""
modules/fs_checker.py
Filesystem integrity checks:
  1. Hidden TCP/UDP ports — compare /proc/net/tcp vs `ss` output
  2. Suspicious SUID binaries not in a known-good whitelist
  3. World-writable files in sensitive directories
"""

import subprocess
from typing import List

# ── Known-legitimate SUID binaries (Kali/Ubuntu baseline) ───────────────────
SUID_WHITELIST = {
    "/usr/bin/passwd",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/sbin/pppd",
    "/bin/mount",
    "/bin/umount",
    "/bin/su",
    "/bin/ping",
}

# Directories to scan for world-writable files
SENSITIVE_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]


# ── Port helpers ─────────────────────────────────────────────────────────────

def _parse_proc_net_tcp(raw: str) -> set:
    """
    Parse /proc/net/tcp (and tcp6) hex port entries.
    Returns a set of decimal port numbers that are in LISTEN state (state=0A).
    """
    ports = set()
    for line in raw.strip().splitlines()[1:]:    # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        state = parts[3]
        if state != "0A":   # 0A = LISTEN
            continue
        local  = parts[1]
        hex_port = local.split(":")[1]
        try:
            ports.add(int(hex_port, 16))
        except ValueError:
            pass
    return ports


def _get_ss_ports(ssh=None) -> set:
    """Get listening ports as reported by the `ss` tool."""
    ports = set()
    output: str = ""
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command("ss -tlnp")
            output = stdout.read().decode(errors="replace")
        else:
            result = subprocess.run(["ss", "-tlnp"],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout

        for line in output.strip().splitlines()[1:]:
            # format: State Recv-Q Send-Q Local-Address:Port ...
            parts = line.split()
            if len(parts) < 4:
                continue
            addr_port = parts[3]
            if ":" in addr_port:
                port_str = addr_port.rsplit(":", 1)[-1]
                if port_str.isdigit():
                    ports.add(int(port_str))
    except Exception:
        pass
    return ports


def _check_hidden_ports(ssh=None) -> List[dict]:
    findings = []
    try:
        raw: str
        if ssh:
            _, stdout, _ = ssh.exec_command("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
            raw = stdout.read().decode(errors="replace")
        else:
            parts: List[str] = []
            for f in ["/proc/net/tcp", "/proc/net/tcp6"]:
                try:
                    with open(f) as fh:
                        parts.append(fh.read())
                except Exception:
                    pass
            raw = "".join(parts)

        proc_ports = _parse_proc_net_tcp(raw)
        ss_ports   = _get_ss_ports(ssh)

        # Ports visible in /proc/net/tcp but NOT in ss = rootkit-hidden
        hidden = proc_ports - ss_ports
        for port in sorted(hidden):
            findings.append({
                "type":   "hidden_port",
                "port":   port,
                "detail": f"Port {port} visible in /proc/net/tcp but not in ss output",
            })
    except Exception as e:
        findings.append({"type": "error", "detail": str(e)})
    return findings


# ── SUID helpers ─────────────────────────────────────────────────────────────

def _check_suid_binaries(ssh=None) -> List[dict]:
    findings = []
    try:
        cmd = "find / -perm -4000 -type f 2>/dev/null"
        if ssh:
            _, stdout, _ = ssh.exec_command(cmd)
            output = stdout.read().decode(errors="replace")
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=30)
            output = result.stdout

        for raw_path in output.strip().splitlines():
            path = raw_path.strip()
            if path and path not in SUID_WHITELIST:
                findings.append({
                    "type":   "suspicious_suid",
                    "path":   path,
                    "detail": "SUID binary not in known-good whitelist",
                })
    except Exception as e:
        findings.append({"type": "error", "detail": str(e)})
    return findings


# ── World-writable helpers ────────────────────────────────────────────────────

def _check_world_writable(ssh=None) -> List[dict]:
    findings = []
    dirs = " ".join(SENSITIVE_DIRS)
    cmd  = f"find {dirs} -perm -o+w -type f 2>/dev/null"
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command(cmd)
            output = stdout.read().decode(errors="replace")
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=30)
            output = result.stdout

        for raw_path in output.strip().splitlines():
            path = raw_path.strip()
            if path:
                findings.append({
                    "type":   "world_writable",
                    "path":   path,
                    "detail": "World-writable file in sensitive directory",
                })
    except Exception as e:
        findings.append({"type": "error", "detail": str(e)})
    return findings


# ── Public API ───────────────────────────────────────────────────────────────

def scan_filesystem(ssh_client=None) -> dict:
    port_findings   = _check_hidden_ports(ssh_client)
    suid_findings   = _check_suid_binaries(ssh_client)
    writable_findings = _check_world_writable(ssh_client)

    all_findings = port_findings + suid_findings + writable_findings

    # Only ports and SUID count as real threats for risk scoring
    threat_count = len(port_findings) + len(suid_findings)

    return {
        "module": "fs_checker",
        "threat_count": threat_count,
        "findings": all_findings,
        "summary": (
            f"{threat_count} filesystem threat(s) detected "
            f"({len(port_findings)} hidden port(s), "
            f"{len(suid_findings)} suspicious SUID binary/binaries)."
            if threat_count
            else "No filesystem threats detected."
        ),
    }
