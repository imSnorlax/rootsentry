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
    # Core utils
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount",
    "/usr/bin/fusermount3", "/usr/bin/vmware-user-suid-wrapper",
    "/usr/bin/staprun", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/wall", "/usr/bin/write", "/usr/bin/ssh-agent",
    "/usr/bin/Xorg", "/usr/bin/dotlockfile", "/usr/bin/expiry",
    "/usr/bin/newuidmap", "/usr/bin/newgidmap", "/usr/bin/traceroute6.iputils",
    # /bin alternatives
    "/bin/mount", "/bin/umount", "/bin/su", "/bin/ping", "/bin/ping6",
    "/bin/fusermount", "/bin/fusermount3",
    # /sbin
    "/usr/sbin/pppd", "/sbin/pppd",
    # ssh / GPG
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/ssh/ssh-keysign",
    # dbus / policykit
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/eject/dmcrypt-get-device",
    # Xorg
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/lib/xorg-core/Xorg",
    # NetworkManager / spice
    "/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper",
    "/usr/lib/NetworkManager/nm-openvpn-auth-dialog",
    # snapd (snap installs duplicate system binaries — auto-handled below)
    "/usr/lib/snapd/snap-confine",
    # vmware
    "/usr/bin/vmware-user-suid-wrapper",
    # Kali / pentesting tools (common legit SUID)
    "/usr/bin/nmap",
}

# Path PREFIXES that are auto-whitelisted (snap duplicates, containers, etc.)
SUID_WHITELIST_PREFIXES = (
    "/snap/",           # snap packages contain copies of system binaries
    "/proc/",           # pseudo-filesystem, never a real binary
    "/sys/",
    "/var/lib/docker/", # container layered FS
    "/run/",
)

# Only flag SUID binaries in these dirs as REAL threats
SUID_THREAT_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/dev/mqueue")

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

# Directories to skip entirely — virtual/pseudo/network filesystems that are
# never real threat locations and make `find /` take forever.
_SUID_PRUNE_PATHS = (
    "/proc", "/sys", "/dev", "/run", "/snap",
    "/var/lib/docker", "/var/lib/lxcfs",
)

# Real filesystem roots to scan for informational SUID binaries.
# Deliberately excludes virtual paths listed above.
_SUID_SCAN_ROOTS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/usr/lib", "/usr/local/lib",
    "/opt", "/home", "/root",
)


def _check_suid_binaries(ssh=None) -> List[dict]:
    """
    Two-pass SUID scan — fast and exhaustive without crawling virtual FSes.

    Pass 1 (THREAT — instant):   Only scans the suspicious temp directories
                                  where a rootkit dropper would live.
    Pass 2 (INFORMATIONAL — fast): Scans real filesystem roots with -xdev
                                   so it never crosses into /proc, /sys,
                                   NFS mounts, etc., plus explicit -prune on
                                   any remaining slow paths.
    """
    findings  = []
    seen_paths: set = set()

    # ── Pass 1: threat directories (fast — tiny trees) ───────────────────────
    threat_dirs = " ".join(SUID_THREAT_DIRS)
    threat_cmd  = f"find {threat_dirs} -perm -4000 -type f 2>/dev/null"
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command(threat_cmd)
            threat_out   = stdout.read().decode(errors="replace")
        else:
            r = subprocess.run(threat_cmd, shell=True, capture_output=True,
                               text=True, timeout=15)
            threat_out = r.stdout

        for raw in threat_out.strip().splitlines():
            path = raw.strip()
            if path and path not in seen_paths:
                seen_paths.add(path)
                findings.append({
                    "type":    "suspicious_suid",
                    "subtype": "threat",
                    "path":    path,
                    "detail":  "SUID binary in suspicious temp directory — likely dropper!",
                })
    except Exception as e:
        findings.append({"type": "error", "detail": f"SUID threat-dir scan: {e}"})

    # ── Pass 2: real filesystem roots, stay on device, explicit prunes ────────
    scan_roots  = " ".join(_SUID_SCAN_ROOTS)
    prune_expr  = " -o ".join(
        f"-path {p} -prune" for p in _SUID_PRUNE_PATHS
    )
    # -xdev: never descend into a different mounted filesystem (NFS, tmpfs, etc.)
    broad_cmd = (
        f"find {scan_roots} -xdev \\( {prune_expr} \\) -o "
        f"\\( -perm -4000 -type f -print \\) 2>/dev/null"
    )
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command(broad_cmd)
            broad_out    = stdout.read().decode(errors="replace")
        else:
            r = subprocess.run(broad_cmd, shell=True, capture_output=True,
                               text=True, timeout=60)
            broad_out = r.stdout

        for raw in broad_out.strip().splitlines():
            path = raw.strip()
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)

            # Skip whitelisted prefixes and exact matches
            if any(path.startswith(p) for p in SUID_WHITELIST_PREFIXES):
                continue
            if path in SUID_WHITELIST:
                continue

            # Already covered by Pass 1
            if any(path.startswith(d) for d in SUID_THREAT_DIRS):
                continue

            findings.append({
                "type":    "suspicious_suid",
                "subtype": "informational",
                "path":    path,
                "detail":  "Unlisted SUID binary (verify manually)",
            })
    except subprocess.TimeoutExpired:
        findings.append({
            "type":   "error",
            "detail": "SUID broad scan timed out after 60s — partial results above",
        })
    except Exception as e:
        findings.append({"type": "error", "detail": f"SUID broad scan: {e}"})

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
    port_findings    = _check_hidden_ports(ssh_client)
    suid_findings    = _check_suid_binaries(ssh_client)
    writable_findings = _check_world_writable(ssh_client)

    # Only REAL threats: hidden ports + SUID in /tmp etc.
    suid_threats      = [f for f in suid_findings if f.get("subtype") == "threat"]
    suid_informational = [f for f in suid_findings if f.get("subtype") == "informational"]

    all_findings = port_findings + suid_findings + writable_findings
    threat_count = len(port_findings) + len(suid_threats)

    info_note = (
        f" ({len(suid_informational)} unlisted system SUID binaries — informational only)"
        if suid_informational else ""
    )

    return {
        "module": "fs_checker",
        "threat_count": threat_count,
        "findings": all_findings,
        "summary": (
            f"{threat_count} filesystem threat(s) detected "
            f"({len(port_findings)} hidden port(s), "
            f"{len(suid_threats)} malicious SUID binary/binaries).{info_note}"
            if threat_count
            else f"No real filesystem threats detected.{info_note}"
        ),
    }

