"""
modules/fs_checker.py
Filesystem integrity checks:
  1. Hidden TCP/UDP ports — compare /proc/net/tcp vs `ss` output
  2. Suspicious SUID binaries not in a known-good whitelist
  3. World-writable files in sensitive directories
  4. Known rootkit indicator paths
"""

import subprocess
from typing import List
from config import ROOTKIT_INDICATOR_PATHS

SUID_WHITELIST = {
    # Standard Linux
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount",
    "/usr/bin/fusermount3", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/wall", "/usr/bin/write", "/usr/bin/ssh-agent",
    "/usr/bin/Xorg", "/usr/bin/dotlockfile", "/usr/bin/expiry",
    "/usr/bin/newuidmap", "/usr/bin/newgidmap",
    "/usr/bin/traceroute6.iputils", "/usr/bin/ping", "/usr/bin/ping6",
    "/usr/bin/staprun", "/usr/bin/vmware-user-suid-wrapper",
    "/bin/mount", "/bin/umount", "/bin/su", "/bin/ping", "/bin/ping6",
    "/bin/fusermount", "/bin/fusermount3",
    "/usr/sbin/pppd", "/sbin/pppd",
    # SSH / OpenSSH
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/ssh/ssh-keysign",
    "/usr/lib/x86_64-linux-gnu/openssh/ssh-keysign",
    # DBus / Polkit
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/x86_64-linux-gnu/polkit-1/polkit-agent-helper-1",
    # Misc system
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/xorg/Xorg.wrap",
    "/usr/lib/xorg-core/Xorg",
    "/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper",
    "/usr/lib/NetworkManager/nm-openvpn-auth-dialog",
    "/usr/lib/snapd/snap-confine",
    # Kali Linux specific
    "/usr/bin/nmap",
    "/usr/bin/kismet",
    "/usr/bin/arping",
    "/usr/bin/clockdiff",
    "/usr/sbin/arping",
    "/usr/sbin/clockdiff",
    "/usr/sbin/traceroute",
    "/usr/bin/traceroute",
    "/usr/bin/tcpdump",
    "/usr/sbin/tcpdump",
    "/usr/bin/dumpcap",
    "/usr/bin/ntfs-3g",
    "/usr/sbin/ntfs-3g",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/usr/sbin/exim4",
    "/usr/sbin/postdrop",
    "/usr/sbin/postqueue",
    "/usr/lib/postfix/sbin/postdrop",
    "/usr/lib/postfix/sbin/postqueue",
    "/usr/bin/bwrap",
    "/usr/bin/pkexec",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/bin/gnome-pty-helper",
    "/usr/lib/gnome-disk-utility/gdu-notification-daemon",
    "/usr/lib/dde-dock/plugins/disk-mount",
    # Snap / container
    "/snap/core/current/usr/bin/sudo",
}

SUID_WHITELIST_PREFIXES = (
    "/snap/", "/proc/", "/sys/", "/var/lib/docker/", "/run/",
    "/usr/lib/x86_64-linux-gnu/",  # Kali multiarch libs
    "/usr/lib/i386-linux-gnu/",
    "/usr/lib/aarch64-linux-gnu/",
)

SUID_THREAT_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/dev/mqueue")

SENSITIVE_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]

_SUID_PRUNE_PATHS = (
    "/proc", "/sys", "/dev", "/run", "/snap",
    "/var/lib/docker", "/var/lib/lxcfs",
)

_SUID_SCAN_ROOTS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/usr/lib", "/usr/local/lib",
    "/opt", "/home", "/root",
)


# ── Known rootkit indicator paths ─────────────────────────────────────────────

def _check_rootkit_paths(ssh=None) -> List[dict]:
    """Check for known rootkit indicator paths."""
    findings = []
    for rpath in ROOTKIT_INDICATOR_PATHS:
        try:
            if ssh:
                _, stdout, _ = ssh.exec_command(
                    f"test -e {rpath} && echo EXISTS || echo ABSENT", timeout=10)
                result = stdout.read().decode(errors="replace").strip()
                exists = "EXISTS" in result
            else:
                import os
                exists = os.path.exists(rpath)
            if exists:
                findings.append({
                    "type":   "rootkit_path",
                    "path":   rpath,
                    "detail": f"Known rootkit indicator path found: {rpath}",
                })
        except Exception:
            pass
    return findings


# ── Port helpers ──────────────────────────────────────────────────────────────

def _parse_proc_net_tcp(raw: str) -> set:
    ports = set()
    for line in raw.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        state = parts[3]
        if state != "0A":
            continue
        local    = parts[1]
        hex_port = local.split(":")[1]
        try:
            ports.add(int(hex_port, 16))
        except ValueError:
            pass
    return ports


def _get_ss_ports(ssh=None) -> set:
    ports = set()
    output: str = ""
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command("ss -tlnp", timeout=15)
            output = stdout.read().decode(errors="replace")
        else:
            result = subprocess.run(["ss", "-tlnp"],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout

        for line in output.strip().splitlines()[1:]:
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
    """
    Bug fix: error entries are now separated from real findings so they
    don't inflate the threat_count.
    """
    real_findings = []
    try:
        raw: str
        if ssh:
            _, stdout, _ = ssh.exec_command(
                "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null", timeout=15)
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

        hidden = proc_ports - ss_ports
        for port in sorted(hidden):
            real_findings.append({
                "type":   "hidden_port",
                "port":   port,
                "detail": f"Port {port} visible in /proc/net/tcp but not in ss output",
            })
    except Exception as e:
        # Return error as informational only — not a threat
        real_findings.append({"type": "error", "detail": str(e)})
    return real_findings


# ── SUID helpers ──────────────────────────────────────────────────────────────

def _check_suid_binaries(ssh=None) -> List[dict]:
    findings  = []
    seen_paths: set = set()

    threat_dirs = " ".join(SUID_THREAT_DIRS)
    threat_cmd  = f"find {threat_dirs} -perm -4000 -type f 2>/dev/null"
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command(threat_cmd, timeout=15)
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

    scan_roots  = " ".join(_SUID_SCAN_ROOTS)
    prune_expr  = " -o ".join(
        f"-path {p} -prune" for p in _SUID_PRUNE_PATHS
    )
    broad_cmd = (
        f"find {scan_roots} -xdev \\( {prune_expr} \\) -o "
        f"\\( -perm -4000 -type f -print \\) 2>/dev/null"
    )
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command(broad_cmd, timeout=25)
            broad_out    = stdout.read().decode(errors="replace")
        else:
            r = subprocess.run(broad_cmd, shell=True, capture_output=True,
                               text=True, timeout=20)
            broad_out = r.stdout

        for raw in broad_out.strip().splitlines():
            path = raw.strip()
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            if any(path.startswith(p) for p in SUID_WHITELIST_PREFIXES):
                continue
            if path in SUID_WHITELIST:
                continue
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
            "detail": "SUID broad scan timed out after 20s — partial results above",
        })
    except Exception as e:
        findings.append({"type": "error", "detail": f"SUID broad scan: {e}"})

    return findings


# ── World-writable helpers ─────────────────────────────────────────────────────

def _check_world_writable(ssh=None) -> List[dict]:
    findings = []
    dirs = " ".join(SENSITIVE_DIRS)
    cmd  = f"find {dirs} -perm -o+w -type f 2>/dev/null"
    try:
        if ssh:
            _, stdout, _ = ssh.exec_command(cmd, timeout=20)
            output = stdout.read().decode(errors="replace")
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=15)
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


# ── Public API ────────────────────────────────────────────────────────────────

def scan_filesystem(ssh_client=None) -> dict:
    rootkit_path_findings = _check_rootkit_paths(ssh_client)
    port_findings         = _check_hidden_ports(ssh_client)
    suid_findings         = _check_suid_binaries(ssh_client)
    writable_findings     = _check_world_writable(ssh_client)

    # Separate real threats from informational / errors
    # Bug fix: error entries in port_findings no longer count as threats
    real_port_findings    = [f for f in port_findings    if f.get("type") == "hidden_port"]
    suid_threats          = [f for f in suid_findings    if f.get("subtype") == "threat"]
    suid_informational    = [f for f in suid_findings    if f.get("subtype") == "informational"]
    # Bug fix: world-writable files in sensitive dirs ARE real threats
    real_writable         = [f for f in writable_findings if f.get("type") == "world_writable"]

    all_findings = (
        rootkit_path_findings
        + port_findings
        + suid_findings
        + writable_findings
    )

    threat_count = (
        len(rootkit_path_findings)
        + len(real_port_findings)
        + len(suid_threats)
        + len(real_writable)
    )

    info_note = (
        f" ({len(suid_informational)} unlisted system SUID binaries — informational only)"
        if suid_informational else ""
    )

    return {
        "module":       "fs_checker",
        "threat_count": threat_count,
        "findings":     all_findings,
        "summary": (
            f"{threat_count} filesystem threat(s) detected "
            f"({len(rootkit_path_findings)} rootkit path(s), "
            f"{len(real_port_findings)} hidden port(s), "
            f"{len(suid_threats)} malicious SUID binary/binaries, "
            f"{len(real_writable)} world-writable sensitive file(s)).{info_note}"
            if threat_count
            else f"No real filesystem threats detected.{info_note}"
        ),
    }
