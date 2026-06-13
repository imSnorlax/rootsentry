"""
modules/mitre_mapper.py
=======================
MITRE ATT&CK® mapping for RootSentry findings.

Enriches scan findings with Technique ID, Name, Tactic, URL, and Severity.
"""

from __future__ import annotations

from typing import Any

# Hardcoded MITRE ATT&CK mapping database
_TECHNIQUE_DB: dict[str, dict[str, Any]] = {
    # hidden_process -> T1564.001 - Hide Artifacts: Hidden Files and Directories
    "hidden_process": {
        "technique_id": "T1564.001",
        "technique_name": "Hide Artifacts: Hidden Files and Directories",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1564/001/",
        "severity": "high",
    },
    # rootkit_module -> T1014 - Rootkit
    "rootkit_module": {
        "technique_id": "T1014",
        "technique_name": "Rootkit",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1014/",
        "severity": "critical",
    },
    # syscall_hook -> T1014 - Rootkit
    "syscall_hook": {
        "technique_id": "T1014",
        "technique_name": "Rootkit",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1014/",
        "severity": "critical",
    },
    # suspicious_symbol -> T1014 - Rootkit
    "suspicious_symbol": {
        "technique_id": "T1014",
        "technique_name": "Rootkit",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1014/",
        "severity": "critical",
    },
    # hidden_symbol -> T1014 - Rootkit
    "hidden_symbol": {
        "technique_id": "T1014",
        "technique_name": "Rootkit",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1014/",
        "severity": "critical",
    },
    # hidden_port -> T1205 - Traffic Signaling
    "hidden_port": {
        "technique_id": "T1205",
        "technique_name": "Traffic Signaling",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1205/",
        "severity": "high",
    },
    # suid_binary -> T1548.001 - Abuse Elevation Control: Setuid and Setgid
    "suid_binary": {
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control: Setuid and Setgid",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/001/",
        "severity": "high",
    },
    # suspicious_suid -> T1548.001 - Abuse Elevation Control: Setuid and Setgid
    "suspicious_suid": {
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control: Setuid and Setgid",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/001/",
        "severity": "high",
    },
    # hidden_file -> T1564.001 - Hide Artifacts
    "hidden_file": {
        "technique_id": "T1564.001",
        "technique_name": "Hide Artifacts",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1564/001/",
        "severity": "high",
    },
    # suspicious_file -> T1564.001 - Hide Artifacts
    "suspicious_file": {
        "technique_id": "T1564.001",
        "technique_name": "Hide Artifacts",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1564/001/",
        "severity": "high",
    },
    # rootkit_path -> T1014 - Rootkit
    "rootkit_path": {
        "technique_id": "T1014",
        "technique_name": "Rootkit",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1014/",
        "severity": "critical",
    },
    # world_writable -> T1222.002 - File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification
    "world_writable": {
        "technique_id": "T1222.002",
        "technique_name": "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1222/002/",
        "severity": "medium",
    },
    # suspicious_socket -> T1071.001 - Application Layer Protocol: Web Protocols
    "suspicious_socket": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "severity": "high",
    },
}

# Severity ordering for sorting / comparison
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Tactic colour hints (used by templates)
TACTIC_COLOURS: dict[str, str] = {
    "Defense Evasion":      "#ff4f4f",
    "Persistence":          "#ffe066",
    "Privilege Escalation": "#ff8c00",
    "Command and Control":  "#ff4f4f",
    "Discovery":            "#38bdf8",
    "Execution":            "#a78bfa",
    "Impact":               "#f472b6",
    "Lateral Movement":     "#fb923c",
    "Collection":           "#34d399",
    "Exfiltration":         "#f87171",
}


def map_finding(finding_type: str, detail: str = "") -> list[dict]:
    """
    Return a list of MITRE ATT&CK technique dicts for a given finding type.
    Returns an empty list for unknown / informational types.
    """
    tech = _TECHNIQUE_DB.get(finding_type)
    if tech:
        # Return as a list for backward compatibility with multi-technique logic
        return [tech]
    return []


def enrich_scan(scan_result: dict) -> dict:
    """
    Enrich every finding in *scan_result* with a ``mitre`` key containing
    the relevant ATT&CK techniques.

    Also adds a top-level ``mitre_summary`` dict.
    The original dict is not mutated — a deep copy is returned.
    """
    import copy
    result = copy.deepcopy(scan_result)

    all_techniques: dict[str, dict] = {}   # technique_id -> technique dict
    tactic_counts:  dict[str, int]  = {}
    severity_counts: dict[str, int] = {}
    highest_severity = "info"

    for _mod_name, mod_data in result.get("modules", {}).items():
        for finding in mod_data.get("findings", []):
            ftype    = finding.get("type", "")
            detail   = finding.get("detail", "")
            techniques = map_finding(ftype, detail)

            if techniques:
                finding["mitre"] = techniques

            for tech in techniques:
                tid = tech["technique_id"]
                if tid not in all_techniques:
                    all_techniques[tid] = tech

                tactic = tech.get("tactic", "Defense Evasion")
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

                sev = tech.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(highest_severity, 0):
                    highest_severity = sev

    result["mitre_summary"] = {
        "techniques":       sorted(all_techniques.values(),
                                   key=lambda t: t["technique_id"]),
        "tactic_counts":    tactic_counts,
        "severity_counts":  severity_counts,
        "highest_severity": highest_severity,
        "total_techniques": len(all_techniques),
    }

    return result


def get_attack_summary(scan_result: dict) -> dict:
    """
    Returns just the ``mitre_summary`` block, computing it on-the-fly if not present.
    """
    if "mitre_summary" in scan_result:
        return scan_result["mitre_summary"]
    return enrich_scan(scan_result).get("mitre_summary", {})
