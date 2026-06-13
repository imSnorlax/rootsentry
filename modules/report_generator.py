"""
modules/report_generator.py
RootSentry — Report Generator
==============================
Generates a self-contained HTML scan report.

Usage (standalone):
    from modules.report_generator import generate_html_report, save_report
    html = generate_html_report(scan_result)
    path = save_report(scan_result, fmt="html")

PDF export requires weasyprint:
    pip install weasyprint
"""

from __future__ import annotations

import html as _html
import json
import os
import datetime
from typing import Optional

REPORTS_DIR = "reports"


# ── Safe HTML escape ──────────────────────────────────────────────────────────

def _e(value) -> str:
    """HTML-escape any value (fixes XSS vulnerability)."""
    return _html.escape(str(value) if value is not None else "", quote=True)


# ── Colour / severity helpers ─────────────────────────────────────────────────

def _risk_colour(risk: str) -> str:
    return {"clean": "#22c55e", "suspicious": "#f59e0b",
            "infected": "#ef4444", "remediated": "#a78bfa"}.get(
        risk.lower(), "#94a3b8"
    )


def _threat_badge(count: int) -> str:
    if count == 0:
        colour = "#22c55e"
    elif count <= 2:
        colour = "#f59e0b"
    else:
        colour = "#ef4444"
    return (f'<span style="background:{colour};padding:2px 10px;border-radius:12px;'
            f'color:#fff;font-weight:700">{count}</span>')


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return '<p style="color:#94a3b8;font-style:italic">No findings.</p>'
    rows = ""
    for f in findings:
        ftype  = _e(f.get("type", "—"))
        label  = _e(
            f.get("pid") or f.get("path") or f.get("port") or
            f.get("module") or f.get("symbol") or
            f.get("local_port") or "—"
        )
        detail = _e(f.get("detail", "—"))
        colour = "#ef4444" if any(k in ftype for k in ("rootkit", "hidden")) else "#f59e0b"
        
        # Add MITRE info if present
        mitre_html = ""
        if f.get("mitre"):
            techs = [f"{t['technique_id']} ({t['technique_name']})" for t in f["mitre"]]
            mitre_html = f"""<div style="margin-top:4px;font-size:0.75rem;color:#00ff88">
              <b>MITRE ATT&CK:</b> {', '.join(_e(t) for t in techs)}
            </div>"""

        rows += f"""
        <tr>
          <td><span style="background:{colour}22;color:{colour};padding:2px 8px;
              border-radius:6px;font-size:0.8rem">{ftype}</span></td>
          <td style="font-family:monospace">{label}</td>
          <td>
            {detail}
            {mitre_html}
          </td>
        </tr>"""
    return f"""
    <table style="width:100%;border-collapse:collapse;font-size:0.9rem">
      <thead>
        <tr style="background:#1e293b;color:#94a3b8;text-align:left">
          <th style="padding:8px 12px">Type</th>
          <th style="padding:8px 12px">Target</th>
          <th style="padding:8px 12px">Detail</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>"""


def _module_section(mod_name: str, mod: dict) -> str:
    icon   = "✘" if mod.get("threat_count", 0) else "✔"
    colour = "#ef4444" if mod.get("threat_count", 0) else "#22c55e"
    table  = _findings_table(mod.get("findings", []))
    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:24px;margin-bottom:20px;
                border-left:4px solid {colour}">
      <h3 style="margin:0 0 8px;color:#f1f5f9">
        <span style="color:{colour}">{icon}</span>
        &nbsp;{_e(mod_name)}
        &nbsp;{_threat_badge(mod.get("threat_count", 0))}
      </h3>
      <p style="color:#94a3b8;margin:0 0 16px">{_e(mod.get("summary", ""))}</p>
      {table}
    </div>"""


def _ioc_section(scan_result: dict) -> str:
    """Extract all Indicators of Compromise into a dedicated table."""
    iocs = []
    for mod_name, mod in scan_result.get("modules", {}).items():
        for f in mod.get("findings", []):
            ftype = f.get("type", "")
            if ftype == "error":
                continue
            ioc_type = ftype.replace("_", " ").title()
            # Build IOC value
            val = (
                f.get("module") or
                str(f.get("pid") or "") or
                f.get("path") or
                str(f.get("port") or "") or
                f.get("symbol") or
                str(f.get("local_port") or "") or
                f.get("remote_addr") or
                "—"
            )
            iocs.append({
                "module":  mod_name,
                "type":    ioc_type,
                "value":   val,
                "detail":  f.get("detail", ""),
            })

    if not iocs:
        return ""

    rows = ""
    for ioc in iocs:
        rows += f"""
        <tr>
          <td style="padding:7px 12px;color:#94a3b8;font-size:.82rem">{_e(ioc['module'])}</td>
          <td style="padding:7px 12px">
            <span style="background:#6366f122;color:#818cf8;padding:2px 8px;
              border-radius:5px;font-size:.78rem">{_e(ioc['type'])}</span>
          </td>
          <td style="padding:7px 12px;font-family:monospace;font-size:.82rem;color:#e2e8f0">{_e(ioc['value'])}</td>
          <td style="padding:7px 12px;color:#94a3b8;font-size:.8rem">{_e(ioc['detail'])}</td>
        </tr>"""

    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:24px;margin-bottom:20px;
                border-left:4px solid #6366f1">
      <h3 style="margin:0 0 16px;color:#f1f5f9">🔍 Indicators of Compromise (IOCs)</h3>
      <table style="width:100%;border-collapse:collapse;font-size:.9rem">
        <thead>
          <tr style="background:#0f172a;color:#94a3b8;text-align:left">
            <th style="padding:7px 12px">Module</th>
            <th style="padding:7px 12px">IOC Type</th>
            <th style="padding:7px 12px">Value</th>
            <th style="padding:7px 12px">Detail</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def _remediation_section(remediation: Optional[dict]) -> str:
    if not remediation:
        return ""
    actions = remediation.get("actions", [])
    if not actions:
        return ""
    rows = ""
    for a in actions:
        ok_col = "#22c55e" if a["success"] else "#ef4444"
        status = "✔ OK" if a["success"] else "✘ FAIL"
        rows += f"""
        <tr>
          <td style="padding:6px 12px">{_e(a['timestamp'])}</td>
          <td style="padding:6px 12px;font-weight:700">{_e(a['action'])}</td>
          <td style="padding:6px 12px;font-family:monospace">{_e(a['target'])}</td>
          <td style="padding:6px 12px;color:{ok_col};font-weight:700">{status}</td>
          <td style="padding:6px 12px;color:#94a3b8">{_e(a.get('detail',''))}</td>
        </tr>"""
    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:24px;margin-bottom:20px;
                border-left:4px solid #6366f1">
      <h3 style="margin:0 0 16px;color:#f1f5f9">🛠 Remediation Actions</h3>
      <p style="color:#94a3b8;margin:0 0 16px">{_e(remediation.get('summary',''))}</p>
      <table style="width:100%;border-collapse:collapse;font-size:0.88rem">
        <thead>
          <tr style="background:#0f172a;color:#94a3b8;text-align:left">
            <th style="padding:6px 12px">Time</th>
            <th style="padding:6px 12px">Action</th>
            <th style="padding:6px 12px">Target</th>
            <th style="padding:6px 12px">Status</th>
            <th style="padding:6px 12px">Detail</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def _mitre_section(scan_result: dict) -> str:
    """Extract and display all mapped MITRE ATT&CK techniques."""
    mitre_summary = scan_result.get("mitre_summary", {})
    techniques = mitre_summary.get("techniques", [])
    if not techniques:
        return ""

    rows = ""
    for tech in techniques:
        tid = _e(tech.get("technique_id", "—"))
        name = _e(tech.get("technique_name", "—"))
        tactic = _e(tech.get("tactic", "—"))
        sev = _e(tech.get("severity", "—")).upper()
        url = _e(tech.get("url", "#"))

        # Determine severity color
        sev_color = "#ef4444" if sev in ("CRITICAL", "HIGH") else "#f59e0b"

        rows += f"""
        <tr>
          <td style="padding:8px 12px;">
            <span style="background:#00ff8822;color:#00ff88;padding:2px 8px;
              border-radius:5px;font-size:.78rem;border:1px solid #00ff8844">{tid}</span>
          </td>
          <td style="padding:8px 12px;font-weight:600;color:#f1f5f9">{name}</td>
          <td style="padding:8px 12px;color:#94a3b8">{tactic}</td>
          <td style="padding:8px 12px;">
            <span style="color:{sev_color};font-weight:700;font-size:0.8rem">{sev}</span>
          </td>
          <td style="padding:8px 12px;font-family:monospace;font-size:.82rem;">
            <a href="{url}" target="_blank" style="color:#00ff88;text-decoration:none">{url}</a>
          </td>
        </tr>"""

    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:24px;margin-bottom:20px;
                border-left:4px solid #00ff88; border: 1px solid #334155;">
      <h3 style="margin:0 0 16px;color:#f1f5f9">🛡️ MITRE ATT&CK® Mapping</h3>
      <table style="width:100%;border-collapse:collapse;font-size:.9rem">
        <thead>
          <tr style="background:#0f172a;color:#94a3b8;text-align:left">
            <th style="padding:8px 12px;width:15%">Technique ID</th>
            <th style="padding:8px 12px;width:30%">Technique Name</th>
            <th style="padding:8px 12px;width:20%">Tactic</th>
            <th style="padding:8px 12px;width:10%">Severity</th>
            <th style="padding:8px 12px;width:25%">Reference URL</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


# ── Main HTML generator ───────────────────────────────────────────────────────

def generate_html_report(scan_result: dict,
                          remediation_result: Optional[dict] = None) -> str:
    host        = scan_result.get("host", "localhost")
    risk        = scan_result.get("risk_level", "unknown")
    total       = scan_result.get("total_threats", 0)
    score       = scan_result.get("weighted_score", 0)
    risk_col    = _risk_colour(risk)
    generated   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    scan_ts     = scan_result.get("timestamp", generated)

    modules_html     = ""
    for mod_name, mod in scan_result.get("modules", {}).items():
        modules_html += _module_section(mod_name, mod)

    ioc_html         = _ioc_section(scan_result)
    mitre_html       = _mitre_section(scan_result)
    remediation_html = _remediation_section(remediation_result)
    num_modules      = len(scan_result.get("modules", {}))

    # Build CSS separately to avoid curly-brace conflicts with f-string
    css = (
        "*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "body { font-family: 'Inter', sans-serif; background: #0f172a; color: #e2e8f0;"
        "  padding: 40px 20px; min-height: 100vh; }\n"
        ".container { max-width: 960px; margin: 0 auto; }\n"
        ".header { background: linear-gradient(135deg, #1e293b, #0f172a);"
        "  border: 1px solid #334155; border-radius: 16px; padding: 36px;"
        "  margin-bottom: 32px; text-align: center; }\n"
        f".logo {{ font-size: 2.4rem; font-weight: 800; color: #f1f5f9; letter-spacing: -1px; }}\n"
        f".logo span {{ color: {risk_col}; }}\n"
        ".meta { color: #64748b; font-size: 0.9rem; margin-top: 8px; }\n"
        f".risk-badge {{ display: inline-block; margin-top: 20px; padding: 10px 32px;"
        f"  background: {risk_col}22; border: 2px solid {risk_col};"
        "  border-radius: 100px; font-size: 1.4rem; font-weight: 800;"
        f"  color: {risk_col}; letter-spacing: 2px; text-transform: uppercase; }}\n"
        ".stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }\n"
        ".stat-card { background: #1e293b; border-radius: 12px; padding: 20px;"
        "  text-align: center; border: 1px solid #334155; }\n"
        ".stat-card .value { font-size: 2rem; font-weight: 800; color: #f1f5f9;"
        "  font-family: 'JetBrains Mono', monospace; }\n"
        ".stat-card .label { color: #64748b; font-size: 0.82rem; margin-top: 4px; }\n"
        "h2 { color: #f1f5f9; margin-bottom: 20px; font-size: 1.2rem; }\n"
        "table { width: 100%; border-collapse: collapse; table-layout: fixed; }\n"
        "table td, table th { padding: 8px 12px; word-break: break-all; }\n"
        "tr:nth-child(even) { background: #0f172a44; }\n"
        ".footer { text-align: center; color: #475569; font-size: 0.82rem; margin-top: 40px; }\n"
    )

    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '  <meta charset="UTF-8" />\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0" />\n'
        f'  <title>RootSentry Report — {_e(host)}</title>\n'
        '  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700'
        '&family=JetBrains+Mono&display=swap" rel="stylesheet"/>\n'
        f'  <style>\n{css}  </style>\n'
        '</head>\n'
        '<body>\n'
        '<div class="container">\n'
        '  <div class="header">\n'
        '    <div class="logo">Root<span>Sentry</span></div>\n'
        f'    <div class="meta">Target: <b>{_e(host)}</b> &nbsp;|&nbsp; '
        f'Scanned: {_e(scan_ts)} &nbsp;|&nbsp; Report: {generated}</div>\n'
        f'    <div class="risk-badge">{_e(risk)}</div>\n'
        '  </div>\n'
        '  <div class="stats-row">\n'
        f'    <div class="stat-card"><div class="value" style="color:{risk_col}">{total}</div>'
        '<div class="label">Total Threats</div></div>\n'
        f'    <div class="stat-card"><div class="value">{score}</div>'
        '<div class="label">Anomaly Score</div></div>\n'
        f'    <div class="stat-card"><div class="value">{num_modules}</div>'
        '<div class="label">Modules Run</div></div>\n'
        f'    <div class="stat-card"><div class="value" style="font-size:1.1rem;padding-top:6px">{_e(host)}</div>'
        '<div class="label">Target Host</div></div>\n'
        '  </div>\n'
        f'  {ioc_html}\n'
        f'  {mitre_html}\n'
        '  <h2>Detection Results</h2>\n'
        f'  {modules_html}\n'
        f'  {remediation_html}\n'
        '  <div class="footer">Generated by RootSentry &mdash; '
        'Linux Rootkit Detection &amp; Remediation Tool</div>\n'
        '</div>\n'
        '</body>\n'
        '</html>'
    )


# ── Save helpers ──────────────────────────────────────────────────────────────

def save_report(scan_result: dict,
               remediation_result: Optional[dict] = None,
               fmt: str = "html",
               output_dir: str = REPORTS_DIR,
               scan_id: Optional[str] = None) -> str:
    """Generate and save a report. Returns the file path.
    
    Uses a stable filename based on scan_id when provided, so repeated
    calls for the same scan don't fill disk with duplicate files.
    """
    os.makedirs(output_dir, exist_ok=True)

    try:
        html_content = generate_html_report(scan_result, remediation_result)
    except Exception as exc:
        # Fallback: return a minimal error report so the route never 500s
        host = scan_result.get("host", "localhost")
        html_content = (
            '<!DOCTYPE html><html><head><meta charset="UTF-8"/>'
            f'<title>RootSentry Report Error</title></head><body>'
            f'<h1 style="color:#ef4444">Report generation failed</h1>'
            f'<p>Host: {_e(host)}</p>'
            f'<pre style="color:#94a3b8">{_e(str(exc))}</pre>'
            '</body></html>'
        )

    # Use stable name if scan_id given; otherwise timestamp-based
    if scan_id:
        safe_id = scan_id.replace("/", "_").replace("\\", "_")
        stem = f"report_{safe_id}"
    else:
        host = scan_result.get("host", "localhost").replace(".", "_")
        ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        stem = f"report_{host}_{ts}"

    if fmt == "pdf":
        try:
            from weasyprint import HTML as WP_HTML
            pdf_path = os.path.join(output_dir, f"{stem}.pdf")
            WP_HTML(string=html_content).write_pdf(pdf_path)
            return pdf_path
        except ImportError:
            fmt = "html"   # fallback to HTML if weasyprint not installed
        except Exception:
            fmt = "html"

    html_path = os.path.join(output_dir, f"{stem}.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return html_path
