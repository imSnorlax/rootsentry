"""
modules/report_generator.py
RootSentry — Report Generator
==============================
Generates an HTML scan report and optionally exports it to PDF.

Usage (standalone):
    from modules.report_generator import generate_html_report, save_report
    html = generate_html_report(scan_result)
    path = save_report(scan_result, fmt="html")   # or fmt="pdf"

PDF export requires weasyprint:
    pip install weasyprint
"""

from __future__ import annotations

import json
import os
import datetime
from typing import Optional


REPORTS_DIR = "reports"


# ── Colour / severity helpers ─────────────────────────────────────────────────

def _risk_colour(risk: str) -> str:
    return {"clean": "#22c55e", "suspicious": "#f59e0b", "infected": "#ef4444"}.get(
        risk.lower(), "#94a3b8"
    )


def _threat_badge(count: int) -> str:
    if count == 0:
        colour = "#22c55e"
    elif count <= 2:
        colour = "#f59e0b"
    else:
        colour = "#ef4444"
    return f'<span style="background:{colour};padding:2px 10px;border-radius:12px;color:#fff;font-weight:700">{count}</span>'


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return '<p style="color:#94a3b8;font-style:italic">No findings.</p>'
    rows = ""
    for f in findings:
        ftype  = f.get("type", "—")
        label  = (f.get("pid") or f.get("path") or f.get("port") or
                  f.get("module") or f.get("symbol") or "—")
        detail = f.get("detail", "—")
        colour = "#ef4444" if "rootkit" in ftype or "hidden" in ftype else "#f59e0b"
        rows += f"""
        <tr>
          <td><span style="background:{colour}22;color:{colour};padding:2px 8px;
              border-radius:6px;font-size:0.8rem">{ftype}</span></td>
          <td style="font-family:monospace">{label}</td>
          <td>{detail}</td>
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
    icon  = "✘" if mod.get("threat_count", 0) else "✔"
    colour = "#ef4444" if mod.get("threat_count", 0) else "#22c55e"
    table  = _findings_table(mod.get("findings", []))
    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:24px;margin-bottom:20px;
                border-left:4px solid {colour}">
      <h3 style="margin:0 0 8px;color:#f1f5f9">
        <span style="color:{colour}">{icon}</span>
        &nbsp;{mod_name}
        &nbsp;{_threat_badge(mod.get("threat_count", 0))}
      </h3>
      <p style="color:#94a3b8;margin:0 0 16px">{mod.get("summary", "")}</p>
      {table}
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
          <td style="padding:6px 12px">{a['timestamp']}</td>
          <td style="padding:6px 12px;font-weight:700">{a['action']}</td>
          <td style="padding:6px 12px;font-family:monospace">{a['target']}</td>
          <td style="padding:6px 12px;color:{ok_col};font-weight:700">{status}</td>
          <td style="padding:6px 12px;color:#94a3b8">{a.get('detail','')}</td>
        </tr>"""
    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:24px;margin-bottom:20px;
                border-left:4px solid #6366f1">
      <h3 style="margin:0 0 16px;color:#f1f5f9">🛠 Remediation Actions</h3>
      <p style="color:#94a3b8;margin:0 0 16px">{remediation.get('summary','')}</p>
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


# ── Main HTML generator ───────────────────────────────────────────────────────

def generate_html_report(scan_result: dict,
                          remediation_result: Optional[dict] = None) -> str:
    """
    Build a full, self-contained HTML report string from a scan result dict.
    """
    host        = scan_result.get("host", "localhost")
    risk        = scan_result.get("risk_level", "unknown")
    total       = scan_result.get("total_threats", 0)
    risk_col    = _risk_colour(risk)
    generated   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    scan_ts     = scan_result.get("timestamp", generated)

    # Build module sections
    modules_html = ""
    for mod_name, mod in scan_result.get("modules", {}).items():
        modules_html += _module_section(mod_name, mod)

    remediation_html = _remediation_section(remediation_result)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RootSentry Report — {host}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 40px 20px;
      min-height: 100vh;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{
      background: linear-gradient(135deg, #1e293b, #0f172a);
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 36px;
      margin-bottom: 32px;
      text-align: center;
    }}
    .logo {{ font-size: 2.4rem; font-weight: 800; color: #f1f5f9; letter-spacing: -1px; }}
    .logo span {{ color: {risk_col}; }}
    .meta {{ color: #64748b; font-size: 0.9rem; margin-top: 8px; }}
    .risk-badge {{
      display: inline-block;
      margin-top: 20px;
      padding: 10px 32px;
      background: {risk_col}22;
      border: 2px solid {risk_col};
      border-radius: 100px;
      color: {risk_col};
      font-size: 1.4rem;
      font-weight: 800;
      letter-spacing: 2px;
      text-transform: uppercase;
    }}
    .stats-row {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin-bottom: 32px;
    }}
    .stat-card {{
      background: #1e293b;
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      border: 1px solid #334155;
    }}
    .stat-card .value {{
      font-size: 2rem;
      font-weight: 800;
      color: #f1f5f9;
      font-family: 'JetBrains Mono', monospace;
    }}
    .stat-card .label {{ color: #64748b; font-size: 0.82rem; margin-top: 4px; }}
    h2 {{ color: #f1f5f9; margin-bottom: 20px; font-size: 1.2rem; }}
    table {{ table-layout: fixed; }}
    table td, table th {{ padding: 8px 12px; word-break: break-all; }}
    tr:nth-child(even) {{ background: #0f172a44; }}
    .footer {{ text-align: center; color: #475569; font-size: 0.82rem; margin-top: 40px; }}
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">Root<span>Sentry</span></div>
    <div class="meta">Target: <b>{host}</b> &nbsp;|&nbsp; Scanned: {scan_ts} &nbsp;|&nbsp; Report: {generated}</div>
    <div class="risk-badge">{risk}</div>
  </div>

  <div class="stats-row">
    <div class="stat-card">
      <div class="value" style="color:{risk_col}">{total}</div>
      <div class="label">Total Threats</div>
    </div>
    <div class="stat-card">
      <div class="value">{len(scan_result.get("modules", {}))}</div>
      <div class="label">Modules Run</div>
    </div>
    <div class="stat-card">
      <div class="value" style="font-size:1.1rem;padding-top:6px">{host}</div>
      <div class="label">Target Host</div>
    </div>
  </div>

  <h2>Detection Results</h2>
  {modules_html}

  {remediation_html}

  <div class="footer">
    Generated by RootSentry &mdash; Linux Rootkit Detection &amp; Remediation Tool
  </div>
</div>
</body>
</html>"""


# ── Save helpers ──────────────────────────────────────────────────────────────

def save_report(scan_result: dict,
                remediation_result: Optional[dict] = None,
                fmt: str = "html",
                output_dir: str = REPORTS_DIR) -> str:
    """
    Save a report to disk. Returns the path to the saved file.
    fmt = "html" | "pdf"
    """
    os.makedirs(output_dir, exist_ok=True)
    host = scan_result.get("host", "localhost").replace(".", "_")
    ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    stem = f"report_{host}_{ts}"

    html_content = generate_html_report(scan_result, remediation_result)

    if fmt == "pdf":
        try:
            from weasyprint import HTML as WP_HTML
            pdf_path = os.path.join(output_dir, f"{stem}.pdf")
            WP_HTML(string=html_content).write_pdf(pdf_path)
            return pdf_path
        except ImportError:
            # Fall back to HTML
            fmt = "html"

    html_path = os.path.join(output_dir, f"{stem}.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return html_path
