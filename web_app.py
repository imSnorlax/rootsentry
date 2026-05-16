"""
web_app.py — RootSentry Flask Web Dashboard
============================================
Routes:
  GET  /                     — Dashboard: scan history
  GET  /scan                 — Trigger a scan (form)
  POST /scan                 — Run scan (AJAX JSON)
  GET  /scan/<id>            — Scan detail page
  GET  /scan/<id>/json       — Scan raw JSON
  DELETE /scan/<id>          — Delete a scan record
  POST /remediate/<id>       — Remediate a scan result
  GET  /remediate/<id>/status — Poll remediation status
  GET  /report/<id>          — Download HTML report
  GET  /logs                 — Log viewer
  GET  /api/scans            — JSON list of all scans (paginated)
"""

from __future__ import annotations

import json
import os
import sys
import glob
import datetime
import threading
import time
import uuid
import logging

from flask import (Flask, render_template, request, jsonify,
                   send_file, abort, redirect, url_for)

# ── Ensure project root on path ───────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (FLASK_HOST, FLASK_PORT, FLASK_DEBUG, SECRET_KEY,
                    SCANS_DIR, REPORTS_DIR, LOG_FILE)
from modules.removal_engine   import remediate_scan
from modules.report_generator import save_report, generate_html_report

# ── Flask app setup ───────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Logging — absolute path so it works regardless of CWD ────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("rootsentry")

os.makedirs(SCANS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── In-progress scan tracking ─────────────────────────────────────────────────
# scan_id -> {"status": "running"|"done"|"error", "step": <str>, "result": ..., "_ts": float}
_running_scans: dict[str, dict] = {}
_lock = threading.Lock()

_running_remediations: dict[str, dict] = {}
_rem_lock = threading.Lock()

_TTL_SECONDS = 300   # evict in-memory entries after 5 minutes


def _evict_old_entries():
    """Remove done/error scan entries older than TTL from memory."""
    now = time.time()
    with _lock:
        stale = [k for k, v in _running_scans.items()
                 if v["status"] != "running" and now - v.get("_ts", now) > _TTL_SECONDS]
        for k in stale:
            del _running_scans[k]
    with _rem_lock:
        stale = [k for k, v in _running_remediations.items()
                 if v["status"] != "running" and now - v.get("_ts", now) > _TTL_SECONDS]
        for k in stale:
            del _running_remediations[k]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_path(scan_id: str) -> str:
    return os.path.join(SCANS_DIR, f"{scan_id}.json")


def _save_scan(scan_id: str, data: dict) -> None:
    with open(_scan_path(scan_id), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _load_scan(scan_id: str) -> dict | None:
    path = _scan_path(scan_id)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _list_scans() -> list[dict]:
    scans = []
    for path in sorted(glob.glob(os.path.join(SCANS_DIR, "*.json")), reverse=True):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            data["_id"] = os.path.splitext(os.path.basename(path))[0]
            scans.append(data)
        except Exception:
            pass
    return scans


def _run_scan_thread(scan_id: str, host: str | None,
                     password: str | None, user: str, port: int) -> None:
    def _progress(step: str):
        with _lock:
            if scan_id in _running_scans:
                _running_scans[scan_id]["step"] = step

    try:
        from scanner import run_scan
        # Bug fix: pass scan_id so scanner.py doesn't generate a second ID/file
        result = run_scan(host=host or None,
                          password=password or None,
                          user=user, port=port,
                          progress_cb=_progress,
                          scan_id=scan_id)
        result["id"]        = scan_id
        result["timestamp"] = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        _save_scan(scan_id, result)
        with _lock:
            _running_scans[scan_id] = {
                "status": "done", "step": "done",
                "result": result, "_ts": time.time()
            }
        log.info("Scan %s complete — %s", scan_id, result.get("risk_level"))
    except Exception as exc:
        err = {
            "status":        "error",
            "id":            scan_id,
            "error":         str(exc),
            "host":          host or "localhost",
            "risk_level":    "error",
            "total_threats": 0,
            "timestamp":     datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "modules":       {},
        }
        _save_scan(scan_id, err)
        with _lock:
            _running_scans[scan_id] = {
                "status": "error", "step": "error",
                "result": err, "_ts": time.time()
            }
        log.error("Scan %s failed: %s", scan_id, exc)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    _evict_old_entries()
    scans = _list_scans()
    return render_template("index.html", scans=scans)


@app.route("/scan", methods=["GET"])
def scan_form():
    return render_template("scan.html")


@app.route("/scan", methods=["POST"])
def scan_trigger():
    data     = request.get_json(silent=True) or request.form
    host     = (data.get("host") or "").strip() or None
    password = (data.get("password") or "").strip() or None
    user     = (data.get("user") or "root").strip()

    # Bug fix: validate port range
    try:
        port = int(data.get("port") or 22)
        port = max(1, min(65535, port))
    except (ValueError, TypeError):
        port = 22

    scan_id = str(uuid.uuid4())[:8]
    with _lock:
        _running_scans[scan_id] = {
            "status": "running", "step": "init",
            "result": None, "_ts": time.time()
        }

    t = threading.Thread(target=_run_scan_thread,
                         args=(scan_id, host, password, user, port),
                         daemon=True)
    t.start()
    log.info("Scan %s started — target: %s", scan_id, host or "localhost")

    if request.is_json:
        return jsonify({"scan_id": scan_id, "status": "running"})
    return redirect(url_for("scan_status_page", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_status_page(scan_id: str):
    with _lock:
        info = _running_scans.get(scan_id)

    if info and info["status"] == "running":
        return render_template("scan_running.html", scan_id=scan_id)

    result = _load_scan(scan_id)
    if result is None:
        abort(404)
    return render_template("scan_detail.html", scan=result, scan_id=scan_id)


@app.route("/scan/<scan_id>/json")
def scan_json(scan_id: str):
    with _lock:
        info = _running_scans.get(scan_id)
    if info:
        return jsonify({
            "scan_id": scan_id,
            "status":  info["status"],
            "step":    info.get("step", "init"),
            "result":  info.get("result"),
        })
    result = _load_scan(scan_id)
    if result is None:
        abort(404)
    return jsonify(result)


@app.route("/scan/<scan_id>", methods=["DELETE"])
def scan_delete(scan_id: str):
    """Delete a scan record and its JSON file."""
    path = _scan_path(scan_id)
    if not os.path.exists(path):
        return jsonify({"error": "Scan not found"}), 404
    try:
        os.remove(path)
        with _lock:
            _running_scans.pop(scan_id, None)
        log.info("Scan %s deleted", scan_id)
        return jsonify({"status": "deleted", "scan_id": scan_id})
    except OSError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/remediate/<scan_id>", methods=["POST"])
def remediate(scan_id: str):
    """Start an async remediation job and return immediately."""
    result = _load_scan(scan_id)
    if result is None:
        abort(404)

    with _rem_lock:
        if scan_id in _running_remediations and \
                _running_remediations[scan_id]["status"] == "running":
            return jsonify({"status": "running", "scan_id": scan_id})
        _running_remediations[scan_id] = {
            "status": "running", "result": None, "_ts": time.time()
        }

    data      = request.get_json(silent=True) or {}
    host      = result.get("host", "localhost")
    is_remote = host not in ("localhost", "127.0.0.1", "")

    ssh_creds: dict = {}
    if is_remote:
        password = data.get("password", "")
        if not password:
            with _rem_lock:
                _running_remediations.pop(scan_id, None)
            return jsonify({"error": "SSH password required for remote remediation"}), 400
        ssh_creds = {
            "host":     host,
            "port":     int(data.get("port", 22)),
            "user":     data.get("user", "root"),
            "password": password,
        }

    def _remediate_thread():
        ssh_client = None
        try:
            if ssh_creds:
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=ssh_creds["host"],
                    port=ssh_creds["port"],
                    username=ssh_creds["user"],
                    password=ssh_creds["password"],
                    timeout=10, allow_agent=False, look_for_keys=False,
                )
                ssh_client = client
                log.info("Opened SSH for remediation: %s@%s:%s",
                         ssh_creds["user"], ssh_creds["host"], ssh_creds["port"])

            rem = remediate_scan(result, ssh_client=ssh_client)
            result["remediation"] = rem
            result["risk_level"] = "remediated"
            result["remediation_note"] = (
                "Risk level updated after remediation — re-scan to confirm clean."
            )
            _save_scan(scan_id, result)
            log.info("Remediation for scan %s: %s", scan_id, rem["summary"])
            with _rem_lock:
                _running_remediations[scan_id] = {
                    "status": "done", "result": rem, "_ts": time.time()
                }
        except Exception as exc:
            log.error("Remediation thread for scan %s failed: %s", scan_id, exc)
            err = {"error": str(exc)}
            with _rem_lock:
                _running_remediations[scan_id] = {
                    "status": "error", "result": err, "_ts": time.time()
                }
        finally:
            if ssh_client:
                ssh_client.close()

    t = threading.Thread(target=_remediate_thread, daemon=True)
    t.start()
    return jsonify({"status": "running", "scan_id": scan_id})


@app.route("/remediate/<scan_id>/status", methods=["GET"])
def remediate_status(scan_id: str):
    with _rem_lock:
        info = _running_remediations.get(scan_id)

    if info is None:
        saved = _load_scan(scan_id)
        if saved and saved.get("remediation"):
            return jsonify({"status": "done", "result": saved["remediation"]})
        return jsonify({"status": "not_found",
                        "error": f"No remediation job found for scan {scan_id}"}), 404

    return jsonify({"status": info["status"], "result": info["result"]})


@app.route("/report/<scan_id>")
def report(scan_id: str):
    result = _load_scan(scan_id)
    if result is None:
        abort(404)
    rem  = result.get("remediation")
    path = save_report(result, rem, fmt="html", output_dir=REPORTS_DIR)
    return send_file(path, mimetype="text/html", as_attachment=False)


@app.route("/logs")
def logs_page():
    lines: list[str] = []
    try:
        # Bug fix: use absolute LOG_FILE path from config
        with open(LOG_FILE, encoding="utf-8") as fh:
            lines = fh.readlines()[-300:]
    except FileNotFoundError:
        pass
    return render_template("logs.html", lines=lines)


@app.route("/api/scans")
def api_scans():
    """Paginated scan list. Query params: ?limit=50&offset=0"""
    try:
        limit  = max(1, min(200, int(request.args.get("limit",  50))))
        offset = max(0,         int(request.args.get("offset",  0)))
    except (ValueError, TypeError):
        limit, offset = 50, 0

    all_scans = _list_scans()
    page      = all_scans[offset: offset + limit]
    return jsonify({
        "total":  len(all_scans),
        "limit":  limit,
        "offset": offset,
        "scans":  page,
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[*] RootSentry dashboard at http://{FLASK_HOST}:{FLASK_PORT}")
    if FLASK_DEBUG:
        print("[!] WARNING: Debug mode is ON — set ROOTSENTRY_DEBUG=1 only in development")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
