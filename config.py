# config.py — RootSentry global configuration

# ── SSH defaults ────────────────────────────────────────────────────────────
DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USER = "root"
DEFAULT_SSH_TIMEOUT = 10          # seconds

# ── Risk thresholds ─────────────────────────────────────────────────────────
RISK_CLEAN      = 0
RISK_SUSPICIOUS = 1              # 1–2 threats
RISK_INFECTED   = 3              # 3+ threats

# ── Known rootkit signatures ─────────────────────────────────────────────────
KNOWN_ROOTKITS = [
    "diamorphine",
    "reptile",
    "azazel",
    "beurk",
    "necurs",
    "suterusu",
    "adore-ng",
    "knark",
    "modhide",
    "kbeast",
]

# ── Suspicious kallsyms symbols ──────────────────────────────────────────────
SUSPICIOUS_KALLSYMS = [
    "sys_call_table",
    "ia32_sys_call_table",
    "do_fork",
    "tcp4_seq_show",
    "packet_rcv",
    "tpacket_rcv",
    "audit_log_exit",
]

# ── Paths ────────────────────────────────────────────────────────────────────
REPORTS_DIR  = "reports"
SCANS_DIR    = "scans"           # JSON scan results

# ── Flask ────────────────────────────────────────────────────────────────────
FLASK_HOST      = "0.0.0.0"
FLASK_PORT      = 5000
FLASK_DEBUG     = True
SECRET_KEY      = "rootsentry-secret-2024"
