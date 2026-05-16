# config.py — RootSentry global configuration
import os

# ── SSH defaults ─────────────────────────────────────────────────────────────
DEFAULT_SSH_PORT    = 22
DEFAULT_SSH_USER    = "root"
DEFAULT_SSH_TIMEOUT = 10          # seconds

# ── Risk thresholds ──────────────────────────────────────────────────────────
RISK_CLEAN      = 0
RISK_SUSPICIOUS = 1              # 1–2 threats
RISK_INFECTED   = 3              # 3+ threats

# ── Anomaly score weights ────────────────────────────────────────────────────
# Used by the weighted risk scorer (higher = more severe finding)
SCORE_WEIGHTS = {
    "hidden_process":    10,   # process invisible to getdents64/ps
    "rootkit_module":    20,   # known rootkit LKM loaded
    "suspicious_symbol": 15,   # kallsyms symbol matches rootkit name
    "hidden_symbol":     12,   # kallsyms address zeroed with kptr_restrict=0
    "hidden_port":       15,   # port in /proc/net/tcp absent from ss
    "suspicious_suid":   18,   # SUID binary in /tmp or /dev/shm
    "world_writable":     5,   # world-writable file in /etc or /usr
    "rootkit_path":      20,   # known rootkit indicator path exists
    "suspicious_socket": 10,   # socket owned by unknown/suspicious process
    "suspicious_file":   12,   # suspicious filename pattern in temp dir
}
SCORE_SUSPICIOUS_THRESHOLD = 10   # weighted score ≥ this → suspicious
SCORE_INFECTED_THRESHOLD   = 30   # weighted score ≥ this → infected

# ── Known rootkit signatures ──────────────────────────────────────────────────
KNOWN_ROOTKITS = [
    # ── ftrace-based LKM rootkits ──────────────────────────────────────────
    "caraxes",
    # ── syscall-table LKM rootkits ─────────────────────────────────────────
    "diamorphine",
    "reptile",
    "suterusu",
    "adore-ng",
    "knark",
    "modhide",
    "kbeast",
    "tyton",           # modern ftrace rootkit
    "reveng_rtkit",    # recent eBPF/LKM hybrid
    "skula",           # LKM rootkit (2022+)
    # ── LD_PRELOAD / userland rootkits ─────────────────────────────────────
    "azazel",
    "beurk",
    "necurs",
    "jynx",
    "bdvl",            # modern LD_PRELOAD rootkit
    "libprocesshider", # LD_PRELOAD process hider
    # ── eBPF-based rootkits ────────────────────────────────────────────────
    "ebpfkit",
    "boopkit",
    # ── Bootkits / firmware rootkits (user-mode indicators) ───────────────
    "blacklotus",
]

# ── Suspicious kallsyms symbols ───────────────────────────────────────────────
SUSPICIOUS_KALLSYMS = [
    # Only flag symbols that are specifically HOOKED by rootkits
    # (not symbols that normally exist in all kernels)
    # Classic syscall-table hook markers
    "sys_call_table",
    "ia32_sys_call_table",
    # Network-layer hooks used by rootkits
    "tcp4_seq_show",
    "packet_rcv",
    "tpacket_rcv",
    # Audit subsystem hooks
    "audit_log_exit",
    # eBPF abuse hooks
    "bpf_prog_load",
    "security_bpf",
    # Note: getdents64, getdents, filldir, filldir64, do_fork are present
    # in ALL Linux kernels and must NOT be flagged as suspicious alone.
    # RootSentry detects their HOOKING via baseline comparison instead.
]

# ── Known rootkit indicator paths ────────────────────────────────────────────
# These paths existing on a system are strong rootkit indicators
ROOTKIT_INDICATOR_PATHS = [
    "/proc/diamorphine",
    "/proc/reptile",
    "/proc/.azazel",
    "/proc/.caraxes",
    "/dev/hda",           # fake device node used by some rootkits
    "/etc/.bdvl",
    # Note: /tmp/.x and /lib/.x removed — Kali temp files may legitimately
    # match these patterns and cause false positives on clean systems.
]

# ── Paths ────────────────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(_BASE_DIR, "reports")
SCANS_DIR   = os.path.join(_BASE_DIR, "scans")    # JSON scan results
LOG_FILE    = os.path.join(_BASE_DIR, "rootsentry.log")

# ── Flask ────────────────────────────────────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5000
# Security: debug mode MUST NOT be on in production.
# Set env var ROOTSENTRY_DEBUG=1 to enable during development only.
FLASK_DEBUG = os.environ.get("ROOTSENTRY_DEBUG", "0") == "1"
SECRET_KEY  = os.environ.get(
    "ROOTSENTRY_SECRET_KEY",
    "rootsentry-change-me-in-production-use-ROOTSENTRY_SECRET_KEY-env"
)
