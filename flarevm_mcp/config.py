"""Configuration: process environment first, then an optional .env next to the
top-level server.py. Nothing is hardcoded; a missing FLAREVM_HOST or password is
a loud startup error, never a silent default.

Every value is a plain module attribute so tests can monkeypatch it; functions
that need config read the attribute at call time.
"""
import logging
import os
import socket
import sys

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_PKG_DIR)
_DOTENV_PATH = os.path.join(REPO_ROOT, ".env")

LOG = logging.getLogger("flarevm-mcp")
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")


class ConfigError(RuntimeError):
    """Raised when a required setting is missing or invalid."""


def _load_dotenv(path=_DOTENV_PATH):
    """Populate os.environ from KEY=VALUE lines without overriding existing vars."""
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass


_load_dotenv()


def _env_int(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError("{} must be an integer, got {!r}".format(name, raw)) from exc


def _env_bool(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_paths(name, default):
    raw = os.environ.get(name)
    items = raw.split(":") if raw else default
    return [os.path.realpath(os.path.expanduser(p)) for p in items if p]


# ── VM endpoint ──────────────────────────────────────────────────────────────
FLAREVM_HOST = os.environ.get("FLAREVM_HOST")  # validated in require_host()
FLAREVM_USER = os.environ.get("FLAREVM_USER", "xtemp")
WINRM_SCHEME = os.environ.get("FLAREVM_WINRM_SCHEME", "http").lower()
WINRM_PORT = _env_int("FLAREVM_WINRM_PORT", 5986 if WINRM_SCHEME == "https" else 5985)
CA_BUNDLE = os.environ.get("FLAREVM_CA_BUNDLE") or None

# ── WinRM behaviour / availability ───────────────────────────────────────────
MAX_WORKERS = _env_int("FLAREVM_MAX_WORKERS", 16)
MAX_CONCURRENT = _env_int("FLAREVM_MAX_CONCURRENT", 4)
MAX_OUTPUT = _env_int("FLAREVM_MAX_OUTPUT", 1024 * 1024)
READ_TIMEOUT = _env_int("FLAREVM_READ_TIMEOUT", 60)
OPERATION_TIMEOUT = _env_int("FLAREVM_OPERATION_TIMEOUT", 30)
BREAKER_THRESHOLD = _env_int("FLAREVM_BREAKER_THRESHOLD", 3)
BREAKER_COOLDOWN = _env_int("FLAREVM_BREAKER_COOLDOWN", 30)
SMB_TIMEOUT = _env_int("FLAREVM_SMB_TIMEOUT", 300)

# ── File transfer ────────────────────────────────────────────────────────────
SMB_SHARE_NAME = os.environ.get("FLAREVM_SMB_SHARE", "KaliShare")
SMB_LOCAL_PATH = os.environ.get("FLAREVM_SMB_LOCAL_PATH", "C:\\Share")
REMOTE_TEMP = os.environ.get("FLAREVM_REMOTE_TEMP", "C:\\temp")
ALLOWED_UPLOAD_ROOTS = _env_paths("FLAREVM_ALLOWED_UPLOAD_ROOTS",
                                  ["~/Desktop", "~/Downloads"])
ALLOWED_DOWNLOAD_ROOTS = _env_paths("FLAREVM_ALLOWED_DOWNLOAD_ROOTS",
                                    ["~/Desktop/analysis"])

# ── Integrity ────────────────────────────────────────────────────────────────
TOOL_MANIFEST = os.path.expanduser(
    os.environ.get("FLAREVM_TOOL_MANIFEST", os.path.join(REPO_ROOT, "tool_manifest.json")))
_strict_raw = os.environ.get("FLAREVM_STRICT_INTEGRITY")
# Default: strict once a manifest exists; explicit env always wins.
STRICT_INTEGRITY = (_strict_raw.strip().lower() in ("1", "true", "yes", "on")
                    if _strict_raw else os.path.isfile(TOOL_MANIFEST))

# ── Snapshot / hypervisor hooks ──────────────────────────────────────────────
VM_ID = os.environ.get("FLAREVM_VM_ID") or None
SNAPSHOT_LIST_CMD = os.environ.get("FLAREVM_SNAPSHOT_LIST_CMD") or None
SNAPSHOT_REVERT_CMD = os.environ.get("FLAREVM_SNAPSHOT_REVERT_CMD") or None
SNAPSHOT_CREATE_CMD = os.environ.get("FLAREVM_SNAPSHOT_CREATE_CMD") or None
CLEAN_SNAPSHOT = os.environ.get("FLAREVM_CLEAN_SNAPSHOT", "clean")
REQUIRE_CLEAN_SNAPSHOT = _env_bool("FLAREVM_REQUIRE_CLEAN_SNAPSHOT", True)

# ── Guest-side services ──────────────────────────────────────────────────────
IDA_MCP_PORT = _env_int("IDA_MCP_PORT", 13337)
WINDBG_MCP_PORT = _env_int("WINDBG_MCP_PORT", 13338)

TOOL_PATHS = {
    "die": "C:\\Tools\\die\\diec.exe",
    "floss": "C:\\Tools\\FLOSS\\floss.exe",
    "capa": "C:\\Tools\\capa\\capa.exe",
    "yara": "C:\\Tools\\yara\\yara64.exe",
    "procmon": "C:\\Tools\\sysinternals\\Procmon.exe",
    "autorunsc": "C:\\Tools\\sysinternals\\autorunsc.exe",
    "strings": "C:\\Tools\\sysinternals\\strings.exe",
    "pe_sieve": "C:\\ProgramData\\chocolatey\\bin\\pe-sieve.exe",
    "hollows_hunter": "C:\\Tools\\hollows_hunter\\hollows_hunter.exe",
    "upx": "C:\\Tools\\upx\\upx.exe",
    "dnspy": "C:\\Tools\\dnSpy\\dnSpy.Console.exe",
    "fakenet": "C:\\Tools\\fakenet\\fakenet3.5\\fakenet.exe",
    "nircmd": "C:\\Tools\\nircmd.exe",
    "x64dbg": "C:\\ProgramData\\chocolatey\\bin\\x64dbg.exe",
    "tshark": "C:\\ProgramData\\chocolatey\\bin\\tshark.exe",
}

DEFAULT_TOOL_TIMEOUT = 300

_password_cache = None


def get_password():
    """Keyring (service 'flarevm', username FLAREVM_USER) → FLAREVM_PASSWORD env → error.
    There is deliberately no default password."""
    global _password_cache
    if _password_cache:
        return _password_cache
    pw = None
    try:
        import keyring
        pw = keyring.get_password("flarevm", FLAREVM_USER)
    except Exception as exc:  # keyring backend missing (Docker, CI)
        LOG.warning("Keyring unavailable (%s); falling back to FLAREVM_PASSWORD", exc)
    if not pw:
        pw = os.environ.get("FLAREVM_PASSWORD")
    if not pw:
        raise ConfigError(
            "No FlareVM password: store one with flarevm_setup.py (keyring service 'flarevm', "
            "user '{}') or set FLAREVM_PASSWORD. There is deliberately no default.".format(FLAREVM_USER))
    _password_cache = pw
    return pw


def require_host():
    """Startup guard: refuse to serve without a VM address."""
    if not FLAREVM_HOST:
        sys.exit(
            "FLAREVM_HOST is not set. Put it in the MCP server 'env' block, export it, "
            "or copy .env.example to .env next to server.py. There is deliberately no default.")
    if WINRM_SCHEME not in ("http", "https"):
        sys.exit("FLAREVM_WINRM_SCHEME must be 'http' or 'https'")
    if OPERATION_TIMEOUT >= READ_TIMEOUT:
        sys.exit("FLAREVM_READ_TIMEOUT must exceed FLAREVM_OPERATION_TIMEOUT")


def winrm_endpoint():
    return "{}://{}:{}/wsman".format(WINRM_SCHEME, FLAREVM_HOST, WINRM_PORT)


def smb_share_path():
    """UNC path of the VM share, derived at call time from FLAREVM_HOST."""
    return "//{}/{}".format(FLAREVM_HOST, SMB_SHARE_NAME)


def detect_kali_ip():
    """Analyst-host IP facing FLAREVM_HOST: KALI_IP env → routing-table lookup → None."""
    env_ip = os.environ.get("KALI_IP")
    if env_ip:
        return env_ip
    if not FLAREVM_HOST:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((FLAREVM_HOST, WINRM_PORT))
            return s.getsockname()[0]
    except OSError:
        return None
