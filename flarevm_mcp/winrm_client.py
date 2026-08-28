"""WinRM execution layer.

Availability design (see docs/HARDENING_PLAN.md §4.3):
  * one pywinrm Session per worker thread (requests.Session is not thread-safe);
  * an asyncio semaphore caps concurrent WinRM operations so a burst of tool
    calls cannot exhaust the executor or swamp the VM;
  * a circuit breaker fails fast after repeated timeouts/connection errors
    instead of letting every call wait out its full timeout;
  * stdout/stderr are hard-capped so a hostile sample cannot flood the client;
  * explicit pywinrm read/operation timeouts so hung HTTP reads actually end.

Tests replace ``run_ps`` (the sync seam) — everything above it is pure Python.
"""
import asyncio
import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import config
from .psquote import cap_output, sanitize_output

LOG = logging.getLogger("flarevm-mcp.winrm")

_executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS, thread_name_prefix="winrm")
_tls = threading.local()
_generation = 0
_sems = {}


class VMUnavailable(RuntimeError):
    """The VM is unreachable, or the circuit breaker is open."""


class CircuitBreaker:
    def __init__(self, threshold, cooldown):
        self.threshold = threshold
        self.cooldown = cooldown
        self.failures = 0
        self.open_until = 0.0
        self.last_error = ""
        self._lock = threading.Lock()

    @property
    def is_open(self):
        return time.monotonic() < self.open_until

    def check(self):
        if self.is_open:
            remaining = int(self.open_until - time.monotonic()) + 1
            raise VMUnavailable(
                "Circuit breaker OPEN: {} consecutive WinRM failures (last: {}). Failing fast for "
                "{}s more. Call check_connection to probe the VM and reset.".format(
                    self.failures, self.last_error or "timeout", remaining))

    def failure(self, reason=""):
        with self._lock:
            self.failures += 1
            self.last_error = reason[:200]
            if self.failures >= self.threshold:
                self.open_until = time.monotonic() + self.cooldown
                LOG.error("circuit breaker opened after %d failures (%s)", self.failures, reason)

    def success(self):
        with self._lock:
            self.failures = 0
            self.open_until = 0.0

    def reset(self):
        self.success()

    def snapshot(self):
        return {
            "state": "open" if self.is_open else "closed",
            "consecutive_failures": self.failures,
            "threshold": self.threshold,
            "last_error": self.last_error,
            "seconds_until_retry": max(0, int(self.open_until - time.monotonic())) if self.is_open else 0,
        }


breaker = CircuitBreaker(config.BREAKER_THRESHOLD, config.BREAKER_COOLDOWN)


def _new_session():
    import winrm  # imported lazily so the module is importable without pywinrm in tests
    kwargs = dict(
        transport="ntlm",
        read_timeout_sec=config.READ_TIMEOUT,
        operation_timeout_sec=config.OPERATION_TIMEOUT,
    )
    if config.WINRM_SCHEME == "https":
        if config.CA_BUNDLE:
            kwargs["server_cert_validation"] = "validate"
            kwargs["ca_trust_path"] = config.CA_BUNDLE
        else:
            kwargs["server_cert_validation"] = "ignore"
            LOG.warning("HTTPS without FLAREVM_CA_BUNDLE: server certificate is NOT validated")
    return winrm.Session(config.winrm_endpoint(),
                         auth=(config.FLAREVM_USER, config.get_password()), **kwargs)


def _session():
    if getattr(_tls, "gen", None) != _generation or getattr(_tls, "session", None) is None:
        _tls.session = _new_session()
        _tls.gen = _generation
    return _tls.session


def reset_sessions():
    """Force every worker thread to build a fresh session on its next call."""
    global _generation
    _generation += 1
    LOG.warning("WinRM sessions reset (generation %d)", _generation)


def _decode(raw):
    text = raw.decode("utf-8", errors="replace").strip()
    return cap_output(sanitize_output(text), config.MAX_OUTPUT)


def run_ps(command):
    """Synchronous WinRM call. Returns (stdout, stderr, status_code). Runs in a worker thread."""
    result = _session().run_ps(command)
    return _decode(result.std_out), _decode(result.std_err), result.status_code


def _semaphore():
    loop = asyncio.get_running_loop()
    sem = _sems.get(id(loop))
    if sem is None:
        sem = _sems[id(loop)] = asyncio.Semaphore(config.MAX_CONCURRENT)
    return sem


def _is_transport_error(exc):
    name = type(exc).__name__
    mod = type(exc).__module__ or ""
    return (mod.startswith("winrm") or mod.startswith("requests") or mod.startswith("urllib3")
            or isinstance(exc, (ConnectionError, OSError)) or "WinRM" in name)


async def run_ps_async(command, timeout=120):
    """Run PowerShell via WinRM with an asyncio-level timeout.

    Returns (stdout, stderr, code). A timeout returns code 1 with a TIMEOUT
    message and resets the sessions (the worker thread cannot be killed; it
    ends when pywinrm's read timeout fires). Transport errors raise
    VMUnavailable so callers/dispatch can surface them as tool errors.
    """
    breaker.check()
    loop = asyncio.get_running_loop()
    digest = hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:12]
    LOG.debug("winrm run len=%d sha=%s timeout=%s", len(command), digest, timeout)
    async with _semaphore():
        fut = asyncio.shield(loop.run_in_executor(_executor, run_ps, command))
        try:
            out, err, code = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            reset_sessions()
            breaker.failure("timeout after {}s".format(timeout))
            return ("", "TIMEOUT: PowerShell command did not respond within {}s — WinRM session reset".format(timeout), 1)
        except Exception as exc:
            if _is_transport_error(exc):
                reset_sessions()
                breaker.failure("{}: {}".format(type(exc).__name__, exc))
                raise VMUnavailable("WinRM transport error: {}: {}".format(type(exc).__name__, exc)) from exc
            raise
    breaker.success()
    return out, err, code
