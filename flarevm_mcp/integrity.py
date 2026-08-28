"""Integrity and availability primitives (see SECURITY.md).

* Tool-binary manifest: SHA256 of every analysis tool on the VM, recorded
  against a clean snapshot and checked before a tool is executed. A hostile
  sample that replaces diec.exe/capa.exe to poison results is caught unless it
  also subverts PowerShell's Get-FileHash — the manifest raises the bar; the
  snapshot revert is the real trust anchor.
* VM state tracker: remembers whether a detonation has happened since the last
  snapshot revert so composite playbooks refuse to stack detonations on a
  dirty VM unless the caller explicitly acknowledges it.
* Snapshot hooks: hypervisor commands run on the analyst host.
"""
import asyncio
import datetime
import json
import logging
import os
import shutil
import threading
import time

from . import config
from .psquote import ps_quote
from .registry import ToolError
from .winrm_client import run_ps_async

LOG = logging.getLogger("flarevm-mcp.integrity")

_manifest = None
_manifest_mtime = None
_verified = {}          # tool_key -> monotonic time of last successful check
VERIFY_TTL = 300


def load_manifest(path=None):
    """Return the manifest dict or None. Re-reads when the file changes."""
    global _manifest, _manifest_mtime
    path = path or config.TOOL_MANIFEST
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        _manifest, _manifest_mtime = None, None
        return None
    if _manifest is None or mtime != _manifest_mtime:
        with open(path, encoding="utf-8") as f:
            _manifest = json.load(f)
        _manifest_mtime = mtime
    return _manifest


def expected_hash(tool_key, path=None):
    m = load_manifest(path)
    if not m:
        return None
    entry = (m.get("tools") or {}).get(tool_key)
    return (entry or {}).get("sha256")


def compare(manifest_tools, observed):
    """Pure comparison used by verify_tools. observed: {key: (path, sha256|None)}."""
    report = {}
    for key, (path, sha) in observed.items():
        exp = (manifest_tools.get(key) or {}).get("sha256")
        if sha is None:
            status = "MISSING"
        elif exp is None:
            status = "UNLISTED"
        elif sha.lower() == exp.lower():
            status = "OK"
        else:
            status = "MISMATCH"
        report[key] = {"path": path, "sha256": sha, "expected": exp, "status": status}
    for key in manifest_tools:
        if key not in report:
            report[key] = {"path": manifest_tools[key].get("path"), "sha256": None,
                           "expected": manifest_tools[key].get("sha256"), "status": "MISSING"}
    return report


async def hash_remote_files(paths):
    """{key: path} -> {key: (path, sha256|None)} in one WinRM round trip."""
    lines = []
    for key, path in paths.items():
        lines.append(
            "try {{ $h = (Get-FileHash -LiteralPath {p} -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }} "
            "catch {{ $h = 'NONE' }}; Write-Output ('{k}|' + $h)".format(p=ps_quote(path), k=key))
    out, err, code = await run_ps_async("\n".join(lines), timeout=120)
    result = {}
    for line in out.splitlines():
        if "|" in line:
            k, h = line.strip().split("|", 1)
            result[k] = (paths.get(k), None if h == "NONE" else h)
    for k in paths:
        result.setdefault(k, (paths[k], None))
    return result


async def verify_binary(tool_key, path):
    """Raise ToolError if STRICT_INTEGRITY is on and the binary's hash differs from the manifest."""
    if not config.strict_integrity():
        return
    exp = expected_hash(tool_key)
    if not exp:
        return  # not in manifest → nothing to compare (verify_tools reports UNLISTED)
    last = _verified.get(tool_key)
    if last and time.monotonic() - last < VERIFY_TTL:
        return
    observed = await hash_remote_files({tool_key: path})
    _, sha = observed.get(tool_key, (path, None))
    if sha is None:
        raise ToolError("INTEGRITY: {} not found at {} (manifest lists it)".format(tool_key, path))
    if sha.lower() != exp.lower():
        raise ToolError(
            "INTEGRITY FAILURE: {} at {} has SHA256 {} but the manifest expects {}. The VM may be "
            "compromised — revert to a clean snapshot. (Set FLAREVM_STRICT_INTEGRITY=0 to override.)".format(
                tool_key, path, sha, exp))
    _verified[tool_key] = time.monotonic()


def write_manifest(observed, host, path=None):
    path = path or config.TOOL_MANIFEST
    data = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": host,
        "tools": {k: {"path": p, "sha256": s} for k, (p, s) in sorted(observed.items()) if s},
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    global _manifest
    _manifest = None
    _verified.clear()
    return data


# ── VM state tracking ────────────────────────────────────────────────────────

class VMState:
    """In-memory record of whether the VM has been dirtied since the last revert."""

    def __init__(self):
        self._lock = threading.Lock()
        self.state = "unknown"      # unknown | clean | dirty
        self.since = time.time()
        self.detonations = []       # (timestamp, description)

    def mark_dirty(self, what):
        with self._lock:
            self.state = "dirty"
            self.detonations.append((time.time(), what[:200]))
            self.detonations = self.detonations[-20:]

    def mark_clean(self, why):
        with self._lock:
            self.state = "clean"
            self.since = time.time()
            self.detonations = []
            LOG.info("VM marked clean: %s", why)

    def snapshot(self):
        return {"state": self.state, "since": self.since,
                "detonations_since_clean": [{"at": t, "what": w} for t, w in self.detonations]}


vm_state = VMState()


def require_clean_for(action, args):
    """Detonation guard. Raises unless the VM is not known-dirty or the caller acknowledged."""
    if not config.REQUIRE_CLEAN_SNAPSHOT or args.get("ack_dirty_vm"):
        return
    if vm_state.state == "dirty":
        prior = "; ".join(w for _, w in vm_state.detonations[-3:])
        raise ToolError(
            "VM is DIRTY: {} already ran since the last snapshot revert ({}). Refusing '{}' so results "
            "from different samples do not mix and a persistent implant cannot tamper with this run. "
            "Revert with vm_snapshot(action='revert') or pass ack_dirty_vm=true to proceed anyway.".format(
                len(vm_state.detonations), prior, action))


# ── Snapshot hooks (run on the analyst host) ─────────────────────────────────

def _hypervisor():
    if config.SNAPSHOT_LIST_CMD or config.SNAPSHOT_REVERT_CMD or config.SNAPSHOT_CREATE_CMD:
        return "custom"
    if not config.VM_ID:
        return None
    if config.VM_ID.lower().endswith(".vmx") and shutil.which("vmrun"):
        return "vmware"
    if shutil.which("VBoxManage"):
        return "virtualbox"
    if shutil.which("virsh"):
        return "libvirt"
    return None


def snapshot_command(action, name):
    """Return argv for the requested snapshot action or None if unconfigured."""
    hv = _hypervisor()
    vm = config.VM_ID or ""
    custom = {"list": config.SNAPSHOT_LIST_CMD, "revert": config.SNAPSHOT_REVERT_CMD,
              "create": config.SNAPSHOT_CREATE_CMD}[action]
    if custom:
        import shlex
        return [a.format(vm=vm, name=name) for a in shlex.split(custom)]
    if hv == "vmware":
        return {"list": ["vmrun", "listSnapshots", vm],
                "revert": ["vmrun", "revertToSnapshot", vm, name],
                "create": ["vmrun", "snapshot", vm, name]}[action]
    if hv == "virtualbox":
        return {"list": ["VBoxManage", "snapshot", vm, "list"],
                "revert": ["VBoxManage", "snapshot", vm, "restore", name],
                "create": ["VBoxManage", "snapshot", vm, "take", name]}[action]
    if hv == "libvirt":
        return {"list": ["virsh", "snapshot-list", vm, "--name"],
                "revert": ["virsh", "snapshot-revert", vm, name],
                "create": ["virsh", "snapshot-create-as", vm, name]}[action]
    return None


async def run_snapshot(action, name):
    argv = snapshot_command(action, name)
    if argv is None:
        raise ToolError(
            "No hypervisor configured. Set FLAREVM_VM_ID (path to .vmx / VirtualBox name / libvirt "
            "domain) or FLAREVM_SNAPSHOT_{LIST,REVERT,CREATE}_CMD with {vm} and {name} placeholders.")
    proc = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        proc.kill()
        raise ToolError("snapshot command timed out: {}".format(" ".join(argv))) from None
    text = (out.decode("utf-8", "replace") + err.decode("utf-8", "replace")).strip()
    if proc.returncode != 0:
        raise ToolError("snapshot {} failed (rc={}): {}".format(action, proc.returncode, text[:500]))
    return text
