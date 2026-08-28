"""File transfer and script staging over SMB.

Integrity design (docs/HARDENING_PLAN.md §4.2):
  * every staged file gets a UUID name — concurrent calls cannot collide;
  * a staged script is hash-verified, executed and deleted inside ONE
    PowerShell invocation, shrinking the tamper window to a single process;
  * uploads and downloads are SHA256-verified end to end;
  * the SMB password travels in the PASSWD environment variable, never argv;
  * Kali-side paths are confined to allow-listed roots so a prompt-injected
    client cannot read ~/.ssh or write outside the analysis directory.
"""
import asyncio
import hashlib
import logging
import ntpath
import os
import shutil
import tempfile
import uuid

from . import config
from .psquote import ps_quote
from .registry import ToolError
from .winrm_client import run_ps_async

LOG = logging.getLogger("flarevm-mcp.transfer")


class PathNotAllowed(ToolError):
    pass


def check_local_path(path, roots, must_exist=False, what="path"):
    """Resolve *path* and require it to live under one of *roots*."""
    real = os.path.realpath(os.path.expanduser(str(path)))
    for root in roots:
        if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
            break
    else:
        raise PathNotAllowed(
            "{} {!r} is outside the allowed roots {}. Adjust FLAREVM_ALLOWED_UPLOAD_ROOTS / "
            "FLAREVM_ALLOWED_DOWNLOAD_ROOTS if this is intentional.".format(what, path, roots))
    if must_exist and not os.path.isfile(real):
        raise ToolError("{} not found: {}".format(what, path))
    return real


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def staging_name(prefix, ext):
    return "{}_{}{}".format(prefix, uuid.uuid4().hex, ext)


async def _smb_exec(command):
    """Run one smbclient command against the VM share. Returns (rc, stdout, stderr)."""
    env = dict(os.environ)
    env["PASSWD"] = config.get_password()
    argv = ["smbclient", config.smb_share_path(), "-U", config.FLAREVM_USER, "-c", command]
    proc = await asyncio.create_subprocess_exec(
        *argv, env=env, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=config.SMB_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        raise ToolError("smbclient timed out after {}s".format(config.SMB_TIMEOUT)) from None
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def smb_put(local_path, remote_name):
    rc, out, err = await _smb_exec('put "{}" "{}"'.format(local_path, remote_name))
    if rc != 0:
        raise ToolError("SMB upload failed: {} {}".format(err.strip(), out.strip()))


async def smb_get(remote_name, local_path):
    rc, out, err = await _smb_exec('get "{}" "{}"'.format(remote_name, local_path))
    if rc != 0:
        raise ToolError("SMB download failed: {} {}".format(err.strip(), out.strip()))


def _remote_temp(name):
    return config.REMOTE_TEMP.rstrip("\\") + "\\" + name


def _share_local(name):
    return config.SMB_LOCAL_PATH.rstrip("\\") + "\\" + name


INLINE_LIMIT = 1500  # pywinrm base64/UTF-16 expands scripts ~3x against an 8 KB command line


async def run_ps_script(script, timeout=300, script_name="mcp_script", force_stage=False):
    """Run a PowerShell script of any length.

    Short scripts go inline. Longer ones (or force_stage=True, needed when the
    script uses Invoke-WebRequest whose output inline mode can swallow) are
    staged via SMB under a unique name and then, in a single WinRM call,
    moved into place, SHA256-verified against the hash computed on Kali,
    executed, and deleted.
    """
    if not force_stage and len(script) < INLINE_LIMIT:
        return await run_ps_async(script, timeout=timeout)

    stem = ntpath.splitext(ntpath.basename(script_name))[0] or "mcp_script"
    name = staging_name(stem, ".ps1")
    data = script.encode("utf-8")
    expected = hashlib.sha256(data).hexdigest()

    tmp_root = tempfile.mkdtemp(prefix="flarevm-mcp-")
    local_tmp = os.path.join(tmp_root, name)
    try:
        with open(local_tmp, "wb") as f:
            f.write(data)
        await smb_put(local_tmp, name)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    remote = _remote_temp(name)
    runner = (
        "New-Item -ItemType Directory -Path {tmpdir} -Force | Out-Null\n"
        "Move-Item -LiteralPath {src} -Destination {dst} -Force\n"
        "$h = (Get-FileHash -LiteralPath {dst} -Algorithm SHA256).Hash.ToLower()\n"
        "if ($h -ne '{sha}') {{\n"
        "  Remove-Item -LiteralPath {dst} -Force -ErrorAction SilentlyContinue\n"
        "  Write-Error \"STAGED SCRIPT HASH MISMATCH: expected {sha} got $h - possible tampering on the VM\"\n"
        "  exit 99\n"
        "}}\n"
        "try {{ & powershell.exe -NoProfile -ExecutionPolicy Bypass -File {dst}; $rc = $LASTEXITCODE }}\n"
        "finally {{ Remove-Item -LiteralPath {dst} -Force -ErrorAction SilentlyContinue }}\n"
        "exit $rc\n"
    ).format(tmpdir=ps_quote(config.REMOTE_TEMP), src=ps_quote(_share_local(name)),
             dst=ps_quote(remote), sha=expected)
    out, err, code = await run_ps_async(runner, timeout=timeout)
    if code == 99:
        raise ToolError("Integrity failure: staged script was modified on the VM before execution. {}".format(err))
    return out, err, code


async def upload_file(local_path, remote_path):
    """Kali → VM with SHA256 verification. Returns a result dict."""
    real = check_local_path(local_path, config.ALLOWED_UPLOAD_ROOTS, must_exist=True, what="local_path")
    local_hash = sha256_file(real)
    size = os.path.getsize(real)
    name = staging_name("up", ntpath.splitext(ntpath.basename(remote_path))[1] or ".bin")
    await smb_put(real, name)
    ps = (
        "$dst = {dst}\n"
        "$dir = [System.IO.Path]::GetDirectoryName($dst)\n"
        "if ($dir -and -not (Test-Path -LiteralPath $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}\n"
        "Move-Item -LiteralPath {src} -Destination $dst -Force\n"
        "(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLower()\n"
    ).format(dst=ps_quote(remote_path), src=ps_quote(_share_local(name)))
    out, err, code = await run_ps_async(ps, timeout=120)
    if code != 0:
        raise ToolError("Move from SMB share failed: {} {}".format(err, out))
    remote_hash = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if remote_hash != local_hash:
        raise ToolError("HASH MISMATCH after upload\nPath: {}\nLocal:  {}\nRemote: {}".format(
            remote_path, local_hash, remote_hash))
    return {"status": "ok", "remote_path": remote_path, "size": size, "sha256": local_hash, "verified": True}


async def download_file(remote_path, local_path):
    """VM → Kali with SHA256 verification; local file is created 0600."""
    real = check_local_path(local_path, config.ALLOWED_DOWNLOAD_ROOTS, what="local_path")
    name = staging_name("dl", ntpath.splitext(ntpath.basename(remote_path))[1] or ".bin")
    ps = (
        "$p = {src}\n"
        "if (-not (Test-Path -LiteralPath $p)) {{ Write-Error \"File not found: $p\"; exit 1 }}\n"
        "$size = (Get-Item -LiteralPath $p).Length\n"
        "$hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()\n"
        "Copy-Item -LiteralPath $p -Destination {staged} -Force\n"
        "Write-Output \"$size $hash\"\n"
    ).format(src=ps_quote(remote_path), staged=ps_quote(_share_local(name)))
    out, err, code = await run_ps_async(ps, timeout=120)
    if code != 0:
        raise ToolError("Remote file error: {} {}".format(err, out))
    try:
        size_s, remote_hash = out.strip().splitlines()[-1].split()
        size = int(size_s)
    except (ValueError, IndexError):
        raise ToolError("Unexpected response while staging download: {!r}".format(out[:200])) from None
    os.makedirs(os.path.dirname(real) or ".", exist_ok=True)
    try:
        await smb_get(name, real)
    finally:
        await run_ps_async("Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue".format(
            ps_quote(_share_local(name))), timeout=15)
    os.chmod(real, 0o600)
    local_hash = sha256_file(real)
    if local_hash != remote_hash:
        raise ToolError("HASH MISMATCH after download\nRemote: {}\nLocal:  {}".format(remote_hash, local_hash))
    return {"status": "ok", "remote_path": remote_path, "local_path": real, "size": size,
            "sha256": local_hash, "verified": True}
