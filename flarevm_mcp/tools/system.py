"""System & file-transfer tools."""
import hashlib
import json
import logging

from .. import config
from ..guest import launch_gui_app
from ..psquote import first_error, ps_ident, ps_int, ps_path, ps_quote, win_arg
from ..registry import ToolError, tool
from ..transfer import download_file, upload_file
from ..winrm_client import breaker, run_ps_async

LOG = logging.getLogger("flarevm-mcp.audit")
_FMT = {"type": "string", "enum": ["text", "json"], "default": "text",
        "description": "Output format"}


@tool(
    "check_connection",
    description="Test WinRM connection to FlareVM. Returns hostname, OS info, and IP. Resets the circuit breaker on success.",
    schema={"type": "object", "properties": {"format": _FMT}, "required": []},
    timeout=30, untrusted=False, category="system",
)
async def _handle_check_connection(args):
    ps = r"""
$os = Get-CimInstance Win32_OperatingSystem
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.254\.' -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress
[pscustomobject]@{
  hostname = $env:COMPUTERNAME
  os = $os.Caption
  ip = @($ips) -join ', '
  uptime_s = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  user = $env:USERNAME
} | ConvertTo-Json -Compress
"""
    out, err, code = await run_ps_async(ps, timeout=25)
    if code != 0 or not out.strip():
        raise ToolError("Connection check failed: {} {}".format(err, out))
    info = json.loads(out.strip().splitlines()[-1])
    breaker.reset()
    info["breaker"] = "closed"
    if args.get("format") == "json":
        return info
    up = int(info.get("uptime_s") or 0)
    return ("=== FlareVM Connection OK ===\nHostname: {}\nOS: {}\nIP: {}\nUptime: {}d {}h {}m\nUser: {}".format(
        info.get("hostname"), info.get("os"), info.get("ip"), up // 86400, (up % 86400) // 3600,
        (up % 3600) // 60, info.get("user")))


@tool(
    "execute_powershell",
    description="Execute an arbitrary PowerShell command on FlareVM. Every command is audit-logged on the analyst host.",
    schema={"type": "object",
            "properties": {"command": {"type": "string", "description": "PowerShell command to execute"},
                           "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)", "default": 120}},
            "required": ["command"]},
    timeout=180, category="system",
)
async def _handle_execute_powershell(args):
    command = str(args["command"])
    timeout = ps_int(args.get("timeout", 120), 1, 170, "timeout")
    LOG.info("execute_powershell sha256=%s len=%d preview=%r",
             hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:16], len(command), command[:120])
    stdout, stderr, code = await run_ps_async(command, timeout=timeout)
    result = stdout or ""
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    result += "\n--- Exit Code: {} ---".format(code)
    return result


@tool(
    "read_file",
    description="Read a text file from FlareVM (truncated at max_bytes).",
    schema={"type": "object",
            "properties": {"file_path": {"type": "string", "description": "Absolute path on FlareVM"},
                           "encoding": {"type": "string", "description": "Encoding (default utf-8)", "default": "utf-8"},
                           "max_bytes": {"type": "integer", "description": "Max bytes to read (default 1MB)", "default": 1048576}},
            "required": ["file_path"]},
    timeout=60, category="system",
)
async def _handle_read_file(args):
    path = ps_path(args["file_path"], "file_path")
    encoding = ps_ident(args.get("encoding", "utf-8"), "encoding")
    max_bytes = ps_int(args.get("max_bytes", 1048576), 1, 16 * 1024 * 1024, "max_bytes")
    ps = """
$path = {path}
if (-not (Test-Path -LiteralPath $path)) {{ Write-Error "File not found: $path"; exit 1 }}
$size = (Get-Item -LiteralPath $path).Length
$enc = [System.Text.Encoding]::GetEncoding({enc})
if ($size -gt {max_bytes}) {{
    $fs = [System.IO.File]::OpenRead($path); $buf = New-Object byte[] {max_bytes}
    $n = $fs.Read($buf, 0, {max_bytes}); $fs.Close()
    Write-Output "--- TRUNCATED (showing first {max_bytes} of $size bytes) ---"
    Write-Output $enc.GetString($buf, 0, $n)
}} else {{
    Write-Output $enc.GetString([System.IO.File]::ReadAllBytes($path))
}}
""".format(path=path, enc=ps_quote(encoding), max_bytes=max_bytes)
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        raise ToolError(first_error(stderr, stdout))
    return stdout


@tool(
    "upload_file",
    description="Upload a file from Kali to FlareVM via SMB with end-to-end SHA256 verification. local_path must be under FLAREVM_ALLOWED_UPLOAD_ROOTS.",
    schema={"type": "object",
            "properties": {"local_path": {"type": "string", "description": "Path on Kali"},
                           "remote_path": {"type": "string", "description": "Destination path on FlareVM"},
                           "format": _FMT},
            "required": ["local_path", "remote_path"]},
    timeout=400, untrusted=False, category="system",
)
async def _handle_upload_file(args):
    ps_path(args["remote_path"], "remote_path")
    res = await upload_file(args["local_path"], args["remote_path"])
    if args.get("format") == "json":
        return res
    return "Upload OK (SMB)\nPath:   {}\nSize:   {:,} bytes\nSHA256: {}\nVerified: yes".format(
        res["remote_path"], res["size"], res["sha256"])


@tool(
    "download_file",
    description="Download a file from FlareVM to Kali via SMB with SHA256 verification. local_path must be under FLAREVM_ALLOWED_DOWNLOAD_ROOTS; the file is written 0600 and must never be executed on the host.",
    schema={"type": "object",
            "properties": {"remote_path": {"type": "string", "description": "Path on FlareVM"},
                           "local_path": {"type": "string", "description": "Destination path on Kali"},
                           "format": _FMT},
            "required": ["remote_path", "local_path"]},
    timeout=400, untrusted=False, category="system",
)
async def _handle_download_file(args):
    ps_path(args["remote_path"], "remote_path")
    res = await download_file(args["remote_path"], args["local_path"])
    if args.get("format") == "json":
        return res
    return "Download OK (SMB)\nRemote: {}\nLocal:  {}\nSize:   {:,} bytes\nSHA256: {}\nVerified: yes".format(
        res["remote_path"], res["local_path"], res["size"], res["sha256"])


@tool(
    "get_file_hash",
    description="Calculate MD5, SHA1 and SHA256 of a file on FlareVM.",
    schema={"type": "object",
            "properties": {"file_path": {"type": "string", "description": "Path on FlareVM"}, "format": _FMT},
            "required": ["file_path"]},
    timeout=60, category="system",
)
async def _handle_get_file_hash(args):
    path = ps_path(args["file_path"], "file_path")
    ps = """
$path = {path}
if (-not (Test-Path -LiteralPath $path)) {{ Write-Error "File not found: $path"; exit 1 }}
[pscustomobject]@{{
  file = $path
  size = (Get-Item -LiteralPath $path).Length
  md5 = (Get-FileHash -LiteralPath $path -Algorithm MD5).Hash.ToLower()
  sha1 = (Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash.ToLower()
  sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
}} | ConvertTo-Json -Compress
""".format(path=path)
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0 or not stdout.strip():
        raise ToolError(first_error(stderr, stdout))
    info = json.loads(stdout.strip().splitlines()[-1])
    if args.get("format") == "json":
        return info
    return ("=== File Hashes ===\nFile: {file}\nSize: {size} bytes\nMD5:    {md5}\nSHA1:   {sha1}\n"
            "SHA256: {sha256}").format(**info)


@tool(
    "list_processes",
    description="List running processes on FlareVM with optional name filter (wildcards allowed).",
    schema={"type": "object",
            "properties": {"filter": {"type": "string", "description": "Process name filter, e.g. 'mal*'"},
                           "format": _FMT},
            "required": []},
    timeout=30, category="system",
)
async def _handle_list_processes(args):
    flt = args.get("filter") or ""
    select = "Select-Object Id, ProcessName, CPU, WorkingSet64, Path"
    if flt:
        source = "Get-Process -Name {} -ErrorAction SilentlyContinue".format(ps_quote(ps_ident(flt, "filter")))
    else:
        source = "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50"
    if args.get("format") == "json":
        ps = "@({} | {}) | ConvertTo-Json -Compress".format(source, select)
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        if code != 0:
            raise ToolError(first_error(stderr, stdout))
        data = json.loads(stdout) if stdout.strip() else []
        return {"processes": data if isinstance(data, list) else [data]}
    ps = "{} | Format-Table Id, ProcessName, CPU, WorkingSet64, Path -AutoSize | Out-String -Width 200".format(source)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        raise ToolError(first_error(stderr, stdout))
    return "=== Running Processes ===\n" + stdout


@tool(
    "take_screenshot",
    description="Take a screenshot of the FlareVM desktop via nircmd in the interactive session.",
    schema={"type": "object",
            "properties": {"output_path": {"type": "string", "description": "Output PNG path", "default": "C:\\temp\\screenshot.png"}},
            "required": []},
    timeout=60, category="system",
)
async def _handle_take_screenshot(args):
    import asyncio
    raw = args.get("output_path", "C:\\temp\\screenshot.png")
    path = ps_path(raw, "output_path")
    await run_ps_async("New-Item -ItemType Directory -Path {} -Force | Out-Null".format(ps_quote(config.REMOTE_TEMP)), timeout=10)
    await launch_gui_app(config.TOOL_PATHS["nircmd"], arguments="savescreenshot " + win_arg(raw, "output_path"), task_name="MCP_Screenshot")
    await asyncio.sleep(2)
    ps = """
if (Test-Path -LiteralPath {p}) {{ Write-Output "Screenshot saved: {raw} ($((Get-Item -LiteralPath {p}).Length) bytes)" }}
else {{ Write-Output "WARNING: Screenshot file not found at {raw}" }}
""".format(p=path, raw=raw.replace('"', "'"))
    stdout, _, _ = await run_ps_async(ps, timeout=15)
    return stdout
