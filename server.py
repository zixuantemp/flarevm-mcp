#!/usr/bin/env python3
r"""
FlareVM MCP Server - Enhanced malware analysis bridge.

Controls a Windows FlareVM malware analysis VM (address from the required FLAREVM_HOST env) via WinRM.
Runs on Kali Linux. Exposes 48 tools to Claude Code for malware analysis.

Transport: MCP stdio (stdin/stdout)
Control: WinRM (pywinrm, ntlm transport)
File transfer: SMB only (//FlareVM/KaliShare -> C:\Share)
GUI tools: Windows Scheduled Tasks for interactive session
IDA Pro: Proxy to IDA MCP server on FlareVM (HTTP JSON-RPC port 13337)
"""

import asyncio
import hashlib
import json
import logging
import ntpath
import os
import socket
import subprocess
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor

import keyring
import winrm
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
    Prompt,
    PromptArgument,
    PromptMessage,
    GetPromptResult,
    Resource,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Configuration — process environment first, then an optional .env file next to
# this script (written by setup.py; see .env.example). Nothing is hardcoded.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DOTENV_PATH = os.path.join(_HERE, ".env")


def _load_dotenv(path=_DOTENV_PATH):
    """Populate os.environ from KEY=VALUE lines in .env without overriding
    variables that are already set. Comments and blank lines are ignored.
    Deliberately dependency-free so the server has no optional import path."""
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

FLAREVM_HOST = os.environ.get("FLAREVM_HOST")  # validated in _require_host() at startup
FLAREVM_USER = os.environ.get("FLAREVM_USER", "xtemp")
FLAREVM_PASSWORD = None  # loaded lazily from keyring or FLAREVM_PASSWORD env

SMB_SHARE_NAME = os.environ.get("FLAREVM_SMB_SHARE", "KaliShare")
SMB_LOCAL_PATH = os.environ.get("FLAREVM_SMB_LOCAL_PATH", "C:\\Share")


def _smb_share_path():
    """UNC path of the VM share, derived at call time from FLAREVM_HOST."""
    return "//{}/{}".format(FLAREVM_HOST, SMB_SHARE_NAME)


def _require_host():
    """Startup guard: refuse to serve without a VM address.

    Kept out of import time so the module stays importable (tests, CI,
    tooling). A missing value fails here, loudly, instead of surfacing later
    as a silent 30 s WinRM timeout against a stale address.
    """
    if not FLAREVM_HOST:
        sys.exit(
            "FLAREVM_HOST is not set. Put it in the MCP server 'env' block, export it, "
            "or copy .env.example to .env next to server.py. There is deliberately no default."
        )


def _detect_kali_ip():
    """Return the analyst-host IP that faces FLAREVM_HOST.

    Order: explicit ``KALI_IP`` env var → the local address the kernel would
    route to FLAREVM_HOST (a UDP ``connect()`` sends no packets, it only
    consults the routing table) → None. Never hardcode this: the lab subnet
    changes and a stale value silently disables FakeNet's HostBlackList.
    """
    env_ip = os.environ.get("KALI_IP")
    if env_ip:
        return env_ip
    if not FLAREVM_HOST:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((FLAREVM_HOST, 5985))
            return s.getsockname()[0]
    except OSError:
        return None

IDA_MCP_PORT = 13337
WINDBG_MCP_PORT = int(os.environ.get("WINDBG_MCP_PORT", "13338"))

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

LOG = logging.getLogger("flarevm-mcp")
logging.basicConfig(level=logging.INFO, stream=sys.stderr)

executor = ThreadPoolExecutor(max_workers=8)

# ---------------------------------------------------------------------------
# Per-tool wall-clock timeout table (seconds)
#
# Two-layer timeout strategy:
#   Layer 1 — run_ps_async: enforced per PowerShell call via asyncio.wait_for.
#             On expiry the WinRM session is reset so the next call gets a
#             fresh connection.  The background thread continues until the
#             HTTP connection closes naturally (Python threads cannot be killed).
#   Layer 2 — call_tool: outer asyncio.wait_for(_dispatch()) catches any
#             handler that chains multiple run_ps_async calls and collectively
#             exceeds the per-tool limit, or hangs in non-WinRM code.
# ---------------------------------------------------------------------------
TOOL_TIMEOUTS = {
    # System / file transfer
    "check_connection":           30,
    "list_processes":             30,
    "take_screenshot":            60,
    "read_file":                  60,
    "get_file_hash":              60,
    "execute_powershell":        180,
    "upload_file":               180,
    "download_file":             180,
    # Static analysis
    "die_analyze":                60,
    "strings_extract":            60,
    "entropy_analysis":           60,
    "yara_scan":                 120,
    "upx_unpack":                 60,
    "unpack_detect_and_try":      90,
    "dnspy_decompile":           120,
    "floss_extract_strings":     600,   # FLOSS on large binaries is slow
    "capa_analyze":              600,   # CAPA can take several minutes
    # Dynamic — process / registry
    "procmon_start":              60,
    "procmon_stop":              180,   # CSV export polls up to 90s
    "procmon_export_csv":        120,
    "process_hacker_info":        60,
    "regshot_snapshot":          300,
    "persistence_audit":         120,
    "autoruns_analyze":          120,
    "execute_with_monitoring":   300,
    # Dynamic — network
    "monitor_network_realtime":  180,
    "fakenet_start":             120,
    "fakenet_stop":               60,
    "wireshark_capture":         120,
    # Debuggers
    "x64dbg_load":                60,
    "x64dbg_run_script":         120,
    "windbg_analyze_dump":       300,
    "windbg_run_cmd":            120,
    "windbg_list_dumps":          30,
    "windbg_launch":              60,
    # Frida
    "frida_list_processes":       30,
    "frida_spawn_and_attach":    120,
    "frida_attach_pid":          120,
    "frida_run_script":          120,
    # Injection detection
    "pe_sieve_scan":              60,
    "hollows_hunter_scan":        90,
    "injection_scan_all":        180,
    # IDA Pro
    "ida_launch_and_wait":       180,
    "ida_get_metadata":           30,
    "ida_list_functions":         30,
    "ida_decompile_function":     60,
    "ida_disassemble_function":   60,
    "ida_list_strings":           30,
    "ida_set_comment":            30,
    "ida_rename_function":        30,
    # Composite playbooks
    "triage_full":               900,
    "behavioral_full":          1800,
}
DEFAULT_TOOL_TIMEOUT = 300

# ---------------------------------------------------------------------------
# WinRM session management
# ---------------------------------------------------------------------------

_session = None


def _get_password():
    global FLAREVM_PASSWORD
    if FLAREVM_PASSWORD is None:
        # Prefer explicit environment configuration, then try keyring, then fall back.
        FLAREVM_PASSWORD = os.environ.get("FLAREVM_PASSWORD")
        if not FLAREVM_PASSWORD:
            try:
                FLAREVM_PASSWORD = keyring.get_password("flarevm", FLAREVM_USER)
            except Exception as e:
                LOG.warning("Keyring unavailable, falling back to env/default password: %s", e)
                FLAREVM_PASSWORD = None
        if not FLAREVM_PASSWORD:
            FLAREVM_PASSWORD = "infected"
    return FLAREVM_PASSWORD


def get_session():
    global _session
    if _session is None:
        _session = winrm.Session(
            FLAREVM_HOST,
            auth=(FLAREVM_USER, _get_password()),
            transport="ntlm",
        )
    return _session


def _reset_session():
    """Discard the cached WinRM session so the next call creates a fresh one.

    Called on timeout: the old HTTP connection may be stuck; a new session
    avoids reusing a socket that will never complete.
    """
    global _session
    _session = None
    LOG.warning("WinRM session reset (triggered by timeout or error)")


def run_ps(command, timeout=120):
    """Run PowerShell command via WinRM synchronously. Returns (stdout, stderr, status_code)."""
    sess = get_session()
    result = sess.run_ps(command)
    stdout = result.std_out.decode("utf-8", errors="replace").strip()
    stderr = result.std_err.decode("utf-8", errors="replace").strip()
    return stdout, stderr, result.status_code


async def run_ps_async(command, timeout=120):
    """Run PowerShell via WinRM asynchronously. Returns (stdout, stderr, code).

    Enforces `timeout` at the asyncio level using asyncio.shield so that the
    coroutine returns promptly on expiry without waiting for the thread to finish
    (Python threads cannot be cancelled; the thread continues until the WinRM
    HTTP connection closes naturally).  On timeout the WinRM session is reset so
    the next call gets a fresh TCP connection.
    """
    loop = asyncio.get_event_loop()
    fut = asyncio.shield(loop.run_in_executor(executor, lambda: run_ps(command, timeout)))
    try:
        return await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        _reset_session()
        return (
            "",
            "TIMEOUT: PowerShell command did not respond within {}s — WinRM session reset".format(timeout),
            1,
        )


async def run_ps_script(script, timeout=300, script_name="mcp_script.ps1", force_stage=False):
    """Run a long PowerShell script that exceeds the WinRM 8KB command-line limit.

    Strategy: stage the script as a local temp file, ship it via SMB (already
    proven working), then invoke `powershell -File`. Falls back to inline
    execution if the script is short enough.

    The inline fallback uses pywinrm's `run_ps`, which base64-encodes the script
    as UTF-16 and passes it on the WinRM command line. That doubles+expands the
    payload, so the effective ceiling for the *raw* script is well under 4000
    chars before Windows rejects it with "The command line is too long". Keep
    the threshold conservative so anything substantial is staged as a file.

    force_stage: always use SMB staging even for short scripts. Required for
    scripts that use Invoke-WebRequest (WinRM inline mode can swallow stdout
    from web response objects; SMB-staged `powershell -File` captures it correctly).
    """
    if not force_stage and len(script) < 1500:
        return await run_ps_async(script, timeout=timeout)

    remote_path = "C:\\temp\\" + script_name

    # Stage locally in a per-process tempdir (Bandit B108: not /tmp directly)
    import tempfile
    tmp_root = tempfile.mkdtemp(prefix="flarevm-mcp-")
    local_tmp = os.path.join(tmp_root, script_name)
    with open(local_tmp, "w", encoding="utf-8") as f:
        f.write(script)

    # SMB upload + Move-Item to final destination (mirrors _handle_upload_file)
    smb_cmd = [
        "smbclient", _smb_share_path(),
        "-U", "{}%{}".format(FLAREVM_USER, _get_password()),
        "-c", 'put "{}" "{}"'.format(local_tmp, script_name),
    ]
    proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError("SMB script upload failed: {}".format(proc.stderr))

    move_cmd = (
        'New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null; '
        'Move-Item -Path "{src}\\{name}" -Destination "{dst}" -Force'
    ).format(src=SMB_LOCAL_PATH, name=script_name, dst=remote_path)
    _, stderr, code = await run_ps_async(move_cmd, timeout=30)
    if code != 0:
        raise RuntimeError("Failed to move script into place: {}".format(stderr))

    # Cleanup local copy + tempdir
    import shutil
    try:
        shutil.rmtree(tmp_root, ignore_errors=True)
    except OSError:
        pass

    return await run_ps_async(
        'powershell.exe -ExecutionPolicy Bypass -File "{}"'.format(remote_path),
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# IDA RPC helper
# ---------------------------------------------------------------------------

async def ida_rpc_call(tool_name, arguments=None):
    """Invoke an IDA MCP tool over the Model Context Protocol on FlareVM.

    The IDA plugin (ida-pro-mcp) is a full MCP server listening on
    http://127.0.0.1:13337/mcp. Individual tools are invoked with the
    ``tools/call`` JSON-RPC method, NOT as direct methods, and results come
    back wrapped as ``result.content[0].text`` (itself a JSON string).

    Returns the parsed tool result (dict/list/str). Raises RuntimeError on a
    transport error or a tool-level error.
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
        "id": 1,
    }
    # Embed the JSON body in a SINGLE-quoted PowerShell string. PowerShell's
    # escape character is the backtick, not the backslash, so a double-quoted
    # form would mangle every '"' in the JSON. Single quotes are literal; the
    # only character needing escaping is a single quote, doubled.
    ps_body = json.dumps(payload).replace("'", "''")
    ps = (
        "$body = '{}'\n"
        "$resp = Invoke-WebRequest -Uri 'http://127.0.0.1:{}/mcp' "
        "-Method POST -ContentType 'application/json' -Body $body -UseBasicParsing\n"
        "Write-Output $resp.Content"
    ).format(ps_body, IDA_MCP_PORT)
    stdout, stderr, code = await run_ps_script(ps, timeout=60, script_name="ida_rpc.ps1", force_stage=True)
    if code != 0:
        raise RuntimeError("IDA RPC transport error: {} {}".format(stderr, stdout))
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("IDA RPC: non-JSON response: {}".format(stdout[:500])) from exc
    if isinstance(envelope, dict) and envelope.get("error"):
        err = envelope["error"]
        msg = err.get("message", err) if isinstance(err, dict) else err
        raise RuntimeError("IDA tool '{}' error: {}".format(tool_name, msg))
    result = envelope.get("result", {}) if isinstance(envelope, dict) else {}
    content = result.get("content") if isinstance(result, dict) else None
    if content and isinstance(content, list):
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return result


async def windbg_rpc_call(tool_name, arguments=None, timeout=120):
    """Invoke an mcp-windbg tool via its HTTP server on FlareVM (port WINDBG_MCP_PORT).

    mcp-windbg uses the MCP 2025-03-26 streamable HTTP transport with json_response=True.
    The protocol requires an initialize handshake before tool calls are accepted.
    Session state (open cdb.exe processes keyed by dump path) persists in the server
    process across HTTP sessions, so a new HTTP session for each call is safe.
    """
    init_payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "flarevm-mcp", "version": "1.0"},
        },
        "id": 1,
    }).replace("'", "''")
    notif_body = '{"jsonrpc":"2.0","method":"notifications/initialized"}'.replace("'", "''")
    tool_payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
        "id": 2,
    }).replace("'", "''")

    ps = (
        "$url = 'http://127.0.0.1:{port}/mcp'\n"
        "# mcp-windbg requires Accept: application/json (rejects SSE-only clients)\n"
        "$ct  = @{{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json' }}\n"
        "\n"
        "# 1. Initialize MCP session\n"
        "$initBody = '{init}'\n"
        "$initResp = Invoke-WebRequest -Uri $url -Method POST -Headers $ct "
        "-Body $initBody -UseBasicParsing -ErrorAction Stop\n"
        "$sid = $initResp.Headers['Mcp-Session-Id']\n"
        "\n"
        "# 2. notifications/initialized\n"
        "$notifBody = '{notif}'\n"
        "$hdr = @{{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json'; 'Mcp-Session-Id' = $sid }}\n"
        "Invoke-WebRequest -Uri $url -Method POST -Headers $hdr -Body $notifBody "
        "-UseBasicParsing -ErrorAction SilentlyContinue | Out-Null\n"
        "\n"
        "# 3. tools/call\n"
        "$toolBody = '{tool}'\n"
        "$toolResp = Invoke-WebRequest -Uri $url -Method POST -Headers $hdr "
        "-Body $toolBody -UseBasicParsing -ErrorAction Stop\n"
        "Write-Output $toolResp.Content\n"
    ).format(port=WINDBG_MCP_PORT, init=init_payload, notif=notif_body, tool=tool_payload)

    stdout, stderr, code = await run_ps_script(ps, timeout=timeout, script_name="windbg_rpc.ps1", force_stage=True)
    LOG.debug("windbg_rpc_call %s: code=%s stdout=%r stderr=%r", tool_name, code, stdout[:200], stderr[:200])
    if code != 0:
        raise RuntimeError("mcp-windbg transport error (is MCP_WinDbg_Server running?): {} {}".format(
            stderr, stdout
        ))
    if not stdout.strip():
        raise RuntimeError("mcp-windbg: empty stdout (code={}); stderr: {}".format(code, stderr[:300]))
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("mcp-windbg: non-JSON response: {}".format(stdout[:500])) from exc
    if isinstance(envelope, dict) and envelope.get("error"):
        err = envelope["error"]
        msg = err.get("message", err) if isinstance(err, dict) else str(err)
        raise RuntimeError("mcp-windbg '{}' error: {}".format(tool_name, msg))
    result = envelope.get("result", {}) if isinstance(envelope, dict) else {}
    content = result.get("content") if isinstance(result, dict) else None
    if content and isinstance(content, list):
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return result


async def _ida_resolve_address(target):
    """Accept a function name or a 0x-address; return a usable address string."""
    s = str(target).strip()
    if s.lower().startswith("0x"):
        return s
    info = await ida_rpc_call("get_function_by_name", {"name": s})
    if isinstance(info, dict) and info.get("address"):
        return info["address"]
    raise RuntimeError("Could not resolve function '{}' to an address".format(target))


# ---------------------------------------------------------------------------
# GUI app launcher via Scheduled Task
# ---------------------------------------------------------------------------

async def launch_gui_app(exe_path, arguments="", task_name="MCP_App",
                         wait_port=None, wait_timeout=60):
    """Launch a GUI application in the interactive user session via Scheduled Task."""
    ps = """
$action = New-ScheduledTaskAction -Execute "{exe}" -Argument "{args}"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\\{user}" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 120)
Unregister-ScheduledTask -TaskName "{task}" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "{task}" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName "{task}"
Write-Output "Scheduled task '{task}' started"
""".format(exe=exe_path, args=arguments.replace('"', '`"'),
           user=FLAREVM_USER, task=task_name)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        raise RuntimeError("Failed to launch GUI app: {} {}".format(stderr, stdout))

    if wait_port is not None:
        ps_wait = """
$timeout = {timeout}
$elapsed = 0
while ($elapsed -lt $timeout) {{
    $result = Test-NetConnection 127.0.0.1 -Port {port} -WarningAction SilentlyContinue
    if ($result.TcpTestSucceeded) {{
        Write-Output "Port {port} is ready after $elapsed seconds"
        exit 0
    }}
    Start-Sleep -Seconds 2
    $elapsed += 2
}}
Write-Output "Timeout waiting for port {port} after $timeout seconds"
exit 1
""".format(port=wait_port, timeout=wait_timeout)
        stdout2, stderr2, code2 = await run_ps_async(ps_wait, timeout=wait_timeout + 30)
        if code2 != 0:
            return stdout + "\nWARNING: " + stdout2
        return stdout + "\n" + stdout2

    return stdout


# ---------------------------------------------------------------------------
# FakeNet config generator
# ---------------------------------------------------------------------------

def generate_fakenet_config(kali_ip=None, excluded_ports=None, excluded_processes=None):
    """Generate a FakeNet-NG INI config with triple-layer protection for the analyst host.

    The HostBlackList is the primary shield: ALL traffic to/from Kali bypasses
    interception regardless of port. Port and process blacklists are
    defense-in-depth.

    Args:
        kali_ip: IP of the analyst Kali machine (default: KALI_IP env, else the
            local address that routes to FLAREVM_HOST — see _detect_kali_ip)
        excluded_ports: Defense-in-depth port list (default: WinRM, SMB, IDA MCP)
        excluded_processes: Process names that handle control traffic
    """
    if kali_ip is None:
        kali_ip = _detect_kali_ip()
    if not kali_ip:
        raise RuntimeError(
            "Cannot determine the analyst host IP for FakeNet's HostBlackList "
            "(no route to FLAREVM_HOST=%s). Set KALI_IP explicitly." % FLAREVM_HOST)
    if excluded_ports is None:
        excluded_ports = [5985, 5986, 445, 139, 13337]
    if excluded_processes is None:
        excluded_processes = ["svchost.exe", "System", "smbd.exe", "wsmprovhost.exe"]
    blacklist_ports = ",".join(str(p) for p in excluded_ports)
    blacklist_procs = ",".join(excluded_processes)
    return """[FakeNet]
DivertTraffic: Yes

[Diverter]
# NetworkMode belongs to [Diverter] in FakeNet-NG 3.x; placing it under
# [FakeNet] makes the diverter abort with "You must configure a NetworkMode".
NetworkMode: SingleHost
# PRIMARY SHIELD: never intercept traffic to/from analyst host
HostBlackList: {kali_ip}
# Process exclusions (WinRM/SMB host processes)
ProcessBlackList: {blacklist_procs}
# Port blacklist (defense-in-depth)
DefaultTCPListener: RawTCPListener
DefaultUDPListener: RawUDPListener
BlackListPortsTCP: {blacklist_ports}
BlackListPortsUDP:

[RawTCPListener]
Enabled: True
Port: 1337
Protocol: TCP
Listener: RawListener
UseSSL: No
Timeout: 10

[RawUDPListener]
Enabled: True
Port: 1337
Protocol: UDP
Listener: RawListener
Timeout: 10

[DNSListener]
Enabled: True
Port: 53
Protocol: UDP
Listener: DNSListener
ResponseA: 192.0.2.123
ResponseAAAA: ::1
ResponseMX: mail.evil.com
ResponseTXT: FAKENET
NXDomains: 0

[HTTPListener80]
Enabled: True
Port: 80
Protocol: TCP
Listener: HTTPListener
UseSSL: No
Webroot: C:\\Tools\\fakenet\\fakenet3.5\\defaultFiles\\
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: http

[HTTPListener443]
Enabled: True
Port: 443
Protocol: TCP
Listener: HTTPListener
UseSSL: Yes
Webroot: C:\\Tools\\fakenet\\fakenet3.5\\defaultFiles\\
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: https

[SMTPListener]
Enabled: True
Port: 25
Protocol: TCP
Listener: SMTPListener

[FTPListener]
Enabled: True
Port: 21
Protocol: TCP
Listener: FTPListener
UseSSL: No

[IRCListener]
Enabled: True
Port: 6667
Protocol: TCP
Listener: IRCListener
""".format(
        kali_ip=kali_ip,
        blacklist_procs=blacklist_procs,
        blacklist_ports=blacklist_ports,
    )


# ---------------------------------------------------------------------------
# Tool helper: resolve tool path on FlareVM
# ---------------------------------------------------------------------------

async def resolve_tool_path(tool_key, fallback_name=None):
    """Find a tool on FlareVM. Check known path first, then where.exe."""
    known = TOOL_PATHS.get(tool_key)
    if known:
        ps = 'if (Test-Path "{}") {{ Write-Output "{}" }} else {{ $p = (where.exe {} 2>$null | Select-Object -First 1); if ($p) {{ Write-Output $p }} else {{ Write-Output "NOT_FOUND" }} }}'.format(
            known, known, fallback_name or tool_key
        )
    else:
        ps = '$p = (where.exe {} 2>$null | Select-Object -First 1); if ($p) {{ Write-Output $p }} else {{ Write-Output "NOT_FOUND" }}'.format(
            fallback_name or tool_key
        )
    stdout, _, _ = await run_ps_async(ps, timeout=15)
    path = stdout.strip().split("\n")[0].strip() if stdout.strip() else "NOT_FOUND"
    if path == "NOT_FOUND":
        raise FileNotFoundError("Tool '{}' not found on FlareVM".format(tool_key))
    return path


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

app = Server("flarevm-mcp")


def _text(content):
    """Helper to return a list with a single TextContent."""
    return [TextContent(type="text", text=str(content))]


# ========================== TOOL DEFINITIONS ==============================

@app.list_tools()
async def list_tools():
    return [
        # --- System & File Transfer ---
        Tool(
            name="check_connection",
            description="Test WinRM connection to FlareVM. Returns hostname, OS info, and IP.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="execute_powershell",
            description="Execute a PowerShell command on FlareVM.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "PowerShell command to execute"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)", "default": 120},
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a file from FlareVM. Returns file content.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path on FlareVM"},
                    "encoding": {"type": "string", "description": "Encoding (default utf-8)", "default": "utf-8"},
                    "max_bytes": {"type": "integer", "description": "Max bytes to read (default 1MB)", "default": 1048576},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="upload_file",
            description="Upload a file from Kali to FlareVM via SMB with SHA256 verification.",
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {"type": "string", "description": "Path on Kali"},
                    "remote_path": {"type": "string", "description": "Destination path on FlareVM"},
                },
                "required": ["local_path", "remote_path"],
            },
        ),
        Tool(
            name="download_file",
            description="Download a file from FlareVM to Kali via SMB.",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {"type": "string", "description": "Path on FlareVM"},
                    "local_path": {"type": "string", "description": "Destination path on Kali"},
                },
                "required": ["remote_path", "local_path"],
            },
        ),
        Tool(
            name="get_file_hash",
            description="Calculate MD5/SHA1/SHA256 hash of a file on FlareVM.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path on FlareVM"},
                    "algorithm": {"type": "string", "description": "Hash algorithm: MD5, SHA1, SHA256 (default SHA256)", "default": "SHA256"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_processes",
            description="List running processes on FlareVM with optional name filter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Process name filter (wildcard supported)", "default": ""},
                },
                "required": [],
            },
        ),
        Tool(
            name="take_screenshot",
            description="Take a screenshot of FlareVM desktop via nircmd and scheduled task.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string", "description": "Output path on FlareVM (default C:\\temp\\screenshot.png)", "default": "C:\\temp\\screenshot.png"},
                },
                "required": [],
            },
        ),
        # --- Static Analysis ---
        Tool(
            name="die_analyze",
            description="Run DetectItEasy (DIE) for packer/compiler detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="floss_extract_strings",
            description="Run FLOSS for obfuscated string recovery.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default 4)", "default": 4},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="capa_analyze",
            description="Run CAPA for capability detection and ATT&CK mapping.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "verbose": {"type": "boolean", "description": "Verbose output", "default": False},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="yara_scan",
            description="Scan a file with YARA rules.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "rules_path": {"type": "string", "description": "Path to YARA rules (default C:\\Tools\\yara\\rules\\)", "default": "C:\\Tools\\yara\\rules\\"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="strings_extract",
            description="Extract printable strings from a file using Sysinternals strings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default 6)", "default": 6},
                    "encoding": {"type": "string", "description": "Encoding: a=ASCII, u=Unicode, b=both (default b)", "default": "b"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="entropy_analysis",
            description="Calculate per-section entropy for PE files to detect packing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to PE file on FlareVM"},
                },
                "required": ["file_path"],
            },
        ),
        # --- Dynamic Analysis: Process Monitoring ---
        Tool(
            name="procmon_start",
            description="Start Process Monitor with optional process filter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string", "description": "PML output path (default C:\\temp\\procmon.pml)", "default": "C:\\temp\\procmon.pml"},
                    "process_filter": {"type": "string", "description": "Process name to filter on (optional)"},
                },
                "required": [],
            },
        ),
        Tool(
            name="procmon_stop",
            description="Stop ProcMon and export results to CSV with summary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pml_path": {"type": "string", "description": "PML file path (default C:\\temp\\procmon.pml)", "default": "C:\\temp\\procmon.pml"},
                    "csv_path": {"type": "string", "description": "CSV output path (default C:\\temp\\procmon.csv)", "default": "C:\\temp\\procmon.csv"},
                },
                "required": [],
            },
        ),
        Tool(
            name="procmon_export_csv",
            description="Export a PML file to CSV format.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pml_path": {"type": "string", "description": "PML file path"},
                    "csv_path": {"type": "string", "description": "CSV output path"},
                },
                "required": ["pml_path", "csv_path"],
            },
        ),
        Tool(
            name="process_hacker_info",
            description="Get detailed info about a process: modules, threads, handles, connections.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                },
                "required": ["pid"],
            },
        ),
        # --- Dynamic Analysis: Network ---
        Tool(
            name="monitor_network_realtime",
            description="Monitor network connections for a duration, returning new connections and DNS cache.",
            inputSchema={
                "type": "object",
                "properties": {
                    "duration": {"type": "integer", "description": "Monitoring duration in seconds (default 30)", "default": 30},
                },
                "required": [],
            },
        ),
        Tool(
            name="fakenet_start",
            description="Start FakeNet-NG with WinRM-safe config (excludes management ports).",
            inputSchema={
                "type": "object",
                "properties": {
                    "extra_excluded_ports": {"type": "string", "description": "Comma-separated additional ports to exclude", "default": ""},
                },
                "required": [],
            },
        ),
        Tool(
            name="fakenet_stop",
            description="Stop FakeNet-NG and retrieve captured logs.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wireshark_capture",
            description="Start/stop packet capture with tshark.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "start or stop", "enum": ["start", "stop"]},
                    "duration": {"type": "integer", "description": "Capture duration in seconds (for start)", "default": 60},
                    "output_path": {"type": "string", "description": "PCAP output path", "default": "C:\\temp\\capture.pcap"},
                    "interface": {"type": "string", "description": "Capture interface (default 1)", "default": "1"},
                },
                "required": ["action"],
            },
        ),
        # --- Dynamic Analysis: Registry ---
        Tool(
            name="regshot_snapshot",
            description="Registry before/after snapshot and comparison.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "first, second, or compare", "enum": ["first", "second", "compare"]},
                },
                "required": ["action"],
            },
        ),
        # --- Dynamic Analysis: Debuggers ---
        Tool(
            name="x64dbg_load",
            description="Load a binary in x64dbg via scheduled task (interactive session).",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to executable on FlareVM"},
                    "arguments": {"type": "string", "description": "Command-line arguments", "default": ""},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="x64dbg_run_script",
            description="Save and execute an x64dbg script.",
            inputSchema={
                "type": "object",
                "properties": {
                    "script": {"type": "string", "description": "x64dbg script content"},
                    "script_path": {"type": "string", "description": "Where to save script on FlareVM", "default": "C:\\temp\\x64dbg_script.txt"},
                },
                "required": ["script"],
            },
        ),
        Tool(
            name="windbg_analyze_dump",
            description=(
                "Open a crash/memory dump via mcp-windbg (cdb.exe) on FlareVM and run initial "
                "triage. Returns crash info, call stack, loaded modules and threads. "
                "Requires mcp-windbg HTTP server running on port 13338 (registered as "
                "MCP_WinDbg_Server scheduled task by setup.py)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_file": {"type": "string", "description": "Absolute path to dump file on FlareVM (e.g. C:\\\\temp\\\\crash.dmp)"},
                    "include_stack_trace": {"type": "boolean", "description": "Include call stack in output", "default": True},
                    "include_modules": {"type": "boolean", "description": "Include loaded modules in output", "default": True},
                    "include_threads": {"type": "boolean", "description": "Include thread list in output", "default": True},
                    "symbols_path": {"type": "string", "description": "Optional symbol server/path (e.g. srv*C:\\symbols*https://msdl.microsoft.com/download/symbols)"},
                    "extra_commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional cdb commands to run after initial analysis (e.g. [\"k 40\", \"!peb\"])",
                    },
                },
                "required": ["dump_file"],
            },
        ),
        Tool(
            name="windbg_run_cmd",
            description=(
                "Run an arbitrary cdb command on an already-opened dump session in mcp-windbg. "
                "Call windbg_analyze_dump first to open the session; subsequent windbg_run_cmd "
                "calls on the same dump_file reuse the persistent cdb.exe process."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_file": {"type": "string", "description": "Path to the dump file (must match a previously opened session)"},
                    "command": {"type": "string", "description": "cdb/WinDbg command to execute (e.g. '!ept', 'k 40', 'lm', '!teb')"},
                },
                "required": ["dump_file", "command"],
            },
        ),
        Tool(
            name="windbg_list_dumps",
            description="List .dmp crash dump files on FlareVM via mcp-windbg.",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory_path": {"type": "string", "description": "Directory to search for dump files (default: C:\\\\temp and common dump locations)"},
                },
                "required": [],
            },
        ),
        # --- Dynamic Analysis: Frida ---
        Tool(
            name="frida_list_processes",
            description="List processes visible to Frida on FlareVM.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="frida_spawn_and_attach",
            description="Spawn a process and attach Frida with a script.",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string", "description": "Path to executable on FlareVM"},
                    "script": {"type": "string", "description": "Frida JavaScript script content"},
                    "timeout": {"type": "integer", "description": "Script timeout in seconds (default 30)", "default": 30},
                },
                "required": ["executable", "script"],
            },
        ),
        Tool(
            name="frida_attach_pid",
            description="Attach Frida to a running process by PID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID to attach to"},
                    "script": {"type": "string", "description": "Frida JavaScript script content"},
                    "timeout": {"type": "integer", "description": "Script timeout in seconds (default 30)", "default": 30},
                },
                "required": ["pid", "script"],
            },
        ),
        Tool(
            name="frida_run_script",
            description="Execute an inline Frida script against a process (by name or PID).",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Process name or PID"},
                    "script": {"type": "string", "description": "Frida JavaScript script content"},
                    "timeout": {"type": "integer", "description": "Script timeout in seconds (default 30)", "default": 30},
                },
                "required": ["target", "script"],
            },
        ),
        # --- Injection & Unpacking Detection ---
        Tool(
            name="pe_sieve_scan",
            description="Scan a process for code injection/hollowing with PE-sieve.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID to scan"},
                    "output_dir": {"type": "string", "description": "Output directory", "default": "C:\\temp\\pe_sieve_output"},
                },
                "required": ["pid"],
            },
        ),
        Tool(
            name="hollows_hunter_scan",
            description="Scan ALL running processes for injection/hollowing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {"type": "string", "description": "Output directory", "default": "C:\\temp\\hollows_output"},
                },
                "required": [],
            },
        ),
        Tool(
            name="upx_unpack",
            description="Attempt UPX unpacking of a packed executable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "packed_file": {"type": "string", "description": "Path to packed file"},
                    "output_file": {"type": "string", "description": "Output path for unpacked file"},
                },
                "required": ["packed_file", "output_file"],
            },
        ),
        Tool(
            name="unpack_detect_and_try",
            description="Composite: detect packer, check entropy, attempt automated unpacking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to potentially packed file"},
                },
                "required": ["file_path"],
            },
        ),
        # --- .NET Analysis ---
        Tool(
            name="dnspy_decompile",
            description="Decompile a .NET assembly with dnSpy Console.",
            inputSchema={
                "type": "object",
                "properties": {
                    "assembly_path": {"type": "string", "description": "Path to .NET assembly on FlareVM"},
                    "output_dir": {"type": "string", "description": "Output directory for decompiled source", "default": "C:\\temp\\decompiled"},
                },
                "required": ["assembly_path"],
            },
        ),
        # --- GUI Tool Launchers ---
        Tool(
            name="ida_launch_and_wait",
            description="Launch IDA Pro with a binary and wait for MCP server (port 13337) to be ready.",
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to binary to load in IDA"},
                    "ida_path": {"type": "string", "description": "Path to IDA executable", "default": "C:\\Tools\\IDA Pro\\ida64.exe"},
                },
                "required": ["binary_path"],
            },
        ),
        Tool(
            name="windbg_launch",
            description="Launch WinDbg GUI with a dump file in the interactive console session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_file": {"type": "string", "description": "Path to dump file"},
                    "windbg_path": {"type": "string", "description": "Path to WinDbg GUI", "default": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"},
                },
                "required": ["dump_file"],
            },
        ),
        # --- IDA Pro Proxy ---
        Tool(
            name="ida_get_metadata",
            description="Get metadata from IDA Pro (binary info, architecture, etc.).",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="ida_list_functions",
            description="List functions in the binary loaded in IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Optional name filter", "default": ""},
                    "count": {"type": "integer", "description": "Max functions to return", "default": 100},
                },
                "required": [],
            },
        ),
        Tool(
            name="ida_decompile_function",
            description="Decompile a function in IDA Pro (Hex-Rays).",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Function name or address"},
                },
                "required": ["function_name"],
            },
        ),
        Tool(
            name="ida_disassemble_function",
            description="Get disassembly of a function in IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Function name or address"},
                },
                "required": ["function_name"],
            },
        ),
        Tool(
            name="ida_list_strings",
            description="List strings found by IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Optional string filter (regex)", "default": ""},
                    "count": {"type": "integer", "description": "Max strings to return", "default": 200},
                },
                "required": [],
            },
        ),
        Tool(
            name="ida_set_comment",
            description="Set a comment in IDA Pro at a given address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address (hex string like 0x401000)"},
                    "comment": {"type": "string", "description": "Comment text"},
                },
                "required": ["address", "comment"],
            },
        ),
        Tool(
            name="ida_rename_function",
            description="Rename a function in IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "Current function name or address"},
                    "new_name": {"type": "string", "description": "New function name"},
                },
                "required": ["old_name", "new_name"],
            },
        ),
        # --- Composite Playbooks ---
        Tool(
            name="triage_full",
            description="Complete static analysis pipeline: hashes, DIE, entropy, CAPA, FLOSS, YARA.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="behavioral_full",
            description="Complete behavioral analysis: regshot, procmon, FakeNet, network monitoring, execute, collect.",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string", "description": "Path to executable on FlareVM"},
                    "arguments": {"type": "string", "description": "Command-line arguments", "default": ""},
                    "duration": {"type": "integer", "description": "Execution duration in seconds (default 30)", "default": 30},
                },
                "required": ["executable"],
            },
        ),
        Tool(
            name="persistence_audit",
            description="Full persistence mechanism scan: autoruns, registry, tasks, services, WMI, startup.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="injection_scan_all",
            description="Scan all processes for code injection using hollows_hunter + pe-sieve.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="execute_with_monitoring",
            description=(
                "Execute a binary under full monitoring: starts Procmon capture, launches the "
                "executable, waits for the specified duration, then stops Procmon and returns "
                "a combined activity summary (file/reg/net events, new processes)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string",
                                   "description": "Full path to the executable on FlareVM, e.g. C:\\temp\\sample.exe"},
                    "arguments":  {"type": "string", "default": "",
                                   "description": "Command-line arguments to pass to the executable"},
                    "duration":   {"type": "integer", "default": 30,
                                   "description": "How many seconds to let the process run before stopping capture"},
                },
                "required": ["executable"],
            },
        ),
        Tool(
            name="autoruns_analyze",
            description=(
                "Run Autoruns (autorunsc.exe) to enumerate all autostart entries: registry run "
                "keys, startup folders, scheduled tasks, services, browser extensions, drivers, "
                "etc.  Returns a structured list with entry name, publisher, image path, and "
                "optionally signature status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "verify_signatures": {
                        "type": "boolean", "default": True,
                        "description": "Check digital signatures for each entry (slower but more thorough)"},
                    "category": {
                        "type": "string", "default": "*",
                        "description": "Autorun category filter passed to autorunsc -a: "
                                       "* (all), l (logon), s (services), t (scheduled tasks), "
                                       "d (drivers), b (boot execute), c (codecs), etc."},
                },
                "required": [],
            },
        ),
    ]


# ========================== TOOL HANDLERS =================================

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    """MCP tool dispatcher with two-layer hang detection.

    Layer 1 (run_ps_async): each individual WinRM call has its own asyncio
    timeout so a single stuck PowerShell command does not block forever.

    Layer 2 (here): per-tool wall-clock limit from TOOL_TIMEOUTS catches
    handlers that chain many calls or hang in non-WinRM code paths.
    """
    wall_timeout = TOOL_TIMEOUTS.get(name, DEFAULT_TOOL_TIMEOUT)
    try:
        return await asyncio.wait_for(_dispatch(name, arguments), timeout=wall_timeout)
    except asyncio.TimeoutError:
        _reset_session()
        return _text(
            "[TIMEOUT] Tool '{}' did not complete within {}s. "
            "The FlareVM may be busy or WinRM unresponsive. "
            "Call check_connection to verify connectivity.".format(name, wall_timeout)
        )
    except Exception as e:
        tb = traceback.format_exc()
        LOG.error("Tool %s failed: %s", name, tb)
        return _text("ERROR in tool '{}' with args {}:\n{}\n\n{}".format(
            name, json.dumps(arguments, default=str), str(e), tb
        ))


async def _dispatch(name: str, arguments: dict):
    """Route a tool name to its handler. Called inside the call_tool timeout guard."""
    # --- System & File Transfer ---
    if name == "check_connection":
        return await _handle_check_connection(arguments)
    elif name == "execute_powershell":
        return await _handle_execute_powershell(arguments)
    elif name == "read_file":
        return await _handle_read_file(arguments)
    elif name == "upload_file":
        return await _handle_upload_file(arguments)
    elif name == "download_file":
        return await _handle_download_file(arguments)
    elif name == "get_file_hash":
        return await _handle_get_file_hash(arguments)
    elif name == "list_processes":
        return await _handle_list_processes(arguments)
    elif name == "take_screenshot":
        return await _handle_take_screenshot(arguments)
    # --- Static Analysis ---
    elif name == "die_analyze":
        return await _handle_die_analyze(arguments)
    elif name == "floss_extract_strings":
        return await _handle_floss_extract_strings(arguments)
    elif name == "capa_analyze":
        return await _handle_capa_analyze(arguments)
    elif name == "yara_scan":
        return await _handle_yara_scan(arguments)
    elif name == "strings_extract":
        return await _handle_strings_extract(arguments)
    elif name == "entropy_analysis":
        return await _handle_entropy_analysis(arguments)
    # --- Dynamic Analysis: Process Monitoring ---
    elif name == "procmon_start":
        return await _handle_procmon_start(arguments)
    elif name == "procmon_stop":
        return await _handle_procmon_stop(arguments)
    elif name == "procmon_export_csv":
        return await _handle_procmon_export_csv(arguments)
    elif name == "process_hacker_info":
        return await _handle_process_hacker_info(arguments)
    # --- Dynamic Analysis: Network ---
    elif name == "monitor_network_realtime":
        return await _handle_monitor_network_realtime(arguments)
    elif name == "fakenet_start":
        return await _handle_fakenet_start(arguments)
    elif name == "fakenet_stop":
        return await _handle_fakenet_stop(arguments)
    elif name == "wireshark_capture":
        return await _handle_wireshark_capture(arguments)
    # --- Dynamic Analysis: Registry ---
    elif name == "regshot_snapshot":
        return await _handle_regshot_snapshot(arguments)
    # --- Dynamic Analysis: Debuggers ---
    elif name == "x64dbg_load":
        return await _handle_x64dbg_load(arguments)
    elif name == "x64dbg_run_script":
        return await _handle_x64dbg_run_script(arguments)
    elif name == "windbg_analyze_dump":
        return await _handle_windbg_analyze_dump(arguments)
    elif name == "windbg_run_cmd":
        return await _handle_windbg_run_cmd(arguments)
    elif name == "windbg_list_dumps":
        return await _handle_windbg_list_dumps(arguments)
    # --- Dynamic Analysis: Frida ---
    elif name == "frida_list_processes":
        return await _handle_frida_list_processes(arguments)
    elif name == "frida_spawn_and_attach":
        return await _handle_frida_spawn_and_attach(arguments)
    elif name == "frida_attach_pid":
        return await _handle_frida_attach_pid(arguments)
    elif name == "frida_run_script":
        return await _handle_frida_run_script(arguments)
    # --- Injection & Unpacking ---
    elif name == "pe_sieve_scan":
        return await _handle_pe_sieve_scan(arguments)
    elif name == "hollows_hunter_scan":
        return await _handle_hollows_hunter_scan(arguments)
    elif name == "upx_unpack":
        return await _handle_upx_unpack(arguments)
    elif name == "unpack_detect_and_try":
        return await _handle_unpack_detect_and_try(arguments)
    # --- .NET Analysis ---
    elif name == "dnspy_decompile":
        return await _handle_dnspy_decompile(arguments)
    # --- GUI Tool Launchers ---
    elif name == "ida_launch_and_wait":
        return await _handle_ida_launch_and_wait(arguments)
    elif name == "windbg_launch":
        return await _handle_windbg_launch(arguments)
    # --- IDA Pro Proxy ---
    elif name == "ida_get_metadata":
        return await _handle_ida_get_metadata(arguments)
    elif name == "ida_list_functions":
        return await _handle_ida_list_functions(arguments)
    elif name == "ida_decompile_function":
        return await _handle_ida_decompile_function(arguments)
    elif name == "ida_disassemble_function":
        return await _handle_ida_disassemble_function(arguments)
    elif name == "ida_list_strings":
        return await _handle_ida_list_strings(arguments)
    elif name == "ida_set_comment":
        return await _handle_ida_set_comment(arguments)
    elif name == "ida_rename_function":
        return await _handle_ida_rename_function(arguments)
    # --- Composite Playbooks ---
    elif name == "triage_full":
        return await _handle_triage_full(arguments)
    elif name == "behavioral_full":
        return await _handle_behavioral_full(arguments)
    elif name == "persistence_audit":
        return await _handle_persistence_audit(arguments)
    elif name == "injection_scan_all":
        return await _handle_injection_scan_all(arguments)
    elif name == "execute_with_monitoring":
        return await _handle_execute_with_monitoring(arguments)
    elif name == "autoruns_analyze":
        return await _handle_autoruns_analyze(arguments)
    else:
        return _text("Unknown tool: {}".format(name))


# ========================== HANDLER IMPLEMENTATIONS =======================

# 1. check_connection
async def _handle_check_connection(args):
    ps = r"""
$hostname = $env:COMPUTERNAME
$os = (Get-WmiObject Win32_OperatingSystem).Caption
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.254\.' -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress
$ip = if ($ips) { $ips -join ', ' } else { 'none' }
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Output "=== FlareVM Connection OK ==="
Write-Output "Hostname: $hostname"
Write-Output "OS: $os"
Write-Output "IP: $ip"
Write-Output "Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
Write-Output "User: $env:USERNAME"
"""
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Connection FAILED: {} {}".format(stderr, stdout))
    return _text(stdout)


# 2. execute_powershell
async def _handle_execute_powershell(args):
    command = args["command"]
    timeout = args.get("timeout", 120)
    stdout, stderr, code = await run_ps_async(command, timeout=timeout)
    result = ""
    if stdout:
        result += stdout
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    result += "\n--- Exit Code: {} ---".format(code)
    return _text(result)


# 3. read_file
async def _handle_read_file(args):
    file_path = args["file_path"]
    encoding = args.get("encoding", "utf-8")
    max_bytes = args.get("max_bytes", 1048576)
    ps = """
$path = "{path}"
if (-not (Test-Path $path)) {{ Write-Error "File not found: $path"; exit 1 }}
$size = (Get-Item $path).Length
if ($size -gt {max_bytes}) {{
    $bytes = [System.IO.File]::ReadAllBytes($path)[0..{max_minus1}]
    $text = [System.Text.Encoding]::GetEncoding("{enc}").GetString($bytes)
    Write-Output "--- TRUNCATED (showing first {max_bytes} of $size bytes) ---"
    Write-Output $text
}} else {{
    Get-Content -Path $path -Raw -Encoding {enc_ps}
}}
""".format(
        path=file_path.replace('"', '`"'),
        max_bytes=max_bytes,
        max_minus1=max_bytes - 1,
        enc=encoding,
        enc_ps="UTF8" if encoding == "utf-8" else "Default",
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text(stdout)


# 4. upload_file (SMB only — single transport, SHA256 verified)
async def _handle_upload_file(args):
    local_path = args["local_path"]
    remote_path = args["remote_path"]

    if not os.path.isfile(local_path):
        return _text("ERROR: local file not found: {}".format(local_path))

    # Local SHA256
    h = hashlib.sha256()
    with open(local_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    local_hash = h.hexdigest()
    file_size = os.path.getsize(local_path)
    filename = os.path.basename(local_path)

    # Step 1: SMB put → //FlareVM/KaliShare → C:\Share\<filename>
    smb_cmd = [
        "smbclient", _smb_share_path(),
        "-U", "{}%{}".format(FLAREVM_USER, _get_password()),
        "-c", 'put "{}" "{}"'.format(local_path, filename),
    ]
    proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return _text("SMB upload failed:\n{}\n{}".format(proc.stderr, proc.stdout))

    # Step 2: Move from share to final destination on FlareVM
    ps_move = """
$src = "{smb_local}\\{filename}"
$dst = "{remote}"
$dstDir = [System.IO.Path]::GetDirectoryName($dst)
if (-not (Test-Path $dstDir)) {{ New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }}
Move-Item -Path $src -Destination $dst -Force
""".format(
        smb_local=SMB_LOCAL_PATH,
        filename=filename,
        remote=remote_path.replace('"', '`"'),
    )
    stdout, stderr, code = await run_ps_async(ps_move, timeout=60)
    if code != 0:
        return _text("Move from SMB share failed:\n{}\n{}".format(stderr, stdout))

    # Step 3: Verify SHA256 on remote
    ps_verify = '(Get-FileHash -Path "{}" -Algorithm SHA256).Hash'.format(
        remote_path.replace('"', '`"')
    )
    stdout, _, _ = await run_ps_async(ps_verify, timeout=60)
    remote_hash = stdout.strip().lower()
    if remote_hash != local_hash.lower():
        return _text(
            "HASH MISMATCH!\nPath: {}\nLocal:  {}\nRemote: {}".format(
                remote_path, local_hash, remote_hash
            )
        )

    return _text(
        "Upload OK (SMB)\n"
        "Path:   {}\n"
        "Size:   {:,} bytes\n"
        "SHA256: {}\n"
        "Verified: ✓".format(remote_path, file_size, local_hash)
    )


# 5. download_file (SMB only — single transport)
async def _handle_download_file(args):
    remote_path = args["remote_path"]
    local_path = args["local_path"]

    # Step 1: Confirm file exists and get size
    ps_size = """
$p = "{path}"
if (-not (Test-Path $p)) {{ Write-Error "File not found: $p"; exit 1 }}
(Get-Item $p).Length
""".format(path=remote_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps_size, timeout=30)
    if code != 0:
        return _text("Remote file error: {}\n{}".format(stderr, stdout))
    file_size = int(stdout.strip())

    # Step 2: Stage on the SMB share (Windows path → use ntpath, not os.path)
    filename = ntpath.basename(remote_path)
    ps_stage = 'Copy-Item -Path "{}" -Destination "{}\\{}" -Force'.format(
        remote_path.replace('"', '`"'), SMB_LOCAL_PATH, filename
    )
    stdout, stderr, code = await run_ps_async(ps_stage, timeout=120)
    if code != 0:
        return _text("Failed to stage on SMB share: {}\n{}".format(stderr, stdout))

    # Step 3: SMB get → local destination
    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    smb_cmd = [
        "smbclient", _smb_share_path(),
        "-U", "{}%{}".format(FLAREVM_USER, _get_password()),
        "-c", 'get "{}" "{}"'.format(filename, local_path),
    ]
    proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return _text("SMB download failed:\n{}\n{}".format(proc.stderr, proc.stdout))

    # Step 4: Cleanup staged copy
    await run_ps_async(
        'Remove-Item -Path "{}\\{}" -Force -ErrorAction SilentlyContinue'.format(
            SMB_LOCAL_PATH, filename
        ),
        timeout=15,
    )

    return _text(
        "Download OK (SMB)\n"
        "Remote: {}\n"
        "Local:  {}\n"
        "Size:   {:,} bytes".format(remote_path, local_path, file_size)
    )


# 6. get_file_hash
async def _handle_get_file_hash(args):
    file_path = args["file_path"]
    # Always compute MD5+SHA1+SHA256; the algorithm arg is accepted for compatibility
    _ = args.get("algorithm", "SHA256")
    ps = """
$path = "{path}"
if (-not (Test-Path $path)) {{ Write-Error "File not found: $path"; exit 1 }}
$md5 = (Get-FileHash -Path $path -Algorithm MD5).Hash
$sha1 = (Get-FileHash -Path $path -Algorithm SHA1).Hash
$sha256 = (Get-FileHash -Path $path -Algorithm SHA256).Hash
$size = (Get-Item $path).Length
Write-Output "=== File Hashes ==="
Write-Output "File: $path"
Write-Output "Size: $size bytes"
Write-Output "MD5:    $md5"
Write-Output "SHA1:   $sha1"
Write-Output "SHA256: $sha256"
""".format(path=file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text(stdout)


# 7. list_processes
async def _handle_list_processes(args):
    proc_filter = args.get("filter", "")
    if proc_filter:
        ps = 'Get-Process -Name "{}" -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, CPU, WorkingSet64, Path -AutoSize | Out-String -Width 200'.format(proc_filter)
    else:
        ps = 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table Id, ProcessName, CPU, WorkingSet64, Path -AutoSize | Out-String -Width 200'
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text("=== Running Processes ===\n" + stdout)


# 8. take_screenshot
async def _handle_take_screenshot(args):
    output_path = args.get("output_path", "C:\\temp\\screenshot.png")
    # Ensure temp directory exists
    await run_ps_async('New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null', timeout=10)
    # Use nircmd via scheduled task for interactive session screenshot
    await launch_gui_app(
        TOOL_PATHS["nircmd"],
        arguments='savescreenshot "{}"'.format(output_path),
        task_name="MCP_Screenshot",
    )
    # Wait a moment for file to be written
    await asyncio.sleep(2)
    ps_check = """
if (Test-Path "{path}") {{
    $size = (Get-Item "{path}").Length
    Write-Output "Screenshot saved: {path} ($size bytes)"
}} else {{
    Write-Output "WARNING: Screenshot file not found at {path}"
}}
""".format(path=output_path)
    stdout, _, _ = await run_ps_async(ps_check, timeout=15)
    return _text(stdout)


# 9. die_analyze
async def _handle_die_analyze(args):
    file_path = args["file_path"]
    die_path = await resolve_tool_path("die", "diec")
    ps = '& "{}" -d "{}" 2>&1'.format(die_path, file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== DetectItEasy Analysis ===\nFile: {}\n\n{}".format(file_path, stdout)
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 10. floss_extract_strings
async def _handle_floss_extract_strings(args):
    file_path = args["file_path"]
    min_length = args.get("min_length", 4)
    floss_path = await resolve_tool_path("floss", "floss")
    ps = '& "{}" -n {} "{}" 2>&1'.format(floss_path, min_length, file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== FLOSS String Extraction ===\nFile: {}\nMin length: {}\n\n{}".format(
        file_path, min_length, stdout
    )
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 11. capa_analyze
async def _handle_capa_analyze(args):
    file_path = args["file_path"]
    verbose = args.get("verbose", False)
    capa_path = await resolve_tool_path("capa", "capa")
    v_flag = "-v" if verbose else ""
    ps = '& "{}" {} "{}" 2>&1'.format(capa_path, v_flag, file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== CAPA Capability Analysis ===\nFile: {}\n\n{}".format(file_path, stdout)
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 12. yara_scan
async def _handle_yara_scan(args):
    file_path = args["file_path"]
    rules_path = args.get("rules_path", "C:\\Tools\\yara\\rules\\")
    # Find YARA executable
    ps_find = """
$paths = @("C:\\Tools\\yara\\yara64.exe", "C:\\ProgramData\\chocolatey\\bin\\yara64.exe")
foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; exit 0 } }
$w = where.exe yara64 2>$null | Select-Object -First 1
if ($w) { Write-Output $w } else { Write-Output "NOT_FOUND" }
"""
    yara_stdout, _, _ = await run_ps_async(ps_find, timeout=15)
    yara_path = yara_stdout.strip().split("\n")[0].strip()
    if yara_path == "NOT_FOUND":
        return _text("YARA not found on FlareVM")

    ps = '& "{yara}" -r "{rules}" "{file}" 2>&1'.format(
        yara=yara_path,
        rules=rules_path.replace('"', '`"'),
        file=file_path.replace('"', '`"'),
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== YARA Scan ===\nFile: {}\nRules: {}\n\n".format(file_path, rules_path)
    if stdout.strip():
        result += "Matches:\n" + stdout
    else:
        result += "No matches found."
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 13. strings_extract
async def _handle_strings_extract(args):
    file_path = args["file_path"]
    min_length = args.get("min_length", 6)
    encoding = args.get("encoding", "b")
    strings_path = await resolve_tool_path("strings", "strings")
    enc_flag = ""
    if encoding == "a":
        enc_flag = "-a"
    elif encoding == "u":
        enc_flag = "-u"
    else:
        enc_flag = ""  # default is both in Sysinternals strings

    ps = '& "{}" -accepteula -n {} {} "{}" 2>&1'.format(
        strings_path, min_length, enc_flag, file_path.replace('"', '`"')
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    lines = stdout.split("\n") if stdout else []
    result = "=== Strings Extraction ===\nFile: {}\nTotal strings found: {}\n\n{}".format(
        file_path, len(lines), stdout
    )
    return _text(result)


# 14. entropy_analysis
# The Python helper kept as a raw string so `{...}` placeholders inside it
# are NOT interpreted by Python's str.format() (they're meant for the
# embedded Python script's own .format() calls).
_ENTROPY_PY = r"""import pefile, math, sys
try:
    pe = pefile.PE(sys.argv[1])
    print("=== PE Section Entropy Analysis ===")
    print("File: " + sys.argv[1])
    print("")
    print("{:8s} {:>10s} {:>10s} {:>8s} {:>6s}".format(
        "Section", "VirtSize", "RawSize", "Entropy", "Status"))
    print("-" * 50)
    total_entropy = 0
    for s in pe.sections:
        data = s.get_data()
        ent = 0
        if data:
            for i in range(256):
                p = data.count(bytes([i])) / len(data)
                if p > 0:
                    ent -= p * math.log2(p)
        name = s.Name.decode(errors='replace').strip('\x00')
        status = "PACKED" if ent > 7.0 else ("HIGH" if ent > 6.5 else "OK")
        print("{:8s} {:10d} {:10d} {:8.2f} {:>6s}".format(
            name, s.Misc_VirtualSize, s.SizeOfRawData, ent, status))
        total_entropy += ent
    avg = total_entropy / len(pe.sections) if pe.sections else 0
    print("")
    print("Average entropy: {:.2f}".format(avg))
    if avg > 7.0:
        print("VERDICT: Likely PACKED (high average entropy)")
    elif avg > 6.0:
        print("VERDICT: Possibly packed or compressed sections")
    else:
        print("VERDICT: Likely NOT packed")
    imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports += len(entry.imports)
    note = "(suspiciously low - may be packed)" if imports < 10 else "(normal)"
    print("\nImport count: {} {}".format(imports, note))
except Exception as e:
    print("Error: " + str(e))
"""


async def _handle_entropy_analysis(args):
    file_path = args["file_path"]
    # Upload the helper script to FlareVM, then run it
    await run_ps_script(
        # Wrap in a tiny PowerShell trampoline that writes the script and runs it
        "Set-Content -Path C:\\temp\\entropy_check.py -Value @'\n"
        + _ENTROPY_PY
        + "'@ -Encoding utf8\n",
        timeout=30,
        script_name="entropy_setup.ps1",
    )
    safe_path = file_path.replace('"', '`"')
    ps = 'New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null; ' \
         'python C:\\temp\\entropy_check.py "{}" 2>&1'.format(safe_path)
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("Entropy analysis failed: {} {}".format(stderr, stdout))
    return _text(stdout)


# 15. procmon_start
async def _poll_file_nonempty(path, attempts=15, interval=2):
    """Poll until a file on FlareVM exists and is non-empty. Returns its size or 0."""
    for _ in range(attempts):
        await asyncio.sleep(interval)
        out, _, _ = await run_ps_async(
            'if (Test-Path "{0}") {{ (Get-Item "{0}").Length }} else {{ 0 }}'.format(path),
            timeout=10)
        try:
            size = int(out.strip().split("\n")[0])
        except (ValueError, IndexError):
            size = 0
        if size > 0:
            return size
    return 0


async def _handle_procmon_start(args):
    output_path = args.get("output_path", "C:\\temp\\procmon.pml")
    process_filter = args.get("process_filter", "")
    procmon_path = await resolve_tool_path("procmon", "Procmon")

    await run_ps_async('New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null', timeout=10)
    # Kill any existing procmon and clear the stale backing file so our poll
    # detects the fresh one.
    await run_ps_async('Stop-Process -Name Procmon* -Force -ErrorAction SilentlyContinue', timeout=15)
    await asyncio.sleep(1)
    await run_ps_async('Remove-Item "{}" -Force -ErrorAction SilentlyContinue'.format(output_path), timeout=10)

    # ProcMon needs an INTERACTIVE desktop to load its driver and (crucially) to
    # convert the log later, so launch it through a scheduled task in the
    # console session rather than Start-Process in the non-interactive WinRM
    # (session 0) context. CLI filtering requires a *binary* .pmc — the old XML
    # /LoadConfig silently disabled capture — so we capture everything and let
    # procmon_stop summarise per process instead.
    pm_args = '/BackingFile "{}" /Quiet /Minimized /AcceptEula'.format(output_path)
    await launch_gui_app(procmon_path, arguments=pm_args, task_name="MCP_Procmon")

    size = await _poll_file_nonempty(output_path, attempts=10, interval=2)

    note = ""
    if process_filter:
        note = ("\nNote: capture is unfiltered (CLI filtering needs a binary .pmc); "
                "the requested filter '{}' is ignored — procmon_stop lists all "
                "processes seen.".format(process_filter))
    if size > 0:
        return _text("=== ProcMon Started (interactive session) ===\n"
                     "Backing file: {} ({} bytes preallocated)\n"
                     "Capturing all process activity. Use procmon_stop to "
                     "terminate and export.{}".format(output_path, size, note))
    return _text("WARNING: ProcMon launched but backing file {} did not appear; "
                 "capture may not have started.{}".format(output_path, note))


# 16. procmon_stop
async def _handle_procmon_stop(args):
    pml_path = args.get("pml_path", "C:\\temp\\procmon.pml")
    csv_path = args.get("csv_path", "C:\\temp\\procmon.csv")
    procmon_path = await resolve_tool_path("procmon", "Procmon")

    # Clear any stale CSV so the poll below sees the fresh export.
    await run_ps_async('Remove-Item "{}" -Force -ErrorAction SilentlyContinue'.format(csv_path), timeout=10)

    # Stop the running capture. /Terminate must also run in the interactive
    # session to reach the capturing instance and flush the PML.
    await launch_gui_app(procmon_path, arguments="/Terminate", task_name="MCP_ProcmonTerm")
    for _ in range(15):
        await asyncio.sleep(2)
        out, _, _ = await run_ps_async(
            '(Get-Process Procmon* -ErrorAction SilentlyContinue | Measure-Object).Count', timeout=10)
        if out.strip().split("\n")[0] == "0":
            break

    # Convert PML -> CSV. /OpenLog + /SaveAs renders through the GUI, so it too
    # needs the interactive desktop; launch it the same way and poll for the
    # output file rather than blocking on the (headless-hanging) call.
    conv_args = '/OpenLog "{}" /SaveAs "{}" /AcceptEula'.format(pml_path, csv_path)
    await launch_gui_app(procmon_path, arguments=conv_args, task_name="MCP_ProcmonConv")
    csv_size = await _poll_file_nonempty(csv_path, attempts=45, interval=2)
    # Ensure the conversion instance has exited.
    await run_ps_async('Stop-Process -Name Procmon* -Force -ErrorAction SilentlyContinue', timeout=10)

    if csv_size == 0:
        exists, _, _ = await run_ps_async('Test-Path "{}"'.format(pml_path), timeout=10)
        return _text("WARNING: CSV export not produced at {} (PML exists: {}). "
                     "The interactive conversion may still be running.".format(
                         csv_path, exists.strip()))

    # Parse the CSV summary — plain file reads work fine over WinRM.
    ps = """
$lines = Get-Content "{csv}" -TotalCount 10001
$total = $lines.Count - 1
$fileOps = ($lines | Select-String -Pattern "CreateFile|WriteFile|ReadFile|DeleteFile|SetDispositionInformationFile" | Measure-Object).Count
$regOps = ($lines | Select-String -Pattern "RegOpenKey|RegSetValue|RegQueryValue|RegCreateKey|RegDeleteKey" | Measure-Object).Count
$netOps = ($lines | Select-String -Pattern "TCP|UDP|Send|Recv" | Measure-Object).Count
$procOps = ($lines | Select-String -Pattern "Process Create|Process Start|Thread Create|Load Image" | Measure-Object).Count

Write-Output "=== ProcMon Summary ==="
Write-Output "PML: {pml}"
Write-Output "CSV: {csv} ({csvsize} bytes)"
Write-Output "Total events (up to 10000): $total"
Write-Output ""
Write-Output "--- Operation Breakdown ---"
Write-Output "File operations:     $fileOps"
Write-Output "Registry operations: $regOps"
Write-Output "Network operations:  $netOps"
Write-Output "Process operations:  $procOps"
Write-Output ""
$procs = $lines | ForEach-Object {{ ($_ -split ',')[1] }} | Sort-Object -Unique | Where-Object {{ $_ -and $_ -ne '"Process Name"' }}
Write-Output "--- Unique Processes ---"
$procs | ForEach-Object {{ Write-Output "  $_" }}
""".format(pml=pml_path, csv=csv_path, csvsize=csv_size)

    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 17. procmon_export_csv
async def _handle_procmon_export_csv(args):
    pml_path = args["pml_path"]
    csv_path = args["csv_path"]
    procmon_path = await resolve_tool_path("procmon", "Procmon")
    ps = """
& "{procmon}" /OpenLog "{pml}" /SaveAs "{csv}" /AcceptEula 2>&1
Start-Sleep -Seconds 5
if (Test-Path "{csv}") {{
    $size = (Get-Item "{csv}").Length
    Write-Output "Exported successfully: {csv} ($size bytes)"
}} else {{
    Write-Output "Export failed - CSV not created"
}}
""".format(procmon=procmon_path, pml=pml_path, csv=csv_path)
    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    return _text(stdout)


# 18. process_hacker_info
async def _handle_process_hacker_info(args):
    pid = args["pid"]
    ps = """
$targetPid = {pid}
$proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
if (-not $proc) {{ Write-Error "Process $targetPid not found"; exit 1 }}

$wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$targetPid"

Write-Output "=== Process Details: $($proc.ProcessName) (PID: $targetPid) ==="
Write-Output ""
Write-Output "--- Basic Info ---"
Write-Output "Name:         $($proc.ProcessName)"
Write-Output "PID:          $targetPid"
Write-Output "Parent PID:   $($wmi.ParentProcessId)"
Write-Output "Command Line: $($wmi.CommandLine)"
Write-Output "Path:         $($proc.Path)"
Write-Output "Start Time:   $($proc.StartTime)"
Write-Output "CPU Time:     $($proc.TotalProcessorTime)"
Write-Output "Working Set:  $([math]::Round($proc.WorkingSet64/1MB, 2)) MB"
Write-Output "Thread Count: $($proc.Threads.Count)"
Write-Output "Handle Count: $($proc.HandleCount)"
Write-Output ""

Write-Output "--- Loaded Modules ---"
$proc.Modules | Select-Object -First 30 | ForEach-Object {{
    Write-Output "  $($_.ModuleName) - $($_.FileName) ($([math]::Round($_.ModuleMemorySize/1KB))KB)"
}}
if ($proc.Modules.Count -gt 30) {{
    Write-Output "  ... and $($proc.Modules.Count - 30) more modules"
}}
Write-Output ""

Write-Output "--- Network Connections ---"
$connections = Get-NetTCPConnection -OwningProcess $targetPid -ErrorAction SilentlyContinue
if ($connections) {{
    $connections | ForEach-Object {{
        Write-Output "  $($_.State): $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
    }}
}} else {{
    Write-Output "  No TCP connections"
}}

$udp = Get-NetUDPEndpoint -OwningProcess $targetPid -ErrorAction SilentlyContinue
if ($udp) {{
    $udp | ForEach-Object {{
        Write-Output "  UDP: $($_.LocalAddress):$($_.LocalPort)"
    }}
}}
""".format(pid=pid)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text(stdout)


# 19. monitor_network_realtime
async def _handle_monitor_network_realtime(args):
    duration = args.get("duration", 30)
    ps = """
$duration = {duration}
$allConnections = @()
$startTime = Get-Date

Write-Output "=== Network Monitoring ({duration}s) ==="
Write-Output "Start time: $startTime"
Write-Output ""

# Get baseline connections
$baseline = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
$baselineUdp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess

$newConnections = @()
$elapsed = 0

while ($elapsed -lt $duration) {{
    Start-Sleep -Seconds 1
    $elapsed++

    $current = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $current) {{
        $key = "$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
        $existing = $baseline | Where-Object {{
            $_.LocalPort -eq $conn.LocalPort -and $_.RemoteAddress -eq $conn.RemoteAddress -and $_.RemotePort -eq $conn.RemotePort
        }}
        if (-not $existing) {{
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $entry = "$($conn.State): $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [PID:$($conn.OwningProcess) $($proc.ProcessName)]"
            if ($entry -notin $newConnections) {{
                $newConnections += $entry
            }}
        }}
    }}
}}

Write-Output "--- New TCP Connections ---"
if ($newConnections.Count -gt 0) {{
    $newConnections | ForEach-Object {{ Write-Output "  $_" }}
}} else {{
    Write-Output "  No new connections detected"
}}
Write-Output ""

Write-Output "--- DNS Cache ---"
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 50
if ($dnsCache) {{
    $dnsCache | ForEach-Object {{
        Write-Output "  $($_.Entry) -> $($_.Data) (TTL: $($_.TimeToLive))"
    }}
}} else {{
    Write-Output "  DNS cache empty or unavailable"
}}
Write-Output ""

Write-Output "--- Current Listening Ports ---"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {{
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "  :$($_.LocalPort) [PID:$($_.OwningProcess) $($proc.ProcessName)]"
}}

Write-Output ""
Write-Output "Monitoring completed at $(Get-Date)"
""".format(duration=duration)
    stdout, stderr, code = await run_ps_async(ps, timeout=duration + 60)
    return _text(stdout)


# 20. fakenet_start
async def _handle_fakenet_start(args):
    extra = args.get("extra_excluded_ports", "")
    excluded = [5985, 5986, 445, 139, 13337]
    if extra:
        for p in extra.split(","):
            p = p.strip()
            if p.isdigit():
                excluded.append(int(p))

    # Determine the analyst (Kali) host IP from the live WinRM connection so the
    # FakeNet HostBlackList actually shields it. The previous code passed the
    # port list positionally as kali_ip, producing an invalid HostBlackList.
    kali_ip = None
    try:
        ip_out, _, _ = await run_ps_async(
            "(Get-NetTCPConnection -LocalPort 5985 -State Established "
            "-ErrorAction SilentlyContinue | Select-Object -First 1).RemoteAddress",
            timeout=15)
        ip_out = ip_out.strip().split("\n")[0].strip()
        if ip_out.count(".") == 3:
            kali_ip = ip_out
    except Exception:
        kali_ip = None

    # ── Option C: idempotent default-gateway + DNS self-heal ──────────────────
    # FakeNet-NG 3.5 requires a default route for its WFP diverter to classify
    # traffic as "external". Without one it prints "No gateways configured" and
    # only intercepts localhost traffic. We add a fake next-hop derived from the
    # VM's own IP (replace last octet with .1 — works for any /8–/30 setup).
    # The fake GW doesn't need to be reachable; FakeNet's kernel hook fires first.
    # Both ActiveStore (immediate) and persistent via `route -p` (survives
    # reboot/snapshot restore).
    ps_gw = r"""
# Use the existing default gateway if one already exists; otherwise derive one
# from the VM's primary IPv4 address (replace last octet with .1).
$existingGw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
               Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($existingGw -and $existingGw -ne '0.0.0.0') {
    # A real (or previously-added) gateway already routes external traffic.
    Write-Output "GW_OK: default route already present via $existingGw — no change needed"
} else {
    # Derive fake gateway from the VM's primary non-loopback IPv4 address.
    $vmIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } |
             Sort-Object InterfaceIndex | Select-Object -First 1).IPAddress
    if (-not $vmIp) {
        Write-Output "GW_WARN: could not determine VM IP — FakeNet may only intercept local traffic"
    } else {
        $octets = $vmIp -split '\.'
        $gw = "$($octets[0]).$($octets[1]).$($octets[2]).1"
        $ifIdx = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
                  Sort-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex
        New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIdx -NextHop $gw `
            -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        & route -p add 0.0.0.0 mask 0.0.0.0 $gw metric 1 | Out-Null
        # Verify
        $check = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                  Where-Object { $_.NextHop -eq $gw } | Select-Object -First 1)
        if ($check) {
            Write-Output "GW_ADDED: fake gateway $gw derived from VM IP $vmIp (active + persistent)"
        } else {
            Write-Output "GW_WARN: could not add default route via $gw — FakeNet may only intercept local traffic"
        }
    }
}
"""
    gw_out, gw_err, _ = await run_ps_async(ps_gw, timeout=20)
    gw_status = gw_out.strip().split("\n")[0].strip()

    config = generate_fakenet_config(kali_ip=kali_ip, excluded_ports=excluded)

    # Write config to FlareVM
    config_escaped = config.replace("'", "''")
    ps_write = """
New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null
@'
{config}
'@ | Out-File -FilePath "C:\\temp\\fakenet_mcp.ini" -Encoding ASCII
Write-Output "Config written to C:\\temp\\fakenet_mcp.ini"
""".format(config=config_escaped)
    stdout, stderr, code = await run_ps_async(ps_write, timeout=30)
    if code != 0:
        return _text("Failed to write FakeNet config: {} {}".format(stderr, stdout))

    # Clear stale capture artifacts so fakenet_stop reports only this run.
    await run_ps_async(
        'New-Item -ItemType Directory -Path "C:\\temp\\fakenet_logs" -Force | Out-Null; '
        'Remove-Item "C:\\temp\\fakenet_logs\\*" -Recurse -Force -ErrorAction SilentlyContinue',
        timeout=20)

    # Launch FakeNet directly via scheduled task — it needs the interactive
    # session for DNS/driver interception. (A .bat wrapper to redirect the
    # console is unreliable through Task Scheduler, so we collect FakeNet's
    # own pcap/dump artifacts in fakenet_stop instead.)
    fakenet_path = await resolve_tool_path("fakenet", "fakenet")
    result = await launch_gui_app(
        fakenet_path,
        arguments='-c "C:\\temp\\fakenet_mcp.ini"',
        task_name="MCP_FakeNet",
    )
    await asyncio.sleep(3)

    return _text("=== FakeNet-NG Started ===\n"
                 "Gateway pre-flight: {}\n"
                 "Config: C:\\temp\\fakenet_mcp.ini\n"
                 "Excluded ports: {}\n"
                 "Task: {}\n\n"
                 "FakeNet is now intercepting network traffic.\n"
                 "Use fakenet_stop to retrieve logs.".format(
                     gw_status,
                     ",".join(str(p) for p in excluded), result
                 ))


# 21. fakenet_stop
async def _handle_fakenet_stop(args):
    ps = r"""
# Stop the scheduled task and the FakeNet process tree. FakeNet-NG runs as a
# PyInstaller bundle named fakenet.exe; the .bat launcher may have spawned it.
Unregister-ScheduledTask -TaskName "MCP_FakeNet" -Confirm:$false -ErrorAction SilentlyContinue
Stop-Process -Name "fakenet*" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Output "=== FakeNet-NG Stopped ==="
Write-Output ""

# FakeNet-NG writes a packet capture (packets_*.pcap) and HTTP POST dumps to
# its working directory. Launched via Task Scheduler that CWD is System32, so
# sweep the likely locations for artifacts from the last 15 minutes.
$cutoff = (Get-Date).AddMinutes(-15)
$searchDirs = @("C:\temp\fakenet_logs", "C:\temp", "C:\Windows\System32",
                "C:\Tools\fakenet\fakenet3.5",
                "$env:LOCALAPPDATA\FakeNet-NG",
                "$env:USERPROFILE\Desktop")
$artifacts = foreach ($d in $searchDirs) {
    Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $cutoff -and
            ($_.Name -match 'packets_.*\.pcap$' -or $_.Name -match '^(http|nbns|dns|fakenet).*\.(txt|log|html)$') }
}
if ($artifacts) {
    Write-Output "--- Captured FakeNet Artifacts ---"
    $artifacts | Sort-Object LastWriteTime -Descending | ForEach-Object {
        Write-Output "  $($_.FullName) - $($_.Length) bytes - $($_.LastWriteTime)"
    }
    # Move the pcap(s) into the log dir for easy retrieval/download.
    New-Item -ItemType Directory -Path "C:\temp\fakenet_logs" -Force | Out-Null
    $artifacts | Where-Object { $_.Name -match 'packets_.*\.pcap$' } | ForEach-Object {
        Move-Item $_.FullName -Destination "C:\temp\fakenet_logs\" -Force -ErrorAction SilentlyContinue
    }
    Write-Output ""
    Write-Output "PCAP(s) moved to C:\temp\fakenet_logs\ (use download_file to retrieve)."
} else {
    Write-Output "No FakeNet capture artifacts found in the last 15 min."
    Write-Output "Tip: FakeNet writes packets_*.pcap to its working directory (often"
    Write-Output "C:\Tools\fakenet\fakenet3.5\ or C:\Windows\System32 when run via Task Scheduler)."
    Write-Output "DNS interception is confirmed working; PCAP capture requires the WFP"
    Write-Output "diverter to log traffic from an interactive-session process, not WinRM session 0."
}
"""
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 22. wireshark_capture
async def _handle_wireshark_capture(args):
    action = args["action"]
    output_path = args.get("output_path", "C:\\temp\\capture.pcap")
    interface = args.get("interface", "1")

    if action == "start":
        duration = args.get("duration", 60)
        # Find tshark
        ps_find = """
$paths = @("C:\\ProgramData\\chocolatey\\bin\\tshark.exe", "C:\\Program Files\\Wireshark\\tshark.exe")
foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; exit 0 } }
$w = where.exe tshark 2>$null | Select-Object -First 1
if ($w) { Write-Output $w } else { Write-Output "NOT_FOUND" }
"""
        tshark_stdout, _, _ = await run_ps_async(ps_find, timeout=15)
        tshark_path = tshark_stdout.strip().split("\n")[0].strip()
        if tshark_path == "NOT_FOUND":
            return _text("tshark not found on FlareVM")

        ps = 'Start-Process -FilePath "{}" -ArgumentList "-i {} -w `"{}`" -a duration:{}" -NoNewWindow -PassThru | Select-Object Id | Format-List'.format(
            tshark_path, interface, output_path, duration
        )
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        return _text("=== Packet Capture Started ===\n"
                     "Interface: {}\nDuration: {}s\nOutput: {}\n{}".format(
                         interface, duration, output_path, stdout
                     ))
    else:  # stop
        ps = """
Stop-Process -Name "tshark" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "dumpcap" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path "{path}") {{
    $size = (Get-Item "{path}").Length
    Write-Output "=== Packet Capture Stopped ==="
    Write-Output "File: {path}"
    Write-Output "Size: $size bytes"
}} else {{
    Write-Output "Capture stopped but PCAP file not found at {path}"
}}
""".format(path=output_path)
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        return _text(stdout)


# 23. regshot_snapshot
async def _handle_regshot_snapshot(args):
    action = args["action"]

    if action == "first":
        ps = """
New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null
Write-Output "=== Registry Snapshot: BEFORE ==="
Write-Output "Exporting HKLM..."
reg export HKLM "C:\\temp\\regshot_hklm_before.reg" /y 2>&1 | Out-Null
Write-Output "Exporting HKCU..."
reg export HKCU "C:\\temp\\regshot_hkcu_before.reg" /y 2>&1 | Out-Null

# Also snapshot scheduled tasks and services
Get-ScheduledTask | Select-Object TaskName, State | Out-File "C:\\temp\\tasks_before.txt" -Encoding UTF8
Get-Service | Select-Object Name, Status, StartType | Out-File "C:\\temp\\services_before.txt" -Encoding UTF8
Get-ChildItem "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Out-File "C:\\temp\\startup_before.txt" -Encoding UTF8

$hklmSize = (Get-Item "C:\\temp\\regshot_hklm_before.reg").Length
$hkcuSize = (Get-Item "C:\\temp\\regshot_hkcu_before.reg").Length
Write-Output "HKLM export: $([math]::Round($hklmSize/1MB, 2)) MB"
Write-Output "HKCU export: $([math]::Round($hkcuSize/1MB, 2)) MB"
Write-Output "Baseline snapshot complete."
""".format(user=FLAREVM_USER)
        stdout, stderr, code = await run_ps_async(ps, timeout=180)
        return _text(stdout)

    elif action == "second":
        ps = """
Write-Output "=== Registry Snapshot: AFTER ==="
Write-Output "Exporting HKLM..."
reg export HKLM "C:\\temp\\regshot_hklm_after.reg" /y 2>&1 | Out-Null
Write-Output "Exporting HKCU..."
reg export HKCU "C:\\temp\\regshot_hkcu_after.reg" /y 2>&1 | Out-Null

Get-ScheduledTask | Select-Object TaskName, State | Out-File "C:\\temp\\tasks_after.txt" -Encoding UTF8
Get-Service | Select-Object Name, Status, StartType | Out-File "C:\\temp\\services_after.txt" -Encoding UTF8
Get-ChildItem "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Out-File "C:\\temp\\startup_after.txt" -Encoding UTF8

$hklmSize = (Get-Item "C:\\temp\\regshot_hklm_after.reg").Length
$hkcuSize = (Get-Item "C:\\temp\\regshot_hkcu_after.reg").Length
Write-Output "HKLM export: $([math]::Round($hklmSize/1MB, 2)) MB"
Write-Output "HKCU export: $([math]::Round($hkcuSize/1MB, 2)) MB"
Write-Output "Post-execution snapshot complete."
""".format(user=FLAREVM_USER)
        stdout, stderr, code = await run_ps_async(ps, timeout=180)
        return _text(stdout)

    elif action == "compare":
        ps = r"""
Write-Output "=== Registry Comparison ==="
Write-Output ""

# Compare HKCU (smaller, faster, more interesting for malware)
Write-Output "--- HKCU Changes ---"
if ((Test-Path "C:\temp\regshot_hkcu_before.reg") -and (Test-Path "C:\temp\regshot_hkcu_after.reg")) {
    $before = Get-Content "C:\temp\regshot_hkcu_before.reg" -Encoding Unicode -ErrorAction SilentlyContinue
    $after = Get-Content "C:\temp\regshot_hkcu_after.reg" -Encoding Unicode -ErrorAction SilentlyContinue
    $diff = Compare-Object $before $after -ErrorAction SilentlyContinue | Select-Object -First 100
    if ($diff) {
        $added = ($diff | Where-Object { $_.SideIndicator -eq '=>' }).Count
        $removed = ($diff | Where-Object { $_.SideIndicator -eq '<=' }).Count
        Write-Output "Added/Modified lines: $added"
        Write-Output "Removed lines: $removed"
        Write-Output ""
        $diff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+ADD]" } else { "[-DEL]" }
            $line = $_.InputObject
            if ($line -match '^\[' -or $line -match '^"') {
                Write-Output "$indicator $line"
            }
        }
    } else {
        Write-Output "No HKCU changes detected."
    }
} else {
    Write-Output "Before/after HKCU snapshots not found."
}

Write-Output ""
Write-Output "--- Scheduled Task Changes ---"
if ((Test-Path "C:\temp\tasks_before.txt") -and (Test-Path "C:\temp\tasks_after.txt")) {
    $tbefore = Get-Content "C:\temp\tasks_before.txt"
    $tafter = Get-Content "C:\temp\tasks_after.txt"
    $tdiff = Compare-Object $tbefore $tafter -ErrorAction SilentlyContinue
    if ($tdiff) {
        $tdiff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+NEW]" } else { "[-DEL]" }
            Write-Output "$indicator $($_.InputObject)"
        }
    } else {
        Write-Output "No task changes."
    }
}

Write-Output ""
Write-Output "--- Service Changes ---"
if ((Test-Path "C:\temp\services_before.txt") -and (Test-Path "C:\temp\services_after.txt")) {
    $sbefore = Get-Content "C:\temp\services_before.txt"
    $safter = Get-Content "C:\temp\services_after.txt"
    $sdiff = Compare-Object $sbefore $safter -ErrorAction SilentlyContinue
    if ($sdiff) {
        $sdiff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+NEW]" } else { "[-DEL]" }
            Write-Output "$indicator $($_.InputObject)"
        }
    } else {
        Write-Output "No service changes."
    }
}

Write-Output ""
Write-Output "--- Startup Folder Changes ---"
if ((Test-Path "C:\temp\startup_before.txt") -and (Test-Path "C:\temp\startup_after.txt")) {
    $supbefore = Get-Content "C:\temp\startup_before.txt"
    $supafter = Get-Content "C:\temp\startup_after.txt"
    $supdiff = Compare-Object $supbefore $supafter -ErrorAction SilentlyContinue
    if ($supdiff) {
        $supdiff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+NEW]" } else { "[-DEL]" }
            Write-Output "$indicator $($_.InputObject)"
        }
    } else {
        Write-Output "No startup folder changes."
    }
}

Write-Output ""
Write-Output "--- HKLM Run Keys (current) ---"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($items) {
        Write-Output "  $key :"
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "    $($_.Name) = $($_.Value)"
        }
    }
}

Write-Output ""
Write-Output "Comparison complete."
"""
        # This comparison script is large; send it as a staged file rather than
        # inline so it doesn't blow the WinRM/cmd command-line length limit
        # ("The command line is too long").
        stdout, stderr, code = await run_ps_script(ps, timeout=180,
                                                   script_name="regshot_compare.ps1")
        result = stdout
        if stderr:
            result += "\n--- Warnings ---\n" + stderr
        return _text(result)

    return _text("Unknown regshot action: {}. Use 'first', 'second', or 'compare'.".format(action))


# 24. x64dbg_load
async def _handle_x64dbg_load(args):
    file_path = args["file_path"]
    arguments = args.get("arguments", "")
    x64dbg_path = await resolve_tool_path("x64dbg", "x64dbg")
    dbg_args = '"{}"'.format(file_path)
    if arguments:
        dbg_args += " " + arguments
    result = await launch_gui_app(
        x64dbg_path,
        arguments=dbg_args,
        task_name="MCP_x64dbg",
    )
    return _text("=== x64dbg Launched ===\nBinary: {}\nArguments: {}\n{}".format(
        file_path, arguments, result
    ))


# 25. x64dbg_run_script
async def _handle_x64dbg_run_script(args):
    script = args["script"]
    script_path = args.get("script_path", "C:\\temp\\x64dbg_script.txt")
    # Write script to file
    script_escaped = script.replace("'", "''")
    ps = """
@'
{script}
'@ | Out-File -FilePath "{path}" -Encoding ASCII
Write-Output "Script saved to {path}"
""".format(script=script_escaped, path=script_path)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Failed to write script: {} {}".format(stderr, stdout))

    # Execute script via x64dbg command line
    ps_run = """
# x64dbg supports script execution via command line
# The script file will be picked up by the running x64dbg instance
$x64dbg = Get-Process -Name "x64dbg" -ErrorAction SilentlyContinue
if (-not $x64dbg) {{
    $x64dbg = Get-Process -Name "x96dbg" -ErrorAction SilentlyContinue
}}
if ($x64dbg) {{
    Write-Output "x64dbg is running (PID: $($x64dbg.Id))"
    Write-Output "Script saved to: {path}"
    Write-Output "Load the script in x64dbg: scriptload `"{path}`""
}} else {{
    Write-Output "WARNING: x64dbg does not appear to be running."
    Write-Output "Script saved to: {path}"
    Write-Output "Start x64dbg first, then load the script manually."
}}
""".format(path=script_path)
    stdout2, _, _ = await run_ps_async(ps_run, timeout=15)
    return _text(stdout + "\n" + stdout2)


# 26. windbg_analyze_dump
async def _handle_windbg_analyze_dump(args):
    dump_file = args["dump_file"]
    include_stack_trace = args.get("include_stack_trace", True)
    include_modules = args.get("include_modules", True)
    include_threads = args.get("include_threads", True)
    symbols_path = args.get("symbols_path")
    extra_commands = args.get("extra_commands") or []

    open_args = {
        "dump_path": dump_file,
        "include_stack_trace": include_stack_trace,
        "include_modules": include_modules,
        "include_threads": include_threads,
    }
    if symbols_path:
        open_args["symbols_path"] = symbols_path

    try:
        result = await windbg_rpc_call("open_windbg_dump", open_args, timeout=180)
    except RuntimeError as e:
        return _text("mcp-windbg error: {}\n\nHint: ensure MCP_WinDbg_Server scheduled task is running (setup.py provisions it).".format(e))

    output = result if isinstance(result, str) else json.dumps(result, indent=2)

    extra_output = ""
    for cmd in extra_commands:
        try:
            cmd_result = await windbg_rpc_call("run_windbg_cmd", {
                "dump_path": dump_file,
                "command": cmd,
            }, timeout=60)
            cmd_text = cmd_result if isinstance(cmd_result, str) else json.dumps(cmd_result, indent=2)
            extra_output += "\n\n--- {} ---\n{}".format(cmd, cmd_text)
        except RuntimeError as e:
            extra_output += "\n\n--- {} (error) ---\n{}".format(cmd, e)

    return _text("=== WinDbg Analysis (mcp-windbg) ===\nDump: {}\n\n{}{}".format(
        dump_file, output, extra_output
    ))


# 27. frida_list_processes
async def _handle_frida_list_processes(args):
    ps = 'frida-ps 2>&1'
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Frida error: {} {}".format(stderr, stdout))
    return _text("=== Frida Process List ===\n" + stdout)


# 28. frida_spawn_and_attach
async def _handle_frida_spawn_and_attach(args):
    executable = args["executable"]
    script = args["script"]
    timeout = args.get("timeout", 30)
    # Write script to temp file
    script_escaped = script.replace("'", "''")
    ps = """
$scriptContent = @'
{script}
'@
$scriptPath = "C:\\temp\\frida_spawn_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Output "Script saved to $scriptPath"
$output = & frida -f "{exe}" -l $scriptPath -q --timeout {timeout} 2>&1
Write-Output $output
""".format(script=script_escaped, exe=executable.replace('"', '`"'), timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Spawn & Attach ===\nExecutable: {}\n\n{}".format(executable, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


# 29. frida_attach_pid
async def _handle_frida_attach_pid(args):
    pid = args["pid"]
    script = args["script"]
    timeout = args.get("timeout", 30)
    script_escaped = script.replace("'", "''")
    ps = """
$scriptContent = @'
{script}
'@
$scriptPath = "C:\\temp\\frida_attach_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Output "Script saved to $scriptPath"
$output = & frida -p {pid} -l $scriptPath -q --timeout {timeout} 2>&1
Write-Output $output
""".format(script=script_escaped, pid=pid, timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Attach (PID: {}) ===\n\n{}".format(pid, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


# 30. frida_run_script
async def _handle_frida_run_script(args):
    target = args["target"]
    script = args["script"]
    timeout = args.get("timeout", 30)
    script_escaped = script.replace("'", "''")
    # Determine if target is PID (numeric) or process name
    try:
        pid = int(target)
        target_flag = "-p {}".format(pid)
    except ValueError:
        target_flag = '-n "{}"'.format(target)

    ps = """
$scriptContent = @'
{script}
'@
$scriptPath = "C:\\temp\\frida_run_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
$output = & frida {target_flag} -l $scriptPath -q --timeout {timeout} 2>&1
Write-Output $output
""".format(script=script_escaped, target_flag=target_flag, timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Script Execution ===\nTarget: {}\n\n{}".format(target, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


# 31. pe_sieve_scan
async def _handle_pe_sieve_scan(args):
    pid = args["pid"]
    output_dir = args.get("output_dir", "C:\\temp\\pe_sieve_output")
    pe_sieve_path = await resolve_tool_path("pe_sieve", "pe-sieve")
    ps = """
New-Item -ItemType Directory -Path "{output}" -Force | Out-Null
$result = & "{tool}" /pid {pid} /dir "{output}" /shellc 3 /iat 3 /data 3 2>&1
Write-Output "=== PE-sieve Scan (PID: {pid}) ==="
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Output Files ---"
Get-ChildItem -Path "{output}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    Write-Output "  $($_.Name) - $($_.Length) bytes"
}}
""".format(tool=pe_sieve_path, pid=pid, output=output_dir)
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 32. hollows_hunter_scan
async def _handle_hollows_hunter_scan(args):
    output_dir = args.get("output_dir", "C:\\temp\\hollows_output")
    hh_path = await resolve_tool_path("hollows_hunter", "hollows_hunter")
    ps = """
New-Item -ItemType Directory -Path "{output}" -Force | Out-Null
$result = & "{tool}" /dir "{output}" /shellc 3 /iat 3 2>&1
Write-Output "=== Hollows Hunter Scan (All Processes) ==="
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Output Files ---"
Get-ChildItem -Path "{output}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    Write-Output "  $($_.Name) - $($_.Length) bytes"
}}
""".format(tool=hh_path, output=output_dir)
    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 33. upx_unpack
async def _handle_upx_unpack(args):
    packed_file = args["packed_file"]
    output_file = args["output_file"]
    upx_path = await resolve_tool_path("upx", "upx")
    ps = '& "{}" -d "{}" -o "{}" 2>&1'.format(
        upx_path, packed_file.replace('"', '`"'), output_file.replace('"', '`"')
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = "=== UPX Unpack ===\nInput: {}\nOutput: {}\n\n{}".format(
        packed_file, output_file, stdout
    )
    if code == 0:
        # Verify output
        ps_check = """
if (Test-Path "{out}") {{
    $size = (Get-Item "{out}").Length
    Write-Output "Unpacked file size: $size bytes"
    $hash = (Get-FileHash -Path "{out}" -Algorithm SHA256).Hash
    Write-Output "SHA256: $hash"
}} else {{
    Write-Output "Output file not created"
}}
""".format(out=output_file)
        check_stdout, _, _ = await run_ps_async(ps_check, timeout=15)
        result += "\n" + check_stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 34. unpack_detect_and_try
async def _handle_unpack_detect_and_try(args):
    file_path = args["file_path"]
    report_parts = ["=== Automated Unpack: Detect & Try ===", "File: {}".format(file_path), ""]

    # Step 1: DIE analysis
    try:
        die_result = await _handle_die_analyze({"file_path": file_path})
        die_text = die_result[0].text if die_result else "DIE analysis failed"
        report_parts.append("--- Step 1: Packer Detection (DIE) ---")
        report_parts.append(die_text)
        report_parts.append("")
    except Exception as e:
        die_text = str(e)
        report_parts.append("DIE failed: " + die_text)

    # Step 2: Entropy analysis
    try:
        ent_result = await _handle_entropy_analysis({"file_path": file_path})
        ent_text = ent_result[0].text if ent_result else "Entropy analysis failed"
        report_parts.append("--- Step 2: Entropy Analysis ---")
        report_parts.append(ent_text)
        report_parts.append("")
    except Exception as e:
        ent_text = str(e)
        report_parts.append("Entropy analysis failed: " + ent_text)

    # Step 3: Try UPX if detected
    die_lower = die_text.lower()
    if "upx" in die_lower:
        report_parts.append("--- Step 3: UPX Detected - Attempting Unpack ---")
        basename = ntpath.splitext(ntpath.basename(file_path))[0]
        output_file = "C:\\temp\\{}_unpacked.exe".format(basename)
        try:
            upx_result = await _handle_upx_unpack({
                "packed_file": file_path,
                "output_file": output_file,
            })
            report_parts.append(upx_result[0].text if upx_result else "UPX unpack failed")
        except Exception as e:
            report_parts.append("UPX unpack failed: " + str(e))
        report_parts.append("")

        # Run FLOSS on unpacked binary
        if await _file_exists(output_file):
            report_parts.append("--- Step 4: FLOSS on Unpacked Binary ---")
            try:
                floss_result = await _handle_floss_extract_strings({
                    "file_path": output_file, "min_length": 6
                })
                report_parts.append(floss_result[0].text if floss_result else "FLOSS failed")
            except Exception as e:
                report_parts.append("FLOSS failed: " + str(e))
    elif "aspack" in die_lower or "mpress" in die_lower or "packed" in die_lower or "PACKED" in ent_text:
        report_parts.append("--- Step 3: Packer Detected - Attempting Runtime Unpack ---")
        # Run the binary briefly, then pe-sieve
        ps_run = """
$proc = Start-Process -FilePath "{file}" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
Write-Output "Started process PID: $($proc.Id)"
$proc.Id
""".format(file=file_path.replace('"', '`"'))
        try:
            stdout, _, code = await run_ps_async(ps_run, timeout=30)
            lines = stdout.strip().split("\n")
            pid_str = lines[-1].strip()
            if pid_str.isdigit():
                pid = int(pid_str)
                report_parts.append("Process started with PID: {}".format(pid))

                # PE-sieve scan
                try:
                    sieve_result = await _handle_pe_sieve_scan({
                        "pid": pid,
                        "output_dir": "C:\\temp\\unpack_pe_sieve",
                    })
                    report_parts.append(sieve_result[0].text if sieve_result else "pe-sieve failed")
                except Exception as e:
                    report_parts.append("pe-sieve failed: " + str(e))

                # Kill the process
                await run_ps_async("Stop-Process -Id {} -Force -ErrorAction SilentlyContinue".format(pid), timeout=10)

                # Check for dumped modules
                ps_check = """
$dumps = Get-ChildItem -Path "C:\\temp\\unpack_pe_sieve" -Filter "*.dll","*.exe" -ErrorAction SilentlyContinue
if ($dumps) {
    Write-Output "Dumped modules:"
    $dumps | ForEach-Object { Write-Output "  $($_.Name) - $($_.Length) bytes" }
} else {
    Write-Output "No modules dumped by pe-sieve"
}
"""
                check_stdout, _, _ = await run_ps_async(ps_check, timeout=15)
                report_parts.append(check_stdout)
            else:
                report_parts.append("Failed to start process: " + stdout)
        except Exception as e:
            report_parts.append("Runtime unpack failed: " + str(e))
    else:
        report_parts.append("--- Step 3: No Known Packer Detected ---")
        report_parts.append("Binary does not appear to be packed with a known packer.")
        report_parts.append("Running FLOSS on original binary for string recovery.")
        try:
            floss_result = await _handle_floss_extract_strings({
                "file_path": file_path, "min_length": 6
            })
            report_parts.append(floss_result[0].text if floss_result else "FLOSS failed")
        except Exception as e:
            report_parts.append("FLOSS failed: " + str(e))

    return _text("\n".join(report_parts))


async def _file_exists(path):
    """Check if a file exists on FlareVM."""
    stdout, _, code = await run_ps_async('Test-Path "{}"'.format(path.replace('"', '`"')), timeout=10)
    return stdout.strip().lower() == "true"


# 35. dnspy_decompile
async def _handle_dnspy_decompile(args):
    assembly_path = args["assembly_path"]
    output_dir = args.get("output_dir", "C:\\temp\\decompiled")
    dnspy_path = await resolve_tool_path("dnspy", "dnSpy.Console")
    ps = """
New-Item -ItemType Directory -Path "{output}" -Force | Out-Null
$result = & "{tool}" -o "{output}" "{assembly}" 2>&1
Write-Output "=== dnSpy Decompilation ==="
Write-Output "Assembly: {assembly}"
Write-Output "Output: {output}"
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Decompiled Files ---"
Get-ChildItem -Path "{output}" -Recurse -File | Select-Object -First 50 | ForEach-Object {{
    Write-Output "  $($_.FullName.Replace('{output}\\', '')) ($($_.Length) bytes)"
}}
$totalFiles = (Get-ChildItem -Path "{output}" -Recurse -File | Measure-Object).Count
Write-Output ""
Write-Output "Total decompiled files: $totalFiles"
""".format(tool=dnspy_path, assembly=assembly_path.replace('"', '`"'), output=output_dir)
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 36. ida_launch_and_wait
async def _handle_ida_launch_and_wait(args):
    binary_path = args["binary_path"]
    ida_path = args.get("ida_path", "C:\\Tools\\IDA Pro\\ida64.exe")

    result = await launch_gui_app(
        ida_path,
        arguments='"{}"'.format(binary_path),
        task_name="MCP_IDA",
        wait_port=IDA_MCP_PORT,
        wait_timeout=60,
    )

    # Try to get initial metadata
    metadata = ""
    try:
        meta_result = await ida_rpc_call("get_metadata")
        if "result" in meta_result:
            metadata = "\n--- IDA Metadata ---\n" + json.dumps(meta_result["result"], indent=2)
    except Exception as e:
        metadata = "\nNote: Could not fetch metadata yet: " + str(e)

    return _text("=== IDA Pro Launched ===\nBinary: {}\n{}\n{}".format(
        binary_path, result, metadata
    ))


# 37. windbg_launch
async def _handle_windbg_launch(args):
    dump_file = args["dump_file"]
    windbg_path = args.get("windbg_path", "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe")

    ps_find = (
        "$paths = @(\n"
        "    '{windbg}',\n"
        "    'C:\\\\Program Files (x86)\\\\Windows Kits\\\\10\\\\Debuggers\\\\x64\\\\windbg.exe',\n"
        "    'C:\\\\Program Files\\\\Windows Kits\\\\10\\\\Debuggers\\\\x64\\\\windbg.exe',\n"
        "    \"$env:LOCALAPPDATA\\\\Microsoft\\\\WindowsApps\\\\WinDbgX.exe\"\n"
        ")\n"
        "foreach ($p in $paths) {{ if (Test-Path $p) {{ Write-Output $p; exit 0 }} }}\n"
        "$w = where.exe windbg 2>$null | Select-Object -First 1\n"
        "if ($w) {{ Write-Output $w }} else {{ Write-Output 'NOT_FOUND' }}\n"
    ).format(windbg=windbg_path.replace("'", "''"))
    stdout, _, _ = await run_ps_async(ps_find, timeout=15)
    actual_path = stdout.strip().split("\n")[0].strip()
    if actual_path == "NOT_FOUND":
        return _text("WinDbg not found on FlareVM. Install via: winget install Microsoft.WinDbg")

    result = await launch_gui_app(
        actual_path,
        arguments='-z "{}"'.format(dump_file),
        task_name="MCP_WinDbg_GUI",
    )
    return _text("=== WinDbg Launched ===\nDump: {}\n{}".format(dump_file, result))


# 37b. windbg_run_cmd
async def _handle_windbg_run_cmd(args):
    dump_file = args["dump_file"]
    command = args["command"]
    try:
        cmd_result = await windbg_rpc_call("run_windbg_cmd", {
            "dump_path": dump_file,
            "command": command,
        }, timeout=60)
    except RuntimeError as e:
        return _text("mcp-windbg error: {}\n\nHint: call windbg_analyze_dump first to open the session.".format(e))
    output = cmd_result if isinstance(cmd_result, str) else json.dumps(cmd_result, indent=2)
    return _text("=== WinDbg Command ===\nDump: {}\nCommand: {}\n\n{}".format(dump_file, command, output))


# 37c. windbg_list_dumps
async def _handle_windbg_list_dumps(args):
    directory_path = args.get("directory_path")
    list_args = {}
    if directory_path:
        list_args["directory_path"] = directory_path
    try:
        result = await windbg_rpc_call("list_windbg_dumps", list_args, timeout=30)
    except RuntimeError as e:
        return _text("mcp-windbg error: {}".format(e))
    output = result if isinstance(result, str) else json.dumps(result, indent=2)
    return _text("=== WinDbg Dump Files ===\n{}".format(output))


# 38. ida_get_metadata
async def _handle_ida_get_metadata(args):
    md = await ida_rpc_call("get_metadata")
    return _text("=== IDA Pro Metadata ===\n" + json.dumps(md, indent=2))


def _ida_unwrap_list(res):
    """The MCP list_* tools return {'data': [...], 'next_offset': N}."""
    if isinstance(res, dict) and "data" in res:
        return res["data"]
    return res if isinstance(res, list) else [res]


# 39. ida_list_functions
async def _handle_ida_list_functions(args):
    offset = args.get("offset", 0)
    count = args.get("count") or 100
    flt = args.get("filter")
    if flt:
        res = await ida_rpc_call("list_functions_filter",
                                 {"offset": offset, "count": count, "filter": flt})
    else:
        res = await ida_rpc_call("list_functions", {"offset": offset, "count": count})
    funcs = _ida_unwrap_list(res)
    lines = ["=== IDA Functions ({} shown) ===".format(len(funcs)), ""]
    for f in funcs:
        if isinstance(f, dict):
            lines.append("  {}: {} (size: {})".format(
                f.get("address", "?"), f.get("name", "?"), f.get("size", "?")))
        else:
            lines.append("  " + str(f))
    return _text("\n".join(lines))


# 40. ida_decompile_function
async def _handle_ida_decompile_function(args):
    target = args["function_name"]
    addr = await _ida_resolve_address(target)
    code = await ida_rpc_call("decompile_function", {"address": addr})
    body = code if isinstance(code, str) else json.dumps(code, indent=2)
    return _text("=== Decompiled: {} ({}) ===\n\n{}".format(target, addr, body))


# 41. ida_disassemble_function
async def _handle_ida_disassemble_function(args):
    target = args["function_name"]
    addr = await _ida_resolve_address(target)
    asm = await ida_rpc_call("disassemble_function", {"start_address": addr})
    body = asm if isinstance(asm, str) else json.dumps(asm, indent=2)
    return _text("=== Disassembly: {} ({}) ===\n\n{}".format(target, addr, body))


# 42. ida_list_strings
async def _handle_ida_list_strings(args):
    offset = args.get("offset", 0)
    count = args.get("count") or 100
    flt = args.get("filter")
    if flt:
        res = await ida_rpc_call("list_strings_filter",
                                 {"offset": offset, "count": count, "filter": flt})
    else:
        res = await ida_rpc_call("list_strings", {"offset": offset, "count": count})
    strings = _ida_unwrap_list(res)
    lines = ["=== IDA Strings ({} shown) ===".format(len(strings)), ""]
    for s in strings:
        if isinstance(s, dict):
            val = s.get("string", s.get("value", s.get("text", "?")))
            lines.append("  {}: {}".format(s.get("address", "?"), val))
        else:
            lines.append("  " + str(s))
    return _text("\n".join(lines))


# 43. ida_set_comment
async def _handle_ida_set_comment(args):
    await ida_rpc_call("set_comment", {
        "address": args["address"],
        "comment": args["comment"],
    })
    return _text("Comment set at {}: {}".format(args["address"], args["comment"]))


# 44. ida_rename_function
async def _handle_ida_rename_function(args):
    old = args["old_name"]
    addr = await _ida_resolve_address(old)
    await ida_rpc_call("rename_function", {
        "function_address": addr,
        "new_name": args["new_name"],
    })
    return _text("Function renamed: {} ({}) -> {}".format(old, addr, args["new_name"]))


# 45. triage_full
async def _handle_triage_full(args):
    file_path = args["file_path"]
    report = ["=" * 60, "FULL STATIC TRIAGE REPORT", "=" * 60, "File: {}".format(file_path), ""]

    # 1. Hashes
    report.append("--- 1. File Hashes ---")
    try:
        hash_result = await _handle_get_file_hash({"file_path": file_path})
        report.append(hash_result[0].text if hash_result else "Hash calculation failed")
    except Exception as e:
        report.append("Hash error: " + str(e))
    report.append("")

    # 2. DIE
    report.append("--- 2. Packer/Compiler Detection (DIE) ---")
    try:
        die_result = await _handle_die_analyze({"file_path": file_path})
        report.append(die_result[0].text if die_result else "DIE failed")
    except Exception as e:
        report.append("DIE error: " + str(e))
    report.append("")

    # 3. Entropy
    report.append("--- 3. Section Entropy ---")
    try:
        ent_result = await _handle_entropy_analysis({"file_path": file_path})
        report.append(ent_result[0].text if ent_result else "Entropy analysis failed")
    except Exception as e:
        report.append("Entropy error: " + str(e))
    report.append("")

    # 4. CAPA
    report.append("--- 4. Capability Detection (CAPA) ---")
    try:
        capa_result = await _handle_capa_analyze({"file_path": file_path})
        report.append(capa_result[0].text if capa_result else "CAPA failed")
    except Exception as e:
        report.append("CAPA error: " + str(e))
    report.append("")

    # 5. FLOSS
    report.append("--- 5. String Recovery (FLOSS) ---")
    try:
        floss_result = await _handle_floss_extract_strings({
            "file_path": file_path, "min_length": 6
        })
        report.append(floss_result[0].text if floss_result else "FLOSS failed")
    except Exception as e:
        report.append("FLOSS error: " + str(e))
    report.append("")

    # 6. YARA
    report.append("--- 6. YARA Rule Matching ---")
    try:
        yara_result = await _handle_yara_scan({"file_path": file_path})
        report.append(yara_result[0].text if yara_result else "YARA failed")
    except Exception as e:
        report.append("YARA error: " + str(e))
    report.append("")

    report.append("=" * 60)
    report.append("END OF TRIAGE REPORT")
    report.append("=" * 60)

    return _text("\n".join(report))


# 46. behavioral_full
async def _handle_behavioral_full(args):
    executable = args["executable"]
    arguments = args.get("arguments", "")
    duration = args.get("duration", 30)

    report = ["=" * 60, "FULL BEHAVIORAL ANALYSIS REPORT", "=" * 60,
              "Executable: {}".format(executable),
              "Arguments: {}".format(arguments),
              "Duration: {}s".format(duration), ""]

    # 1. Registry baseline
    report.append("--- Step 1: Registry Baseline ---")
    try:
        reg1 = await _handle_regshot_snapshot({"action": "first"})
        report.append(reg1[0].text if reg1 else "Failed")
    except Exception as e:
        report.append("Regshot baseline error: " + str(e))
    report.append("")

    # 2. Start ProcMon
    report.append("--- Step 2: Start ProcMon ---")
    try:
        pm_start = await _handle_procmon_start({
            "output_path": "C:\\temp\\behavioral_procmon.pml",
            "process_filter": ntpath.basename(executable),
        })
        report.append(pm_start[0].text if pm_start else "Failed")
    except Exception as e:
        report.append("ProcMon start error: " + str(e))
    report.append("")

    # 3. Start FakeNet
    report.append("--- Step 3: Start FakeNet ---")
    try:
        fn_start = await _handle_fakenet_start({})
        report.append(fn_start[0].text if fn_start else "Failed")
    except Exception as e:
        report.append("FakeNet start error: " + str(e))
    report.append("")

    # 4. Start network monitoring (in parallel with execution)
    report.append("--- Step 4: Execute Malware ---")
    exec_cmd = '"{}"'.format(executable)
    if arguments:
        exec_cmd += " " + arguments
    ps_exec = """
$proc = Start-Process -FilePath "{exe}" -ArgumentList '{args}' -PassThru -WindowStyle Hidden
Write-Output "Started: $($proc.ProcessName) (PID: $($proc.Id))"
$proc.Id
""".format(exe=executable.replace('"', '`"'), args=arguments.replace("'", "''"))
    try:
        stdout, stderr, code = await run_ps_async(ps_exec, timeout=30)
        report.append(stdout)
        mal_pid = None
        lines = stdout.strip().split("\n")
        pid_str = lines[-1].strip()
        if pid_str.isdigit():
            mal_pid = int(pid_str)
    except Exception as e:
        report.append("Execution error: " + str(e))
        mal_pid = None
    report.append("")

    # 5. Wait for duration
    report.append("--- Step 5: Monitoring for {}s ---".format(duration))
    await asyncio.sleep(duration)
    report.append("Monitoring period complete.")
    report.append("")

    # 6. Kill malware process
    if mal_pid:
        await run_ps_async("Stop-Process -Id {} -Force -ErrorAction SilentlyContinue".format(mal_pid), timeout=10)
        report.append("Malware process (PID: {}) terminated.".format(mal_pid))
    report.append("")

    # 7. Stop FakeNet and collect logs
    report.append("--- Step 6: FakeNet Results ---")
    try:
        fn_stop = await _handle_fakenet_stop({})
        report.append(fn_stop[0].text if fn_stop else "Failed")
    except Exception as e:
        report.append("FakeNet stop error: " + str(e))
    report.append("")

    # 8. Stop ProcMon and export
    report.append("--- Step 7: ProcMon Results ---")
    try:
        pm_stop = await _handle_procmon_stop({
            "pml_path": "C:\\temp\\behavioral_procmon.pml",
            "csv_path": "C:\\temp\\behavioral_procmon.csv",
        })
        report.append(pm_stop[0].text if pm_stop else "Failed")
    except Exception as e:
        report.append("ProcMon stop error: " + str(e))
    report.append("")

    # 9. Registry after + compare
    report.append("--- Step 8: Registry Changes ---")
    try:
        reg2 = await _handle_regshot_snapshot({"action": "second"})
        report.append(reg2[0].text if reg2 else "Failed")
        report.append("")
        reg_cmp = await _handle_regshot_snapshot({"action": "compare"})
        report.append(reg_cmp[0].text if reg_cmp else "Failed")
    except Exception as e:
        report.append("Regshot compare error: " + str(e))
    report.append("")

    # 10. Network state
    report.append("--- Step 9: Post-Execution Network State ---")
    ps_net = """
Write-Output "--- Active Connections ---"
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "  $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($proc.ProcessName)]"
}
Write-Output ""
Write-Output "--- DNS Cache ---"
Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
    Write-Output "  $($_.Entry) -> $($_.Data)"
}
"""
    try:
        net_stdout, _, _ = await run_ps_async(ps_net, timeout=30)
        report.append(net_stdout)
    except Exception as e:
        report.append("Network state error: " + str(e))

    report.append("")
    report.append("=" * 60)
    report.append("END OF BEHAVIORAL ANALYSIS REPORT")
    report.append("=" * 60)

    return _text("\n".join(report))


# 47. persistence_audit
async def _handle_persistence_audit(args):
    ps = r"""
Write-Output "============================================================"
Write-Output "PERSISTENCE MECHANISM AUDIT"
Write-Output "============================================================"
Write-Output ""

# 1. Autoruns (if available)
Write-Output "--- 1. Autoruns Analysis ---"
$autorunsc = "C:\Tools\sysinternals\autorunsc.exe"
if (Test-Path $autorunsc) {
    $ar = & $autorunsc -accepteula -a * -c -nobanner 2>&1 | Select-Object -First 100
    $ar | ForEach-Object { Write-Output "  $_" }
} else {
    Write-Output "  autorunsc.exe not found, using manual checks"
}
Write-Output ""

# 2. Registry Run Keys
Write-Output "--- 2. Registry Run Keys ---"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)
foreach ($key in $runKeys) {
    $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($items) {
        Write-Output "  $key :"
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "    $($_.Name) = $($_.Value)"
        }
    }
}
Write-Output ""

# 3. Scheduled Tasks
Write-Output "--- 3. Scheduled Tasks (non-Microsoft) ---"
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled'
} | Select-Object -First 30 | ForEach-Object {
    $action = ($_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)
    Write-Output "  Task: $($_.TaskName)"
    Write-Output "  Path: $($_.TaskPath)"
    Write-Output "  State: $($_.State)"
    $actions = $_.Actions
    foreach ($a in $actions) {
        Write-Output "  Action: $($a.Execute) $($a.Arguments)"
    }
    Write-Output ""
}
Write-Output ""

# 4. Services
Write-Output "--- 4. Services (non-standard) ---"
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch 'C:\\Windows\\system32\\svchost' -and $_.PathName -notmatch 'C:\\Windows\\servicing'
} | Select-Object -First 30 | ForEach-Object {
    Write-Output "  $($_.Name) [$($_.State)] - $($_.PathName)"
}
Write-Output ""

# 5. WMI Event Subscriptions
Write-Output "--- 5. WMI Event Subscriptions ---"
$consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
$filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
$bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
if ($consumers) {
    Write-Output "  Event Consumers:"
    $consumers | ForEach-Object { Write-Output "    $($_.Name): $($_.CommandLineTemplate)" }
}
if ($filters) {
    Write-Output "  Event Filters:"
    $filters | ForEach-Object { Write-Output "    $($_.Name): $($_.Query)" }
}
if ($bindings) {
    Write-Output "  Bindings:"
    $bindings | ForEach-Object { Write-Output "    Filter=$($_.Filter) -> Consumer=$($_.Consumer)" }
}
if (-not $consumers -and -not $filters) {
    Write-Output "  No WMI event subscriptions found."
}
Write-Output ""

# 6. Startup Folders
Write-Output "--- 6. Startup Folders ---"
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach ($sp in $startupPaths) {
    Write-Output "  $sp :"
    $items = Get-ChildItem -Path $sp -ErrorAction SilentlyContinue
    if ($items) {
        $items | ForEach-Object { Write-Output "    $($_.Name) ($($_.Length) bytes)" }
    } else {
        Write-Output "    (empty)"
    }
}
Write-Output ""

# 7. DLL search order hijacking indicators
Write-Output "--- 7. Suspicious DLLs in PATH ---"
$env:PATH -split ';' | Where-Object { $_ -and $_ -notmatch 'Windows|System32|Program Files' } | ForEach-Object {
    $dlls = Get-ChildItem -Path $_ -Filter "*.dll" -ErrorAction SilentlyContinue | Select-Object -First 5
    if ($dlls) {
        Write-Output "  $_ :"
        $dlls | ForEach-Object { Write-Output "    $($_.Name)" }
    }
}
Write-Output ""
Write-Output "============================================================"
Write-Output "END OF PERSISTENCE AUDIT"
Write-Output "============================================================"
"""
    # Script is too long for inline command — write to file then invoke
    stdout, stderr, code = await run_ps_script(
        ps, timeout=180, script_name="persistence_audit.ps1"
    )
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 48. injection_scan_all
async def _handle_injection_scan_all(args):
    report = ["=" * 60, "INJECTION SCAN - ALL PROCESSES", "=" * 60, ""]

    # Step 1: Hollows Hunter scan
    report.append("--- Step 1: Hollows Hunter (All Processes) ---")
    try:
        hh_result = await _handle_hollows_hunter_scan({
            "output_dir": "C:\\temp\\injection_scan_hh"
        })
        hh_text = hh_result[0].text if hh_result else "Failed"
        report.append(hh_text)
    except Exception as e:
        hh_text = ""
        report.append("Hollows Hunter error: " + str(e))
    report.append("")

    # Step 2: Parse hollows_hunter output for suspicious PIDs
    ps_parse = r"""
$scanDir = "C:\temp\injection_scan_hh"
$suspiciousPids = @()
if (Test-Path $scanDir) {
    # Look for process-specific subdirectories (format: pid_processname)
    Get-ChildItem -Path $scanDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $dirName = $_.Name
        if ($dirName -match '^(\d+)_') {
            $targetPid = $Matches[1]
            $files = (Get-ChildItem -Path $_.FullName -File -ErrorAction SilentlyContinue | Measure-Object).Count
            if ($files -gt 0) {
                $suspiciousPids += $targetPid
                Write-Output "SUSPICIOUS: PID $targetPid ($dirName) - $files artifacts"
            }
        }
    }
}
if ($suspiciousPids.Count -eq 0) {
    Write-Output "NO_SUSPICIOUS_PIDS"
}
"""
    parse_stdout, _, _ = await run_ps_async(ps_parse, timeout=30)

    # Step 3: Detailed pe-sieve on suspicious PIDs
    if "NO_SUSPICIOUS_PIDS" not in parse_stdout:
        report.append("--- Step 2: Detailed PE-sieve on Suspicious Processes ---")
        for line in parse_stdout.strip().split("\n"):
            if line.startswith("SUSPICIOUS:"):
                # Extract PID
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "PID" and i + 1 < len(parts):
                        pid_str = parts[i + 1].strip("()")
                        if pid_str.isdigit():
                            report.append("\n  Scanning PID {}...".format(pid_str))
                            try:
                                sieve_result = await _handle_pe_sieve_scan({
                                    "pid": int(pid_str),
                                    "output_dir": "C:\\temp\\injection_scan_sieve_{}".format(pid_str),
                                })
                                report.append(sieve_result[0].text if sieve_result else "Failed")
                            except Exception as e:
                                report.append("  PE-sieve error: " + str(e))
                        break
    else:
        report.append("--- Step 2: No Suspicious Processes Found ---")
        report.append("Hollows Hunter did not detect any code injection indicators.")

    report.append("")
    report.append("=" * 60)
    report.append("END OF INJECTION SCAN")
    report.append("=" * 60)

    return _text("\n".join(report))


# 49. execute_with_monitoring
async def _handle_execute_with_monitoring(args):
    executable = args["executable"]
    arguments  = args.get("arguments", "")
    duration   = int(args.get("duration", 30))

    report = ["=" * 60, "EXECUTE WITH MONITORING", "=" * 60,
              "Executable : {}".format(executable),
              "Arguments  : {}".format(arguments or "(none)"),
              "Duration   : {}s".format(duration), ""]

    # 1. Start Procmon capture
    report.append("--- [1/3] Starting Procmon capture ---")
    try:
        pm_result = await _handle_procmon_start({})
        report.append(pm_result[0].text if pm_result else "Procmon start returned no output")
    except Exception as e:
        report.append("Procmon start warning: {}".format(e))
    report.append("")

    # 2. Launch the executable
    report.append("--- [2/3] Launching {} ---".format(executable))
    arg_clause = ""
    if arguments:
        arg_clause = " -ArgumentList '{}'".format(arguments.replace("'", "''"))
    launch_ps = (
        "$proc = Start-Process -FilePath '{exe}'{args} -PassThru -ErrorAction Stop\n"
        "Write-Output \"PID: $($proc.Id)\"\n"
        "Start-Sleep -Seconds {dur}\n"
        "$proc.HasExited | Out-Null\n"
        "Write-Output \"Exited: $($proc.HasExited)\""
    ).format(exe=executable.replace("'", "''"), args=arg_clause, dur=duration)
    try:
        out, err, code = await run_ps_async(launch_ps, timeout=duration + 30)
        report.append(out if out else "(no output)")
        if err:
            report.append("STDERR: " + err[:500])
    except Exception as e:
        report.append("Launch error: {}".format(e))
    report.append("")

    # 3. Stop Procmon and get summary
    report.append("--- [3/3] Stopping Procmon and collecting results ---")
    try:
        stop_result = await _handle_procmon_stop({})
        report.append(stop_result[0].text if stop_result else "Procmon stop returned no output")
    except Exception as e:
        report.append("Procmon stop error: {}".format(e))

    report.extend(["", "=" * 60, "END OF EXECUTE WITH MONITORING", "=" * 60])
    return _text("\n".join(report))


# 50. autoruns_analyze
async def _handle_autoruns_analyze(args):
    verify_sigs = args.get("verify_signatures", True)
    category    = args.get("category", "*")

    # Locate autorunsc.exe
    ps_find = r"""
$candidates = @(
    "C:\Tools\Sysinternals\autorunsc.exe",
    "C:\Tools\SysinternalsSuite\autorunsc.exe",
    "C:\ProgramData\chocolatey\bin\autorunsc.exe",
    "C:\ProgramData\chocolatey\lib\autoruns\tools\autorunsc.exe",
    "C:\Windows\System32\autorunsc.exe"
)
$found = $null
foreach ($c in $candidates) { if (Test-Path $c) { $found = $c; break } }
if (-not $found) {
    $cmd = Get-Command autorunsc -ErrorAction SilentlyContinue
    if ($cmd) { $found = $cmd.Source }
}
if ($found) { Write-Output $found } else { Write-Output "NOT_FOUND" }
"""
    path_out, _, _ = await run_ps_async(ps_find, timeout=15)
    autorunsc_path = path_out.strip().split("\n")[0].strip()
    if autorunsc_path == "NOT_FOUND" or not autorunsc_path:
        return _text(
            "ERROR: autorunsc.exe not found on FlareVM.\n"
            "Install Autoruns from SysInternals or chocolatey:\n"
            "  choco install autoruns -y\n"
            "  # or download from https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns"
        )

    # Build flags: -accepteula always; -a <category>; -s for sig check; -c for CSV output
    sig_flag = "-s " if verify_sigs else ""
    esc_path = autorunsc_path.replace("'", "''")
    ps_run = (
        "$out = & '{path}' -accepteula -a {cat} {sig}-c -nobanner 2>&1\n"
        "Write-Output $out"
    ).format(path=esc_path, cat=category, sig=sig_flag)

    out, err, code = await run_ps_async(ps_run, timeout=120)
    if not out.strip():
        return _text("autoruns_analyze returned no output (stderr: {})".format(err[:300]))

    # Parse CSV lines into a readable report
    lines = out.strip().splitlines()
    header = None
    entries = []
    for line in lines:
        if not line.strip():
            continue
        if line.startswith('"Time"') or line.startswith("Time"):
            header = [f.strip('"') for f in line.split(",")]
            continue
        if header:
            cols = line.split(",")
            cols = [c.strip('"') for c in cols]
            row = dict(zip(header, cols, strict=False))  # CSV rows may be ragged
            entries.append(row)

    if not entries:
        return _text("Autoruns output (raw):\n" + out[:3000])

    # Group by Category
    by_cat = {}
    for e in entries:
        cat = e.get("Category", "?")
        by_cat.setdefault(cat, []).append(e)

    report_lines = [
        "=== AUTORUNS ANALYSIS ===",
        "Binary  : {}".format(autorunsc_path),
        "Category: {}  |  Signatures: {}".format(category, verify_sigs),
        "Total entries: {}".format(len(entries)),
        "",
    ]
    for cat in sorted(by_cat):
        report_lines.append("-- {} ({} entries) --".format(cat, len(by_cat[cat])))
        for e in by_cat[cat]:
            name      = e.get("Entry", e.get("Entry Name", "?"))
            publisher = e.get("Publisher", "")
            path      = e.get("Image Path", e.get("Launch String", ""))
            sig       = e.get("Signer", "")
            report_lines.append("  {:<40} {}".format(name[:40], path[:60]))
            if publisher:
                report_lines.append("    Publisher: {}  Signer: {}".format(publisher[:40], sig[:30]))
        report_lines.append("")

    return _text("\n".join(report_lines))


# ========================== MCP PROMPTS ===================================

PROMPT_DEFS = [
    {
        "name": "triage_unknown_sample",
        "description": "Full static triage workflow for an unknown malware sample on FlareVM.",
        "arguments": [
            {"name": "sample_path", "description": "Path to sample on Kali host", "required": True},
        ],
    },
    {
        "name": "behavioral_analysis",
        "description": "Detonation walkthrough with FakeNet, ProcMon, and Regshot.",
        "arguments": [
            {"name": "sample_path", "description": "Path to sample on Kali host", "required": True},
            {"name": "duration", "description": "Detonation duration (seconds)", "required": False},
        ],
    },
    {
        "name": "unpack_workflow",
        "description": "Step-by-step unpacking flow with fallback strategies.",
        "arguments": [
            {"name": "sample_path", "description": "Path to packed sample on FlareVM", "required": True},
        ],
    },
    {
        "name": "injection_hunt",
        "description": "Scan all running processes for code injection indicators.",
        "arguments": [],
    },
    {
        "name": "persistence_audit_report",
        "description": "Generate a Windows persistence audit report (autoruns + scheduled tasks + services).",
        "arguments": [],
    },
]


def _prompt_body(name: str, args: dict) -> str:
    sample = args.get("sample_path", "<sample>")
    duration = args.get("duration", "30")
    if name == "triage_unknown_sample":
        return (
            "Perform a full static triage of the malware sample at `{path}` using the flarevm MCP server.\n\n"
            "Workflow:\n"
            "1. `check_connection` to ensure FlareVM is reachable.\n"
            "2. `upload_file` from `{path}` to `C:\\temp\\sample.bin`.\n"
            "3. `triage_full` (or run individually):\n"
            "   - `die_analyze` for packer/compiler ID.\n"
            "   - `floss_extract_strings` for stack/decoded strings.\n"
            "   - `capa_analyze` for capability fingerprint.\n"
            "   - `yara_scan` against C:\\Tools\\yara\\rules.\n"
            "4. Search output for IOCs: URLs, IPs, mutexes, registry keys, file paths, flag patterns.\n"
            "5. Produce a triage report: hash, packer, capabilities, suspicious strings, recommended next steps.\n"
        ).format(path=sample)
    if name == "behavioral_analysis":
        return (
            "Perform behavioral (dynamic) analysis of `{path}` for {dur} seconds.\n\n"
            "Workflow:\n"
            "1. `check_connection` and confirm FlareVM snapshot is clean.\n"
            "2. `upload_file` to `C:\\temp\\sample.bin`.\n"
            "3. Start collectors:\n"
            "   - `fakenet_start` with the default config.\n"
            "   - `procmon_start` with filter on the sample's PID.\n"
            "   - `regshot_baseline` for registry comparison.\n"
            "4. `execute_with_monitoring` to detonate the sample for {dur}s.\n"
            "5. Stop collectors: `procmon_stop`, `fakenet_stop`, `regshot_compare`.\n"
            "6. `download_file` artifacts (PCAP, PML, regshot diff) to Kali.\n"
            "7. Summarize: network IOCs, persistence, file/registry mutations, child processes.\n"
        ).format(path=sample, dur=duration)
    if name == "unpack_workflow":
        return (
            "Attempt to unpack the packed binary at `{path}` on FlareVM.\n\n"
            "Workflow:\n"
            "1. `die_analyze` to fingerprint the packer (UPX, Themida, ASPack, etc.).\n"
            "2. If UPX: `unpack_detect_and_try` (calls `upx -d` automatically).\n"
            "3. If known packer with public unpacker: run via `execute_powershell`.\n"
            "4. Generic fallback: `pe_sieve_scan` after detonation to dump unpacked PE from memory.\n"
            "5. If still packed: open in `x64dbg_launch_gui`, set breakpoint on `VirtualAlloc`/`WriteProcessMemory`, dump from memory.\n"
            "6. Re-run `die_analyze`, `floss_extract_strings`, `capa_analyze` on the unpacked image.\n"
            "7. Report: original packer, unpacker used, OEP if known, capability diff.\n"
        ).format(path=sample)
    if name == "injection_hunt":
        return (
            "Scan all running processes on FlareVM for code injection.\n\n"
            "Workflow:\n"
            "1. `check_connection`.\n"
            "2. `injection_scan_all` (orchestrates Hollows Hunter sweep + targeted PE-sieve).\n"
            "3. For each suspicious PID, `pe_sieve_scan` with detail and `download_file` dumps.\n"
            "4. For each dump, `die_analyze` and `floss_extract_strings` to identify the injected payload.\n"
            "5. Cross-reference with `list_processes` for parent-child anomalies.\n"
            "6. Report: process tree of injectors, payload identification, suggested IOCs.\n"
        )
    if name == "persistence_audit_report":
        return (
            "Generate a Windows persistence audit report from FlareVM.\n\n"
            "Workflow:\n"
            "1. `check_connection`.\n"
            "2. `persistence_audit` (Autorunsc + scheduled tasks + services + WMI subscriptions).\n"
            "3. Filter results: highlight unsigned binaries, recent modifications, suspicious paths (`%TEMP%`, `%APPDATA%`).\n"
            "4. For each suspicious entry, `download_file` the binary and run `die_analyze` + `yara_scan`.\n"
            "5. Output a markdown report grouped by persistence mechanism (Run keys, scheduled tasks, services, WMI).\n"
        )
    return "Unknown prompt: " + name


@app.list_prompts()
async def list_prompts():
    out = []
    for p in PROMPT_DEFS:
        out.append(Prompt(
            name=p["name"],
            description=p["description"],
            arguments=[
                PromptArgument(
                    name=a["name"],
                    description=a["description"],
                    required=a.get("required", False),
                )
                for a in p["arguments"]
            ],
        ))
    return out


@app.get_prompt()
async def get_prompt(name: str, arguments: dict = None):
    args = arguments or {}
    body = _prompt_body(name, args)
    return GetPromptResult(
        description=next((p["description"] for p in PROMPT_DEFS if p["name"] == name), name),
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text=body),
            )
        ],
    )


# ========================== MCP RESOURCES =================================

CHEATSHEET_TEXT = """# FlareVM MCP Cheatsheet

## Quick triage
- check_connection
- upload_file (kali_path -> C:\\temp\\sample.bin)
- triage_full (DIE + FLOSS + CAPA + YARA)

## Detonation
- fakenet_start / fakenet_stop
- procmon_start / procmon_stop
- regshot_baseline / regshot_compare
- execute_with_monitoring

## Unpacking
- die_analyze (identify packer)
- unpack_detect_and_try (UPX auto)
- pe_sieve_scan (dump from memory)
- x64dbg_launch_gui (manual unpack)

## Injection hunt
- injection_scan_all (Hollows Hunter + PE-sieve)
- list_processes
- pe_sieve_scan --pid <PID>

## Persistence
- persistence_audit (autorunsc + tasks + services)
- list_scheduled_tasks
- list_services

## Network
- tshark_capture (PCAP capture)
- fakenet_start (DNS+HTTP+HTTPS sinkhole)

## Tool flags
- die: -j (JSON output), -d (deep)
- floss: -n 6 (min length), --no-static-strings
- capa: -j (JSON), -vv (verbose)
- yara: -r (recursive), -s (show strings)
- pe-sieve: /pid <N> /imp 3 /shellc 3 /data 3
"""

YARA_INDEX_TEXT = """# YARA Rules Index

Default rules directory: `C:\\Tools\\yara\\rules\\`

## Recommended rule sources
- Florian Roth signature-base: https://github.com/Neo23x0/signature-base
- YaraRules Project: https://github.com/Yara-Rules/rules
- Elastic Protections Artifacts: https://github.com/elastic/protections-artifacts
- ReversingLabs YARA rules: https://github.com/reversinglabs/reversinglabs-yara-rules

## Common malware family rules to keep
- Cobalt Strike beacon detection
- Metasploit shellcode patterns
- Common loader patterns (DonutLoader, Shellter)
- Ransomware family heuristics (LockBit, BlackCat, Conti)
- Stealer families (RedLine, Raccoon, Vidar)

## Use via MCP
- yara_scan(file_path, rules_dir="C:\\Tools\\yara\\rules") -> matches per rule
"""

TOOLS_REFERENCE_TEXT = """# FlareVM Tool Reference

| Tool | Path | Purpose |
|------|------|---------|
| DIE | C:\\Tools\\die\\diec.exe | Packer / compiler identification |
| FLOSS | C:\\Tools\\FLOSS\\floss.exe | Stacked / decoded string extraction |
| CAPA | C:\\Tools\\capa\\capa.exe | Capability fingerprinting |
| YARA | C:\\Tools\\yara\\yara64.exe | Signature scanning |
| ProcMon | C:\\Tools\\sysinternals\\Procmon.exe | Behavioral monitoring |
| Autorunsc | C:\\Tools\\sysinternals\\autorunsc.exe | Persistence enumeration |
| Strings | C:\\Tools\\sysinternals\\strings.exe | ASCII/Unicode strings |
| PE-sieve | C:\\Tools\\pe-sieve\\pe-sieve64.exe | In-memory PE anomaly scan |
| Hollows Hunter | C:\\Tools\\hollows_hunter\\hollows_hunter64.exe | System-wide injection sweep |
| UPX | C:\\Tools\\upx\\upx.exe | UPX unpack/pack |
| dnSpy | C:\\Tools\\dnSpy\\dnSpy.Console.exe | .NET decompilation |
| FakeNet-NG | C:\\Tools\\fakenet\\fakenet.exe | Network sinkhole |
| NirCmd | C:\\Tools\\nircmd.exe | GUI automation |
| x64dbg | C:\\ProgramData\\chocolatey\\bin\\x64dbg.exe | Debugger |
| TShark | C:\\ProgramData\\chocolatey\\bin\\tshark.exe | CLI Wireshark |
"""


RESOURCE_DEFS = [
    ("flarevm://tools/inventory", "FlareVM tools inventory", "text/plain"),
    ("flarevm://config/fakenet-default", "Default FakeNet-NG config", "text/plain"),
    ("flarevm://docs/yara-rules", "YARA rules index", "text/markdown"),
    ("flarevm://docs/cheatsheet", "FlareVM MCP cheatsheet", "text/markdown"),
    ("flarevm://status/connection", "FlareVM connection status", "text/plain"),
]


@app.list_resources()
async def list_resources():
    return [
        Resource(uri=u, name=n, description=n, mimeType=m)
        for (u, n, m) in RESOURCE_DEFS
    ]


@app.read_resource()
async def read_resource(uri):
    uri_s = str(uri)
    if uri_s == "flarevm://docs/cheatsheet":
        return CHEATSHEET_TEXT
    if uri_s == "flarevm://docs/yara-rules":
        rules_text = YARA_INDEX_TEXT
        try:
            ps = r"if (Test-Path 'C:\Tools\yara\rules') { Get-ChildItem -Path 'C:\Tools\yara\rules' -Recurse -Filter *.yar* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName } else { Write-Output 'NO_RULES_DIR' }"
            stdout, _, _ = await run_ps_async(ps, timeout=20)
            if stdout and "NO_RULES_DIR" not in stdout:
                rules_text += "\n## Installed rules\n\n" + stdout
        except Exception:
            pass
        return rules_text
    if uri_s == "flarevm://config/fakenet-default":
        try:
            return generate_fakenet_config()
        except Exception as e:
            return "Error generating config: " + str(e)
    if uri_s == "flarevm://tools/inventory":
        lines = ["# FlareVM Tools Inventory\n"]
        # Build a single PowerShell script that tests all paths at once.
        checks = []
        for key, path in TOOL_PATHS.items():
            esc = path.replace("'", "''")
            checks.append("Write-Output ('{0}|{1}|' + (Test-Path '{2}'))".format(key, path, esc))
        ps = "\n".join(checks)
        try:
            stdout, _, _ = await run_ps_async(ps, timeout=30)
            for line in stdout.splitlines():
                parts = line.strip().split("|")
                if len(parts) == 3:
                    status = "OK" if parts[2].lower() == "true" else "MISSING"
                    lines.append("- **{}** [{}] `{}`".format(parts[0], status, parts[1]))
        except Exception as e:
            lines.append("(connection error: {})".format(e))
            for k, p in TOOL_PATHS.items():
                lines.append("- **{}** `{}`".format(k, p))
        lines.append("\n" + TOOLS_REFERENCE_TEXT)
        return "\n".join(lines)
    if uri_s == "flarevm://status/connection":
        try:
            res = await _handle_check_connection({})
            return res[0].text if res else "No response"
        except Exception as e:
            return "Connection error: " + str(e)
    return "Unknown resource: " + uri_s


# ========================== MAIN ==========================================

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main_sync():
    """Synchronous entry point for console_scripts."""
    _require_host()
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
