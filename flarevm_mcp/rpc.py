"""JSON-RPC proxies to the IDA Pro MCP plugin and mcp-windbg running on the VM."""
import json
import logging

from . import __version__, config
from .transfer import run_ps_script

LOG = logging.getLogger("flarevm-mcp.rpc")


async def ida_rpc_call(tool_name, arguments=None):
    """Invoke an IDA MCP tool over the Model Context Protocol on FlareVM.

    The IDA plugin (ida-pro-mcp) is a full MCP server listening on
    http://127.0.0.1:13337/mcp. Individual tools are invoked with the
    ``tools/call`` JSON-RPC method, NOT as direct methods, and results come
    back wrapped as ``result.content`` (itself a JSON string).

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
    ).format(ps_body, config.IDA_MCP_PORT)
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
    """Invoke an mcp-windbg tool via its HTTP server on FlareVM (port config.WINDBG_MCP_PORT).

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
            "clientInfo": {"name": "flarevm-mcp", "version": __version__},
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
    ).format(port=config.WINDBG_MCP_PORT, init=init_payload, notif=notif_body, tool=tool_payload)

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
