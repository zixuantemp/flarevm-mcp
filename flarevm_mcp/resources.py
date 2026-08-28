"""MCP resources: tool inventory, FakeNet config, docs, connection/integrity status."""
import json

from mcp.types import Resource

from . import config
from ._resource_data import CHEATSHEET_TEXT, TOOLS_REFERENCE_TEXT, YARA_INDEX_TEXT
from .fakenet import generate_fakenet_config
from .integrity import load_manifest, vm_state
from .psquote import ps_quote, sanitize_output
from .winrm_client import breaker, run_ps_async

RESOURCE_DEFS = [
    ("flarevm://tools/inventory", "FlareVM tools inventory", "text/plain"),
    ("flarevm://config/fakenet-default", "Default FakeNet-NG config", "text/plain"),
    ("flarevm://docs/yara-rules", "YARA rules index", "text/markdown"),
    ("flarevm://docs/cheatsheet", "FlareVM MCP cheatsheet", "text/markdown"),
    ("flarevm://status/connection", "FlareVM connection, breaker and VM-state status", "application/json"),
    ("flarevm://status/integrity", "Tool manifest status", "application/json"),
]


def list_resources():
    return [Resource(uri=u, name=n, description=n, mimeType=m) for (u, n, m) in RESOURCE_DEFS]


async def read_resource(uri):
    uri_s = str(uri)
    if uri_s == "flarevm://docs/cheatsheet":
        return CHEATSHEET_TEXT
    if uri_s == "flarevm://docs/yara-rules":
        text = YARA_INDEX_TEXT
        try:
            ps = ("if (Test-Path 'C:\\Tools\\yara\\rules') { Get-ChildItem -Path 'C:\\Tools\\yara\\rules' -Recurse "
                  "-Filter *.yar* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName } "
                  "else { Write-Output 'NO_RULES_DIR' }")
            out, _, _ = await run_ps_async(ps, timeout=20)
            if out and "NO_RULES_DIR" not in out:
                text += "\n## Installed rules (untrusted VM listing)\n\n" + sanitize_output(out)
        except Exception:
            pass
        return text
    if uri_s == "flarevm://config/fakenet-default":
        try:
            return generate_fakenet_config()
        except Exception as exc:
            return "Error generating config: {}".format(exc)
    if uri_s == "flarevm://tools/inventory":
        lines = ["# FlareVM Tools Inventory\n"]
        checks = ["Write-Output ('{0}|{1}|' + (Test-Path -LiteralPath {2}))".format(k, p, ps_quote(p))
                  for k, p in config.TOOL_PATHS.items()]
        try:
            out, _, _ = await run_ps_async("\n".join(checks), timeout=30)
            for line in out.splitlines():
                parts = line.strip().split("|")
                if len(parts) == 3:
                    lines.append("- **{}** [{}] `{}`".format(parts[0], "OK" if parts[2].lower() == "true" else "MISSING", parts[1]))
        except Exception as exc:
            lines.append("(connection error: {})".format(exc))
            lines += ["- **{}** `{}`".format(k, p) for k, p in config.TOOL_PATHS.items()]
        return "\n".join(lines) + "\n" + TOOLS_REFERENCE_TEXT
    if uri_s == "flarevm://status/connection":
        status = {"host": config.FLAREVM_HOST, "endpoint": config.winrm_endpoint(),
                  "breaker": breaker.snapshot(), "vm_state": vm_state.snapshot()}
        try:
            out, err, code = await run_ps_async("$env:COMPUTERNAME", timeout=20)
            status["reachable"] = code == 0
            status["hostname"] = sanitize_output(out.strip()) if code == 0 else None
            if code != 0:
                status["error"] = err
        except Exception as exc:
            status["reachable"] = False
            status["error"] = str(exc)
        return json.dumps(status, indent=2)
    if uri_s == "flarevm://status/integrity":
        m = load_manifest()
        return json.dumps({"manifest": config.TOOL_MANIFEST, "present": bool(m),
                           "generated": (m or {}).get("generated"), "strict": config.strict_integrity(),
                           "tools_listed": sorted((m or {}).get("tools", {}).keys())}, indent=2)
    return "Unknown resource: " + uri_s
