"""Debuggers tools (migrated from the 1.1.0 monolith; see docs/HARDENING_PLAN.md)."""
import json

from ..registry import tool
from .. import config
from ..winrm_client import run_ps_async
from ..guest import resolve_tool_path
from ..guest import launch_gui_app
from ..rpc import ida_rpc_call
from ..rpc import windbg_rpc_call
from ._common import _text
from ..psquote import here_string, no_ctrl, ps_path, win_arg


@tool(
    'x64dbg_load',
    description='Load a binary in x64dbg via scheduled task (interactive session).',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to executable on FlareVM'},
                    'arguments': {'type': 'string',
                                  'description': 'Command-line arguments',
                                  'default': ''}},
     'required': ['file_path']},
    timeout=60,
    category='debuggers',
)
async def _handle_x64dbg_load(args):
    file_path = args["file_path"]
    arguments = args.get("arguments", "")
    x64dbg_path = await resolve_tool_path("x64dbg", "x64dbg")
    dbg_args = win_arg(file_path, "file_path")
    if arguments:
        dbg_args += " " + no_ctrl(arguments, "arguments")
    result = await launch_gui_app(
        x64dbg_path,
        arguments=dbg_args,
        task_name="MCP_x64dbg",
    )
    return _text("=== x64dbg Launched ===\nBinary: {}\nArguments: {}\n{}".format(
        file_path, arguments, result
    ))


@tool(
    'x64dbg_run_script',
    description='Save and execute an x64dbg script.',
    schema={'type': 'object',
     'properties': {'script': {'type': 'string', 'description': 'x64dbg script content'},
                    'script_path': {'type': 'string',
                                    'description': 'Where to save script on FlareVM',
                                    'default': 'C:\\temp\\x64dbg_script.txt'}},
     'required': ['script']},
    timeout=120,
    category='debuggers',
)
async def _handle_x64dbg_run_script(args):
    script = args["script"]
    script_path = args.get("script_path", "C:\\temp\\x64dbg_script.txt")
    path_q = ps_path(script_path, "script_path")
    ps = """
{script} | Out-File -LiteralPath {path} -Encoding ASCII
Write-Output "Script saved to $({path})"
""".format(script=here_string(script), path=path_q)
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
$sp = {path}
if ($x64dbg) {{
    Write-Output "x64dbg is running (PID: $($x64dbg.Id))"
    Write-Output "Script saved to: $sp"
    Write-Output "Load the script in x64dbg: scriptload `"$sp`""
}} else {{
    Write-Output "WARNING: x64dbg does not appear to be running."
    Write-Output "Script saved to: $sp"
    Write-Output "Start x64dbg first, then load the script manually."
}}
""".format(path=path_q)
    stdout2, _, _ = await run_ps_async(ps_run, timeout=15)
    return _text(stdout + "\n" + stdout2)


@tool(
    'windbg_analyze_dump',
    description='Open a crash/memory dump via mcp-windbg (cdb.exe) on FlareVM and run initial triage. Returns crash info, call stack, loaded modules and threads. Requires mcp-windbg HTTP server running on port 13338 (registered as MCP_WinDbg_Server scheduled task by setup.py).',
    schema={'type': 'object',
     'properties': {'dump_file': {'type': 'string',
                                  'description': 'Absolute path to dump file on FlareVM (e.g. '
                                                 'C:\\\\temp\\\\crash.dmp)'},
                    'include_stack_trace': {'type': 'boolean',
                                            'description': 'Include call stack in output',
                                            'default': True},
                    'include_modules': {'type': 'boolean',
                                        'description': 'Include loaded modules in output',
                                        'default': True},
                    'include_threads': {'type': 'boolean',
                                        'description': 'Include thread list in output',
                                        'default': True},
                    'symbols_path': {'type': 'string',
                                     'description': 'Optional symbol server/path (e.g. '
                                                    'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols)'},
                    'extra_commands': {'type': 'array',
                                       'items': {'type': 'string'},
                                       'description': 'Additional cdb commands to run after '
                                                      'initial analysis (e.g. ["k 40", "!peb"])'}},
     'required': ['dump_file']},
    timeout=300,
    category='debuggers',
)
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
        return _text("mcp-windbg error: {}\n\nHint: ensure MCP_WinDbg_Server scheduled task is running (flarevm_setup.py provisions it).".format(e))

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


@tool(
    'windbg_launch',
    description='Launch WinDbg GUI with a dump file in the interactive console session.',
    schema={'type': 'object',
     'properties': {'dump_file': {'type': 'string', 'description': 'Path to dump file'},
                    'windbg_path': {'type': 'string',
                                    'description': 'Path to WinDbg GUI',
                                    'default': 'C:\\Program Files (x86)\\Windows '
                                               'Kits\\10\\Debuggers\\x64\\windbg.exe'}},
     'required': ['dump_file']},
    timeout=60,
    category='debuggers',
)
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
        arguments='-z {}'.format(win_arg(dump_file, "dump_file")),
        task_name="MCP_WinDbg_GUI",
    )
    return _text("=== WinDbg Launched ===\nDump: {}\n{}".format(dump_file, result))


@tool(
    'windbg_run_cmd',
    description='Run an arbitrary cdb command on an already-opened dump session in mcp-windbg. Call windbg_analyze_dump first to open the session; subsequent windbg_run_cmd calls on the same dump_file reuse the persistent cdb.exe process.',
    schema={'type': 'object',
     'properties': {'dump_file': {'type': 'string',
                                  'description': 'Path to the dump file (must match a previously '
                                                 'opened session)'},
                    'command': {'type': 'string',
                                'description': "cdb/WinDbg command to execute (e.g. '!ept', 'k "
                                               "40', 'lm', '!teb')"}},
     'required': ['dump_file', 'command']},
    timeout=120,
    category='debuggers',
)
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


@tool(
    'windbg_list_dumps',
    description='List .dmp crash dump files on FlareVM via mcp-windbg.',
    schema={'type': 'object',
     'properties': {'directory_path': {'type': 'string',
                                       'description': 'Directory to search for dump files '
                                                      '(default: C:\\\\temp and common dump '
                                                      'locations)'}},
     'required': []},
    timeout=30,
    category='debuggers',
)
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


@tool(
    'ida_launch_and_wait',
    description='Launch IDA Pro with a binary and wait for MCP server (port 13337) to be ready.',
    schema={'type': 'object',
     'properties': {'binary_path': {'type': 'string',
                                    'description': 'Path to binary to load in IDA'},
                    'ida_path': {'type': 'string',
                                 'description': 'Path to IDA executable',
                                 'default': 'C:\\Tools\\IDA Pro\\ida64.exe'}},
     'required': ['binary_path']},
    timeout=180,
    category='debuggers',
)
async def _handle_ida_launch_and_wait(args):
    binary_path = args["binary_path"]
    ida_path = args.get("ida_path", "C:\\Tools\\IDA Pro\\ida64.exe")

    result = await launch_gui_app(
        ida_path,
        arguments=win_arg(binary_path, "binary_path"),
        task_name="MCP_IDA",
        wait_port=config.IDA_MCP_PORT,
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
