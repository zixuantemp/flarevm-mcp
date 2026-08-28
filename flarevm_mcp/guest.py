"""Guest-side helpers: locate tools on the VM, launch GUI apps in the interactive session, poll files."""
import asyncio

from . import config
from .psquote import ps_quote
from .winrm_client import run_ps_async
from .integrity import verify_binary
from .psquote import no_ctrl, ps_ident, ps_path


async def resolve_tool_path(tool_key, fallback_name=None):
    """Find a tool on FlareVM (known path first, then where.exe) and, when a manifest
    exists and strict mode is on, verify its SHA256 before returning it."""
    known = config.TOOL_PATHS.get(tool_key)
    name = ps_quote(ps_ident(fallback_name or tool_key, "tool name"))
    if known:
        ps = ("if (Test-Path -LiteralPath {k}) {{ Write-Output {k} }} else {{ $p = (where.exe {n} 2>$null | "
              "Select-Object -First 1); if ($p) {{ Write-Output $p }} else {{ Write-Output 'NOT_FOUND' }} }}"
              ).format(k=ps_quote(known), n=name)
    else:
        ps = ("$p = (where.exe {n} 2>$null | Select-Object -First 1); if ($p) {{ Write-Output $p }} "
              "else {{ Write-Output 'NOT_FOUND' }}").format(n=name)
    stdout, _, _ = await run_ps_async(ps, timeout=15)
    path = stdout.strip().split("\n")[0].strip() if stdout.strip() else "NOT_FOUND"
    if path == "NOT_FOUND":
        raise FileNotFoundError("Tool '{}' not found on FlareVM".format(tool_key))
    await verify_binary(tool_key, path)
    return path


async def launch_gui_app(exe_path, arguments="", task_name="MCP_App",
                         wait_port=None, wait_timeout=60):
    """Launch a GUI application in the interactive user session via Scheduled Task."""
    ps = """
$exe = {exe}
$task = {task}
$action = if ({args}) {{ New-ScheduledTaskAction -Execute $exe -Argument {args} }} else {{ New-ScheduledTaskAction -Execute $exe }}
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
$principal = New-ScheduledTaskPrincipal -UserId ("$env:COMPUTERNAME\\" + {user}) -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 120)
Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task
Write-Output "Scheduled task '$task' started"
""".format(exe=ps_path(exe_path, "executable"), args=ps_quote(no_ctrl(arguments, "arguments")),
           user=ps_quote(config.FLAREVM_USER), task=ps_quote(ps_ident(task_name, "task name")))
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


async def _poll_file_nonempty(path, attempts=15, interval=2):
    """Poll until a file on FlareVM exists and is non-empty. Returns its size or 0."""
    for _ in range(attempts):
        await asyncio.sleep(interval)
        out, _, _ = await run_ps_async(
            'if (Test-Path -LiteralPath {0}) {{ (Get-Item -LiteralPath {0}).Length }} else {{ 0 }}'.format(ps_path(path)),
            timeout=10)
        try:
            size = int(out.strip().split("\n")[0])
        except (ValueError, IndexError):
            size = 0
        if size > 0:
            return size
    return 0


async def _file_exists(path):
    """Check if a file exists on FlareVM."""
    stdout, _, code = await run_ps_async('Test-Path -LiteralPath {}'.format(ps_path(path)), timeout=10)
    return stdout.strip().lower() == "true"
