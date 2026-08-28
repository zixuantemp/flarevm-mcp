"""Frida tools (migrated from the 1.1.0 monolith)."""

from ..registry import tool
from ..winrm_client import run_ps_async
from ._common import _text
from ..psquote import here_string, ps_ident, ps_int, ps_path, ps_quote


@tool(
    'frida_list_processes',
    description='List processes visible to Frida on FlareVM.',
    schema={'type': 'object', 'properties': {}, 'required': []},
    timeout=30,
    category='frida',
)
async def _handle_frida_list_processes(args):
    ps = 'frida-ps 2>&1'
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Frida error: {} {}".format(stderr, stdout))
    return _text("=== Frida Process List ===\n" + stdout)


@tool(
    'frida_spawn_and_attach',
    description='Spawn a process and attach Frida with a script.',
    schema={'type': 'object',
     'properties': {'executable': {'type': 'string',
                                   'description': 'Path to executable on FlareVM'},
                    'script': {'type': 'string', 'description': 'Frida JavaScript script content'},
                    'timeout': {'type': 'integer',
                                'description': 'Script timeout in seconds (default 30)',
                                'default': 30}},
     'required': ['executable', 'script']},
    timeout=120,
    category='frida',
)
async def _handle_frida_spawn_and_attach(args):
    executable = args["executable"]
    script = args["script"]
    timeout = ps_int(args.get("timeout", 30), 1, 3600, "timeout")
    ps = """
$scriptContent = {script}
$scriptPath = "C:\\temp\\frida_spawn_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Output "Script saved to $scriptPath"
$output = & frida -f {exe} -l $scriptPath -q --timeout {timeout} 2>&1
Write-Output $output
""".format(script=here_string(script), exe=ps_path(executable, "executable"), timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Spawn & Attach ===\nExecutable: {}\n\n{}".format(executable, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


@tool(
    'frida_attach_pid',
    description='Attach Frida to a running process by PID.',
    schema={'type': 'object',
     'properties': {'pid': {'type': 'integer', 'description': 'Process ID to attach to'},
                    'script': {'type': 'string', 'description': 'Frida JavaScript script content'},
                    'timeout': {'type': 'integer',
                                'description': 'Script timeout in seconds (default 30)',
                                'default': 30}},
     'required': ['pid', 'script']},
    timeout=120,
    category='frida',
)
async def _handle_frida_attach_pid(args):
    pid = ps_int(args["pid"], 1, 2**31 - 1, "pid")
    script = args["script"]
    timeout = ps_int(args.get("timeout", 30), 1, 3600, "timeout")
    ps = """
$scriptContent = {script}
$scriptPath = "C:\\temp\\frida_attach_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Output "Script saved to $scriptPath"
$output = & frida -p {pid} -l $scriptPath -q --timeout {timeout} 2>&1
Write-Output $output
""".format(script=here_string(script), pid=pid, timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Attach (PID: {}) ===\n\n{}".format(pid, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


@tool(
    'frida_run_script',
    description='Execute an inline Frida script against a process (by name or PID).',
    schema={'type': 'object',
     'properties': {'target': {'type': 'string', 'description': 'Process name or PID'},
                    'script': {'type': 'string', 'description': 'Frida JavaScript script content'},
                    'timeout': {'type': 'integer',
                                'description': 'Script timeout in seconds (default 30)',
                                'default': 30}},
     'required': ['target', 'script']},
    timeout=120,
    category='frida',
)
async def _handle_frida_run_script(args):
    target = args["target"]
    script = args["script"]
    timeout = ps_int(args.get("timeout", 30), 1, 3600, "timeout")
    # Determine if target is PID (numeric) or process name
    try:
        pid = int(target)
        target_flag = "-p {}".format(pid)
    except ValueError:
        target_flag = '-n {}'.format(ps_quote(ps_ident(target, "target")))

    ps = """
$scriptContent = {script}
$scriptPath = "C:\\temp\\frida_run_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
$output = & frida {target_flag} -l $scriptPath -q --timeout {timeout} 2>&1
Write-Output $output
""".format(script=here_string(script), target_flag=target_flag, timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Script Execution ===\nTarget: {}\n\n{}".format(target, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)
