"""Dynamic tools (migrated from the 1.1.0 monolith)."""
import asyncio

from ..registry import tool
from ..winrm_client import run_ps_async
from ..transfer import run_ps_script
from ..guest import resolve_tool_path
from ..guest import launch_gui_app
from ..guest import _poll_file_nonempty
from ._common import _text
from ..psquote import ps_int, ps_path, ps_quote, win_arg


@tool(
    'procmon_start',
    description='Start Process Monitor (captures all process activity; summarise per process with procmon_stop).',
    schema={'type': 'object',
     'properties': {'output_path': {'type': 'string',
                                    'description': 'PML output path (default '
                                                   'C:\\temp\\procmon.pml)',
                                    'default': 'C:\\temp\\procmon.pml'}},
     'required': []},
    timeout=60,
    category='dynamic',
)
async def _handle_procmon_start(args):
    output_path = args.get("output_path", "C:\\temp\\procmon.pml")
    out_q = ps_path(output_path, "output_path")
    procmon_path = await resolve_tool_path("procmon", "Procmon")

    await run_ps_async('New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null', timeout=10)
    # Kill any existing procmon and clear the stale backing file so our poll
    # detects the fresh one.
    await run_ps_async('Stop-Process -Name Procmon* -Force -ErrorAction SilentlyContinue', timeout=15)
    await asyncio.sleep(1)
    await run_ps_async('Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue'.format(out_q), timeout=10)

    # ProcMon needs an INTERACTIVE desktop to load its driver and (crucially) to
    # convert the log later, so launch it through a scheduled task in the
    # console session rather than Start-Process in the non-interactive WinRM
    # (session 0) context. CLI filtering requires a *binary* .pmc — the old XML
    # /LoadConfig silently disabled capture — so we capture everything and let
    # procmon_stop summarise per process instead.
    pm_args = '/BackingFile {} /Quiet /Minimized /AcceptEula'.format(win_arg(output_path, "output_path"))
    await launch_gui_app(procmon_path, arguments=pm_args, task_name="MCP_Procmon")

    size = await _poll_file_nonempty(output_path, attempts=10, interval=2)
    if size > 0:
        return _text("=== ProcMon Started (interactive session) ===\n"
                     "Backing file: {} ({} bytes preallocated)\n"
                     "Capturing all process activity (unfiltered; CLI filters need a binary .pmc). "
                     "Use procmon_stop to terminate and export.".format(output_path, size))
    return _text("WARNING: ProcMon launched but backing file {} did not appear; "
                 "capture may not have started.".format(output_path))


@tool(
    'procmon_stop',
    description='Stop ProcMon and export results to CSV with summary.',
    schema={'type': 'object',
     'properties': {'pml_path': {'type': 'string',
                                 'description': 'PML file path (default C:\\temp\\procmon.pml)',
                                 'default': 'C:\\temp\\procmon.pml'},
                    'csv_path': {'type': 'string',
                                 'description': 'CSV output path (default C:\\temp\\procmon.csv)',
                                 'default': 'C:\\temp\\procmon.csv'}},
     'required': []},
    timeout=180,
    category='dynamic',
)
async def _handle_procmon_stop(args):
    pml_path = args.get("pml_path", "C:\\temp\\procmon.pml")
    csv_path = args.get("csv_path", "C:\\temp\\procmon.csv")
    pml_q, csv_q = ps_path(pml_path, "pml_path"), ps_path(csv_path, "csv_path")
    procmon_path = await resolve_tool_path("procmon", "Procmon")

    # Clear any stale CSV so the poll below sees the fresh export.
    await run_ps_async('Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue'.format(csv_q), timeout=10)

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
    conv_args = '/OpenLog {} /SaveAs {} /AcceptEula'.format(win_arg(pml_path, "pml_path"), win_arg(csv_path, "csv_path"))
    await launch_gui_app(procmon_path, arguments=conv_args, task_name="MCP_ProcmonConv")
    csv_size = await _poll_file_nonempty(csv_path, attempts=45, interval=2)
    # Ensure the conversion instance has exited.
    await run_ps_async('Stop-Process -Name Procmon* -Force -ErrorAction SilentlyContinue', timeout=10)

    if csv_size == 0:
        exists, _, _ = await run_ps_async('Test-Path -LiteralPath {}'.format(pml_q), timeout=10)
        return _text("WARNING: CSV export not produced at {} (PML exists: {}). "
                     "The interactive conversion may still be running.".format(
                         csv_path, exists.strip()))

    # Parse the CSV summary — plain file reads work fine over WinRM.
    ps = """
$csv = {csv}
$pml = {pml}
$lines = Get-Content -LiteralPath $csv -TotalCount 10001
$total = $lines.Count - 1
$fileOps = ($lines | Select-String -Pattern "CreateFile|WriteFile|ReadFile|DeleteFile|SetDispositionInformationFile" | Measure-Object).Count
$regOps = ($lines | Select-String -Pattern "RegOpenKey|RegSetValue|RegQueryValue|RegCreateKey|RegDeleteKey" | Measure-Object).Count
$netOps = ($lines | Select-String -Pattern "TCP|UDP|Send|Recv" | Measure-Object).Count
$procOps = ($lines | Select-String -Pattern "Process Create|Process Start|Thread Create|Load Image" | Measure-Object).Count

Write-Output "=== ProcMon Summary ==="
Write-Output "PML: $pml"
Write-Output "CSV: $csv ({csvsize} bytes)"
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
""".format(pml=pml_q, csv=csv_q, csvsize=int(csv_size))

    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'procmon_export_csv',
    description='Export a PML file to CSV format.',
    schema={'type': 'object',
     'properties': {'pml_path': {'type': 'string', 'description': 'PML file path'},
                    'csv_path': {'type': 'string', 'description': 'CSV output path'}},
     'required': ['pml_path', 'csv_path']},
    timeout=120,
    category='dynamic',
)
async def _handle_procmon_export_csv(args):
    pml_path = args["pml_path"]
    csv_path = args["csv_path"]
    procmon_path = await resolve_tool_path("procmon", "Procmon")
    ps = """
$csv = {csv}
& {procmon} /OpenLog {pml} /SaveAs {csv} /AcceptEula 2>&1
Start-Sleep -Seconds 3
if (Test-Path -LiteralPath $csv) {{
    $size = (Get-Item -LiteralPath $csv).Length
    Write-Output "CSV exported: $csv ($size bytes)"
}} else {{
    Write-Output "WARNING: CSV not created at $csv"
}}
""".format(procmon=ps_quote(procmon_path), pml=ps_path(pml_path, "pml_path"), csv=ps_path(csv_path, "csv_path"))
    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    return _text(stdout)


@tool(
    'process_hacker_info',
    description='Get detailed info about a process: modules, threads, handles, connections.',
    schema={'type': 'object',
     'properties': {'pid': {'type': 'integer', 'description': 'Process ID'}},
     'required': ['pid']},
    timeout=60,
    category='dynamic',
)
async def _handle_process_hacker_info(args):
    pid = ps_int(args["pid"], 1, 2**31 - 1, "pid")
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


@tool(
    'regshot_snapshot',
    description='Registry before/after snapshot and comparison.',
    schema={'type': 'object',
     'properties': {'action': {'type': 'string',
                               'description': 'first, second, or compare',
                               'enum': ['first', 'second', 'compare']}},
     'required': ['action']},
    timeout=300,
    category='dynamic',
)
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
Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Out-File "C:\\temp\\startup_before.txt" -Encoding UTF8

$hklmSize = (Get-Item "C:\\temp\\regshot_hklm_before.reg").Length
$hkcuSize = (Get-Item "C:\\temp\\regshot_hkcu_before.reg").Length
Write-Output "HKLM export: $([math]::Round($hklmSize/1MB, 2)) MB"
Write-Output "HKCU export: $([math]::Round($hkcuSize/1MB, 2)) MB"
Write-Output "Baseline snapshot complete."
"""
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
Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Out-File "C:\\temp\\startup_after.txt" -Encoding UTF8

$hklmSize = (Get-Item "C:\\temp\\regshot_hklm_after.reg").Length
$hkcuSize = (Get-Item "C:\\temp\\regshot_hkcu_after.reg").Length
Write-Output "HKLM export: $([math]::Round($hklmSize/1MB, 2)) MB"
Write-Output "HKCU export: $([math]::Round($hkcuSize/1MB, 2)) MB"
Write-Output "Post-execution snapshot complete."
"""
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
