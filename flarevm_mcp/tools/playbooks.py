"""Playbooks tools (migrated from the 1.1.0 monolith; see docs/HARDENING_PLAN.md)."""
import asyncio

from ..registry import tool
from ..winrm_client import run_ps_async
from ..transfer import run_ps_script
from ._common import _text
from .dynamic import _handle_procmon_start, _handle_procmon_stop, _handle_regshot_snapshot
from .network import _handle_fakenet_start, _handle_fakenet_stop
from .static import _handle_capa_analyze, _handle_die_analyze, _handle_entropy_analysis, _handle_floss_extract_strings, _handle_yara_scan
from .system import _handle_get_file_hash
from ..psquote import ps_int, ps_path, ps_quote
from ..integrity import require_clean_for, vm_state
from ..registry import progress


@tool(
    'triage_full',
    description='Complete static analysis pipeline: hashes, DIE, entropy, CAPA, FLOSS, YARA.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to file on FlareVM'}},
     'required': ['file_path']},
    timeout=900,
    category='playbooks',
)
async def _handle_triage_full(args):
    file_path = args["file_path"]
    ps_path(file_path, "file_path")
    report = ["=" * 60, "FULL STATIC TRIAGE REPORT", "=" * 60, "File: {}".format(file_path), ""]

    # 1. Hashes
    report.append("--- 1. File Hashes ---")
    await progress("1. File Hashes", 1, 6)
    try:
        hash_result = await _handle_get_file_hash({"file_path": file_path})
        report.append(hash_result if hash_result else "Hash calculation failed")
    except Exception as e:
        report.append("Hash error: " + str(e))
    report.append("")

    # 2. DIE
    report.append("--- 2. Packer/Compiler Detection (DIE) ---")
    await progress("2. Packer/Compiler Detection (DIE)", 2, 6)
    try:
        die_result = await _handle_die_analyze({"file_path": file_path})
        report.append(die_result if die_result else "DIE failed")
    except Exception as e:
        report.append("DIE error: " + str(e))
    report.append("")

    # 3. Entropy
    report.append("--- 3. Section Entropy ---")
    await progress("3. Section Entropy", 3, 6)
    try:
        ent_result = await _handle_entropy_analysis({"file_path": file_path})
        report.append(ent_result if ent_result else "Entropy analysis failed")
    except Exception as e:
        report.append("Entropy error: " + str(e))
    report.append("")

    # 4. CAPA
    report.append("--- 4. Capability Detection (CAPA) ---")
    await progress("4. Capability Detection (CAPA)", 4, 6)
    try:
        capa_result = await _handle_capa_analyze({"file_path": file_path})
        report.append(capa_result if capa_result else "CAPA failed")
    except Exception as e:
        report.append("CAPA error: " + str(e))
    report.append("")

    # 5. FLOSS
    report.append("--- 5. String Recovery (FLOSS) ---")
    await progress("5. String Recovery (FLOSS)", 5, 6)
    try:
        floss_result = await _handle_floss_extract_strings({
            "file_path": file_path, "min_length": 6
        })
        report.append(floss_result if floss_result else "FLOSS failed")
    except Exception as e:
        report.append("FLOSS error: " + str(e))
    report.append("")

    # 6. YARA
    report.append("--- 6. YARA Rule Matching ---")
    await progress("6. YARA Rule Matching", 6, 6)
    try:
        yara_result = await _handle_yara_scan({"file_path": file_path})
        report.append(yara_result if yara_result else "YARA failed")
    except Exception as e:
        report.append("YARA error: " + str(e))
    report.append("")

    report.append("=" * 60)
    report.append("END OF TRIAGE REPORT")
    report.append("=" * 60)

    return _text("\n".join(report))


@tool(
    'behavioral_full',
    description='Complete behavioral analysis: regshot, procmon, FakeNet, network monitoring, execute, collect.',
    schema={'type': 'object',
     'properties': {'ack_dirty_vm': {'type': 'boolean', 'default': False, 'description': 'Proceed even if the VM is dirty since the last snapshot revert'},
                    'executable': {'type': 'string',
                                   'description': 'Path to executable on FlareVM'},
                    'arguments': {'type': 'string',
                                  'description': 'Command-line arguments',
                                  'default': ''},
                    'duration': {'type': 'integer',
                                 'description': 'Execution duration in seconds (default 30)',
                                 'default': 30}},
     'required': ['executable']},
    timeout=1800,
    category='playbooks',
)
async def _handle_behavioral_full(args):
    executable = args["executable"]
    arguments = args.get("arguments", "")
    duration = ps_int(args.get("duration", 30), 1, 1500, "duration")
    exe_q = ps_path(executable, "executable")
    require_clean_for("behavioral_full", args)
    vm_state.mark_dirty("behavioral_full executed {}".format(executable))

    report = ["=" * 60, "FULL BEHAVIORAL ANALYSIS REPORT", "=" * 60,
              "Executable: {}".format(executable),
              "Arguments: {}".format(arguments),
              "Duration: {}s".format(duration), ""]

    # 1. Registry baseline
    report.append("--- Step 1: Registry Baseline ---")
    await progress("Step 1: Registry Baseline", 1, 9)
    try:
        reg1 = await _handle_regshot_snapshot({"action": "first"})
        report.append(reg1 if reg1 else "Failed")
    except Exception as e:
        report.append("Regshot baseline error: " + str(e))
    report.append("")

    # 2. Start ProcMon
    report.append("--- Step 2: Start ProcMon ---")
    await progress("Step 2: Start ProcMon", 2, 9)
    try:
        pm_start = await _handle_procmon_start({
            "output_path": "C:\\temp\\behavioral_procmon.pml",
        })
        report.append(pm_start if pm_start else "Failed")
    except Exception as e:
        report.append("ProcMon start error: " + str(e))
    report.append("")

    # 3. Start FakeNet
    report.append("--- Step 3: Start FakeNet ---")
    await progress("Step 3: Start FakeNet", 3, 9)
    try:
        fn_start = await _handle_fakenet_start({})
        report.append(fn_start if fn_start else "Failed")
    except Exception as e:
        report.append("FakeNet start error: " + str(e))
    report.append("")

    # 4. Start network monitoring (in parallel with execution)
    report.append("--- Step 4: Execute Malware ---")
    await progress("Step 4: Execute Malware", 4, 9)
    arg_clause = " -ArgumentList {}".format(ps_quote(arguments)) if arguments else ""
    ps_exec = """
$proc = Start-Process -FilePath {exe}{args} -PassThru -WindowStyle Hidden
Write-Output "Started: $($proc.ProcessName) (PID: $($proc.Id))"
$proc.Id
""".format(exe=exe_q, args=arg_clause)
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
    await progress("Step 6: FakeNet Results", 5, 9)
    try:
        fn_stop = await _handle_fakenet_stop({})
        report.append(fn_stop if fn_stop else "Failed")
    except Exception as e:
        report.append("FakeNet stop error: " + str(e))
    report.append("")

    # 8. Stop ProcMon and export
    report.append("--- Step 7: ProcMon Results ---")
    await progress("Step 7: ProcMon Results", 6, 9)
    try:
        pm_stop = await _handle_procmon_stop({
            "pml_path": "C:\\temp\\behavioral_procmon.pml",
            "csv_path": "C:\\temp\\behavioral_procmon.csv",
        })
        report.append(pm_stop if pm_stop else "Failed")
    except Exception as e:
        report.append("ProcMon stop error: " + str(e))
    report.append("")

    # 9. Registry after + compare
    report.append("--- Step 8: Registry Changes ---")
    await progress("Step 8: Registry Changes", 7, 9)
    try:
        reg2 = await _handle_regshot_snapshot({"action": "second"})
        report.append(reg2 if reg2 else "Failed")
        report.append("")
        reg_cmp = await _handle_regshot_snapshot({"action": "compare"})
        report.append(reg_cmp if reg_cmp else "Failed")
    except Exception as e:
        report.append("Regshot compare error: " + str(e))
    report.append("")

    # 10. Network state
    report.append("--- Step 9: Post-Execution Network State ---")
    await progress("Step 9: Post-Execution Network State", 8, 9)
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


@tool(
    'persistence_audit',
    description='Full persistence mechanism scan: autoruns, registry, tasks, services, WMI, startup.',
    schema={'type': 'object', 'properties': {}, 'required': []},
    timeout=120,
    category='playbooks',
)
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


@tool(
    'execute_with_monitoring',
    description='Execute a binary under full monitoring: starts Procmon capture, launches the executable, waits for the specified duration, then stops Procmon and returns a combined activity summary (file/reg/net events, new processes).',
    schema={'type': 'object',
     'properties': {'ack_dirty_vm': {'type': 'boolean', 'default': False, 'description': 'Proceed even if the VM is dirty since the last snapshot revert'},
                    'executable': {'type': 'string',
                                   'description': 'Full path to the executable on FlareVM, e.g. '
                                                  'C:\\temp\\sample.exe'},
                    'arguments': {'type': 'string',
                                  'default': '',
                                  'description': 'Command-line arguments to pass to the '
                                                 'executable'},
                    'duration': {'type': 'integer',
                                 'default': 30,
                                 'description': 'How many seconds to let the process run before '
                                                'stopping capture'}},
     'required': ['executable']},
    timeout=300,
    category='playbooks',
)
async def _handle_execute_with_monitoring(args):
    executable = args["executable"]
    arguments  = args.get("arguments", "")
    duration   = ps_int(args.get("duration", 30), 1, 240, "duration")
    exe_q = ps_path(executable, "executable")
    require_clean_for("execute_with_monitoring", args)
    vm_state.mark_dirty("execute_with_monitoring executed {}".format(executable))

    report = ["=" * 60, "EXECUTE WITH MONITORING", "=" * 60,
              "Executable : {}".format(executable),
              "Arguments  : {}".format(arguments or "(none)"),
              "Duration   : {}s".format(duration), ""]

    # 1. Start Procmon capture
    await progress("[1/3]", 1, 3)
    report.append("--- [1/3] Starting Procmon capture ---")
    try:
        pm_result = await _handle_procmon_start({})
        report.append(pm_result if pm_result else "Procmon start returned no output")
    except Exception as e:
        report.append("Procmon start warning: {}".format(e))
    report.append("")

    # 2. Launch the executable
    await progress("[2/3]", 2, 3)
    report.append("--- [2/3] Launching {} ---".format(executable))
    arg_clause = ""
    if arguments:
        arg_clause = " -ArgumentList {}".format(ps_quote(arguments))
    launch_ps = (
        "$proc = Start-Process -FilePath {exe}{args} -PassThru -ErrorAction Stop\n"
        "Write-Output \"PID: $($proc.Id)\"\n"
        "Start-Sleep -Seconds {dur}\n"
        "$proc.HasExited | Out-Null\n"
        "Write-Output \"Exited: $($proc.HasExited)\""
    ).format(exe=exe_q, args=arg_clause, dur=duration)
    try:
        out, err, code = await run_ps_async(launch_ps, timeout=duration + 30)
        report.append(out if out else "(no output)")
        if err:
            report.append("STDERR: " + err[:500])
    except Exception as e:
        report.append("Launch error: {}".format(e))
    report.append("")

    # 3. Stop Procmon and get summary
    await progress("[3/3]", 3, 3)
    report.append("--- [3/3] Stopping Procmon and collecting results ---")
    try:
        stop_result = await _handle_procmon_stop({})
        report.append(stop_result if stop_result else "Procmon stop returned no output")
    except Exception as e:
        report.append("Procmon stop error: {}".format(e))

    report.extend(["", "=" * 60, "END OF EXECUTE WITH MONITORING", "=" * 60])
    return _text("\n".join(report))


@tool(
    'autoruns_analyze',
    description='Run Autoruns (autorunsc.exe) to enumerate all autostart entries: registry run keys, startup folders, scheduled tasks, services, browser extensions, drivers, etc.  Returns a structured list with entry name, publisher, image path, and optionally signature status.',
    schema={'type': 'object',
     'properties': {'verify_signatures': {'type': 'boolean',
                                          'default': True,
                                          'description': 'Check digital signatures for each entry '
                                                         '(slower but more thorough)'},
                    'category': {'type': 'string',
                                 'default': '*',
                                 'description': 'Autorun category filter passed to autorunsc -a: * '
                                                '(all), l (logon), s (services), t (scheduled '
                                                'tasks), d (drivers), b (boot execute), c '
                                                '(codecs), etc.'}},
     'required': []},
    timeout=120,
    category='playbooks',
)
async def _handle_autoruns_analyze(args):
    verify_sigs = args.get("verify_signatures", True)
    category    = args.get("category", "*")
    import re as _re
    if not _re.match(r"^[A-Za-z*,]{1,32}$", str(category)):
        raise ValueError("invalid category: {!r}".format(category))

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
