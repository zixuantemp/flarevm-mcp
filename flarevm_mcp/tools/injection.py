"""Injection tools (migrated from the 1.1.0 monolith)."""
import ntpath

from ..registry import tool
from ..winrm_client import run_ps_async
from ..guest import resolve_tool_path
from ..guest import _file_exists
from ._common import _text
from .static import _handle_die_analyze, _handle_entropy_analysis, _handle_floss_extract_strings
from ..psquote import ps_int, ps_path, ps_quote
from ..integrity import require_clean_for, vm_state


@tool(
    'pe_sieve_scan',
    description='Scan a process for code injection/hollowing with PE-sieve.',
    schema={'type': 'object',
     'properties': {'pid': {'type': 'integer', 'description': 'Process ID to scan'},
                    'output_dir': {'type': 'string',
                                   'description': 'Output directory',
                                   'default': 'C:\\temp\\pe_sieve_output'}},
     'required': ['pid']},
    timeout=60,
    category='injection',
)
async def _handle_pe_sieve_scan(args):
    pid = ps_int(args["pid"], 1, 2**31 - 1, "pid")
    output_dir = args.get("output_dir", "C:\\temp\\pe_sieve_output")
    pe_sieve_path = await resolve_tool_path("pe_sieve", "pe-sieve")
    ps = """
$out = {output}
New-Item -ItemType Directory -Path $out -Force | Out-Null
$result = & {tool} /pid {pid} /dir $out /shellc 3 /iat 3 /data 3 2>&1
Write-Output "=== PE-sieve Scan (PID: {pid}) ==="
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Output Files ---"
Get-ChildItem -LiteralPath $out -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    Write-Output "  $($_.Name) - $($_.Length) bytes"
}}
""".format(tool=ps_quote(pe_sieve_path), pid=pid, output=ps_path(output_dir, "output_dir"))
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'hollows_hunter_scan',
    description='Scan ALL running processes for injection/hollowing.',
    schema={'type': 'object',
     'properties': {'output_dir': {'type': 'string',
                                   'description': 'Output directory',
                                   'default': 'C:\\temp\\hollows_output'}},
     'required': []},
    timeout=90,
    category='injection',
)
async def _handle_hollows_hunter_scan(args):
    output_dir = args.get("output_dir", "C:\\temp\\hollows_output")
    hh_path = await resolve_tool_path("hollows_hunter", "hollows_hunter")
    ps = """
$out = {output}
New-Item -ItemType Directory -Path $out -Force | Out-Null
$result = & {tool} /dir $out /shellc 3 /iat 3 2>&1
Write-Output "=== Hollows Hunter Scan (All Processes) ==="
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Output Files ---"
Get-ChildItem -LiteralPath $out -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    Write-Output "  $($_.Name) - $($_.Length) bytes"
}}
""".format(tool=ps_quote(hh_path), output=ps_path(output_dir, "output_dir"))
    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'upx_unpack',
    description='Attempt UPX unpacking of a packed executable.',
    schema={'type': 'object',
     'properties': {'packed_file': {'type': 'string', 'description': 'Path to packed file'},
                    'output_file': {'type': 'string',
                                    'description': 'Output path for unpacked file'}},
     'required': ['packed_file', 'output_file']},
    timeout=60,
    category='injection',
)
async def _handle_upx_unpack(args):
    packed_file = args["packed_file"]
    output_file = args["output_file"]
    upx_path = await resolve_tool_path("upx", "upx")
    out_q = ps_path(output_file, "output_file")
    ps = '& {} -d {} -o {} 2>&1'.format(
        ps_quote(upx_path), ps_path(packed_file, "packed_file"), out_q
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = "=== UPX Unpack ===\nInput: {}\nOutput: {}\n\n{}".format(
        packed_file, output_file, stdout
    )
    if code == 0:
        # Verify output
        ps_check = """
$o = {out}
if (Test-Path -LiteralPath $o) {{
    $size = (Get-Item -LiteralPath $o).Length
    Write-Output "Unpacked file size: $size bytes"
    $hash = (Get-FileHash -LiteralPath $o -Algorithm SHA256).Hash
    Write-Output "SHA256: $hash"
}} else {{
    Write-Output "Output file not created"
}}
""".format(out=out_q)
        check_stdout, _, _ = await run_ps_async(ps_check, timeout=15)
        result += "\n" + check_stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'unpack_detect_and_try',
    description='Composite: detect packer, check entropy, attempt automated unpacking.',
    schema={'type': 'object',
     'properties': {'ack_dirty_vm': {'type': 'boolean', 'default': False, 'description': 'Proceed even if the VM is dirty since the last snapshot revert'},
                    'file_path': {'type': 'string',
                                  'description': 'Path to potentially packed file'}},
     'required': ['file_path']},
    timeout=90,
    category='injection',
)
async def _handle_unpack_detect_and_try(args):
    file_path = args["file_path"]
    ps_path(file_path, "file_path")
    report_parts = ["=== Automated Unpack: Detect & Try ===", "File: {}".format(file_path), ""]

    # Step 1: DIE analysis
    try:
        die_result = await _handle_die_analyze({"file_path": file_path})
        die_text = die_result if die_result else "DIE analysis failed"
        report_parts.append("--- Step 1: Packer Detection (DIE) ---")
        report_parts.append(die_text)
        report_parts.append("")
    except Exception as e:
        die_text = str(e)
        report_parts.append("DIE failed: " + die_text)

    # Step 2: Entropy analysis
    try:
        ent_result = await _handle_entropy_analysis({"file_path": file_path})
        ent_text = ent_result if ent_result else "Entropy analysis failed"
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
            report_parts.append(upx_result if upx_result else "UPX unpack failed")
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
                report_parts.append(floss_result if floss_result else "FLOSS failed")
            except Exception as e:
                report_parts.append("FLOSS failed: " + str(e))
    elif "aspack" in die_lower or "mpress" in die_lower or "packed" in die_lower or "PACKED" in ent_text:
        report_parts.append("--- Step 3: Packer Detected - Attempting Runtime Unpack ---")
        # Run the binary briefly, then pe-sieve. This DETONATES the sample.
        require_clean_for("unpack_detect_and_try (runtime unpack)", args)
        vm_state.mark_dirty("unpack_detect_and_try executed {}".format(file_path))
        ps_run = """
$proc = Start-Process -FilePath {file} -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
Write-Output "Started process PID: $($proc.Id)"
$proc.Id
""".format(file=ps_path(file_path, "file_path"))
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
                    report_parts.append(sieve_result if sieve_result else "pe-sieve failed")
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
            report_parts.append(floss_result if floss_result else "FLOSS failed")
        except Exception as e:
            report_parts.append("FLOSS failed: " + str(e))

    return _text("\n".join(report_parts))


@tool(
    'injection_scan_all',
    description='Scan all processes for code injection using hollows_hunter + pe-sieve.',
    schema={'type': 'object', 'properties': {}, 'required': []},
    timeout=180,
    category='injection',
)
async def _handle_injection_scan_all(args):
    report = ["=" * 60, "INJECTION SCAN - ALL PROCESSES", "=" * 60, ""]

    # Step 1: Hollows Hunter scan
    report.append("--- Step 1: Hollows Hunter (All Processes) ---")
    try:
        hh_result = await _handle_hollows_hunter_scan({
            "output_dir": "C:\\temp\\injection_scan_hh"
        })
        hh_text = hh_result if hh_result else "Failed"
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
                                report.append(sieve_result if sieve_result else "Failed")
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
