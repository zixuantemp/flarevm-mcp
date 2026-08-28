"""Static tools (migrated from the 1.1.0 monolith)."""

from ..registry import tool
from ..winrm_client import run_ps_async
from ..transfer import run_ps_script
from ..guest import resolve_tool_path
from ._common import _text
from ..psquote import ps_int, ps_path, ps_quote


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


@tool(
    'die_analyze',
    description='Run DetectItEasy (DIE) for packer/compiler detection.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to file on FlareVM'}},
     'required': ['file_path']},
    timeout=60,
    category='static',
)
async def _handle_die_analyze(args):
    file_path = args["file_path"]
    die_path = await resolve_tool_path("die", "diec")
    ps = '& {} -d {} 2>&1'.format(ps_quote(die_path), ps_path(file_path, "file_path"))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== DetectItEasy Analysis ===\nFile: {}\n\n{}".format(file_path, stdout)
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'floss_extract_strings',
    description='Run FLOSS for obfuscated string recovery.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to file on FlareVM'},
                    'min_length': {'type': 'integer',
                                   'description': 'Minimum string length (default 4)',
                                   'default': 4}},
     'required': ['file_path']},
    timeout=600,
    category='static',
)
async def _handle_floss_extract_strings(args):
    file_path = args["file_path"]
    min_length = ps_int(args.get("min_length", 4), 1, 256, "min_length")
    floss_path = await resolve_tool_path("floss", "floss")
    ps = '& {} -n {} {} 2>&1'.format(ps_quote(floss_path), min_length, ps_path(file_path, "file_path"))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== FLOSS String Extraction ===\nFile: {}\nMin length: {}\n\n{}".format(
        file_path, min_length, stdout
    )
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'capa_analyze',
    description='Run CAPA for capability detection and ATT&CK mapping.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to file on FlareVM'},
                    'verbose': {'type': 'boolean',
                                'description': 'Verbose output',
                                'default': False}},
     'required': ['file_path']},
    timeout=600,
    category='static',
)
async def _handle_capa_analyze(args):
    file_path = args["file_path"]
    verbose = bool(args.get("verbose", False))
    capa_path = await resolve_tool_path("capa", "capa")
    v_flag = "-v " if verbose else ""
    ps = '& {} {}{} 2>&1'.format(ps_quote(capa_path), v_flag, ps_path(file_path, "file_path"))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== CAPA Capability Analysis ===\nFile: {}\n\n{}".format(file_path, stdout)
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'yara_scan',
    description='Scan a file with YARA rules.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to file on FlareVM'},
                    'rules_path': {'type': 'string',
                                   'description': 'Path to YARA rules (default '
                                                  'C:\\Tools\\yara\\rules\\)',
                                   'default': 'C:\\Tools\\yara\\rules\\'}},
     'required': ['file_path']},
    timeout=120,
    category='static',
)
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

    ps = '& {yara} -r {rules} {file} 2>&1'.format(
        yara=ps_quote(yara_path),
        rules=ps_path(rules_path, "rules_path"),
        file=ps_path(file_path, "file_path"),
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


@tool(
    'strings_extract',
    description='Extract printable strings from a file using Sysinternals strings.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to file on FlareVM'},
                    'min_length': {'type': 'integer',
                                   'description': 'Minimum string length (default 6)',
                                   'default': 6},
                    'encoding': {'type': 'string',
                                 'description': 'Encoding: a=ASCII, u=Unicode, b=both (default b)',
                                 'default': 'b'}},
     'required': ['file_path']},
    timeout=60,
    category='static',
)
async def _handle_strings_extract(args):
    file_path = args["file_path"]
    min_length = ps_int(args.get("min_length", 6), 1, 256, "min_length")
    encoding = args.get("encoding", "b")
    if encoding not in ("a", "u", "b"):
        raise ValueError("encoding must be one of a, u, b")
    strings_path = await resolve_tool_path("strings", "strings")
    enc_flag = ""
    if encoding == "a":
        enc_flag = "-a"
    elif encoding == "u":
        enc_flag = "-u"
    else:
        enc_flag = ""  # default is both in Sysinternals strings

    ps = '& {} -accepteula -n {} {} {} 2>&1'.format(
        ps_quote(strings_path), min_length, enc_flag, ps_path(file_path, "file_path")
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    lines = stdout.split("\n") if stdout else []
    result = "=== Strings Extraction ===\nFile: {}\nTotal strings found: {}\n\n{}".format(
        file_path, len(lines), stdout
    )
    return _text(result)


@tool(
    'entropy_analysis',
    description='Calculate per-section entropy for PE files to detect packing.',
    schema={'type': 'object',
     'properties': {'file_path': {'type': 'string', 'description': 'Path to PE file on FlareVM'}},
     'required': ['file_path']},
    timeout=60,
    category='static',
)
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
    ps = 'New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null; ' \
         'python C:\\temp\\entropy_check.py {} 2>&1'.format(ps_path(file_path, "file_path"))
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("Entropy analysis failed: {} {}".format(stderr, stdout))
    return _text(stdout)


@tool(
    'dnspy_decompile',
    description='Decompile a .NET assembly with dnSpy Console.',
    schema={'type': 'object',
     'properties': {'assembly_path': {'type': 'string',
                                      'description': 'Path to .NET assembly on FlareVM'},
                    'output_dir': {'type': 'string',
                                   'description': 'Output directory for decompiled source',
                                   'default': 'C:\\temp\\decompiled'}},
     'required': ['assembly_path']},
    timeout=120,
    category='static',
)
async def _handle_dnspy_decompile(args):
    assembly_path = args["assembly_path"]
    output_dir = args.get("output_dir", "C:\\temp\\decompiled")
    dnspy_path = await resolve_tool_path("dnspy", "dnSpy.Console")
    ps = """
$out = {output}
$asm = {assembly}
New-Item -ItemType Directory -Path $out -Force | Out-Null
$result = & {tool} -o $out $asm 2>&1
Write-Output "=== dnSpy Decompilation ==="
Write-Output "Assembly: $asm"
Write-Output "Output: $out"
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Decompiled Files ---"
Get-ChildItem -LiteralPath $out -Recurse -File | Select-Object -First 50 | ForEach-Object {{
    Write-Output "  $($_.FullName.Substring($out.Length).TrimStart('\\')) ($($_.Length) bytes)"
}}
$totalFiles = (Get-ChildItem -LiteralPath $out -Recurse -File | Measure-Object).Count
Write-Output ""
Write-Output "Total decompiled files: $totalFiles"
""".format(tool=ps_quote(dnspy_path), assembly=ps_path(assembly_path, "assembly_path"), output=ps_path(output_dir, "output_dir"))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)