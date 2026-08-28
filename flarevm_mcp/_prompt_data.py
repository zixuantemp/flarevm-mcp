"""Prompt definitions (data only)."""

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


