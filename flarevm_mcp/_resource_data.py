"""Static resource texts (data only)."""

CHEATSHEET_TEXT = """# FlareVM MCP Cheatsheet

## Quick triage
- check_connection
- upload_file (kali_path -> C:\\temp\\sample.bin)
- triage_full (DIE + FLOSS + CAPA + YARA)

## Detonation
- fakenet_start / fakenet_stop
- procmon_start / procmon_stop
- regshot_baseline / regshot_compare
- execute_with_monitoring

## Unpacking
- die_analyze (identify packer)
- unpack_detect_and_try (UPX auto)
- pe_sieve_scan (dump from memory)
- x64dbg_launch_gui (manual unpack)

## Injection hunt
- injection_scan_all (Hollows Hunter + PE-sieve)
- list_processes
- pe_sieve_scan --pid <PID>

## Persistence
- persistence_audit (autorunsc + tasks + services)
- list_scheduled_tasks
- list_services

## Network
- tshark_capture (PCAP capture)
- fakenet_start (DNS+HTTP+HTTPS sinkhole)

## Tool flags
- die: -j (JSON output), -d (deep)
- floss: -n 6 (min length), --no-static-strings
- capa: -j (JSON), -vv (verbose)
- yara: -r (recursive), -s (show strings)
- pe-sieve: /pid <N> /imp 3 /shellc 3 /data 3
"""

YARA_INDEX_TEXT = """# YARA Rules Index

Default rules directory: `C:\\Tools\\yara\\rules\\`

## Recommended rule sources
- Florian Roth signature-base: https://github.com/Neo23x0/signature-base
- YaraRules Project: https://github.com/Yara-Rules/rules
- Elastic Protections Artifacts: https://github.com/elastic/protections-artifacts
- ReversingLabs YARA rules: https://github.com/reversinglabs/reversinglabs-yara-rules

## Common malware family rules to keep
- Cobalt Strike beacon detection
- Metasploit shellcode patterns
- Common loader patterns (DonutLoader, Shellter)
- Ransomware family heuristics (LockBit, BlackCat, Conti)
- Stealer families (RedLine, Raccoon, Vidar)

## Use via MCP
- yara_scan(file_path, rules_dir="C:\\Tools\\yara\\rules") -> matches per rule
"""

TOOLS_REFERENCE_TEXT = """# FlareVM Tool Reference

| Tool | Path | Purpose |
|------|------|---------|
| DIE | C:\\Tools\\die\\diec.exe | Packer / compiler identification |
| FLOSS | C:\\Tools\\FLOSS\\floss.exe | Stacked / decoded string extraction |
| CAPA | C:\\Tools\\capa\\capa.exe | Capability fingerprinting |
| YARA | C:\\Tools\\yara\\yara64.exe | Signature scanning |
| ProcMon | C:\\Tools\\sysinternals\\Procmon.exe | Behavioral monitoring |
| Autorunsc | C:\\Tools\\sysinternals\\autorunsc.exe | Persistence enumeration |
| Strings | C:\\Tools\\sysinternals\\strings.exe | ASCII/Unicode strings |
| PE-sieve | C:\\Tools\\pe-sieve\\pe-sieve64.exe | In-memory PE anomaly scan |
| Hollows Hunter | C:\\Tools\\hollows_hunter\\hollows_hunter64.exe | System-wide injection sweep |
| UPX | C:\\Tools\\upx\\upx.exe | UPX unpack/pack |
| dnSpy | C:\\Tools\\dnSpy\\dnSpy.Console.exe | .NET decompilation |
| FakeNet-NG | C:\\Tools\\fakenet\\fakenet.exe | Network sinkhole |
| NirCmd | C:\\Tools\\nircmd.exe | GUI automation |
| x64dbg | C:\\ProgramData\\chocolatey\\bin\\x64dbg.exe | Debugger |
| TShark | C:\\ProgramData\\chocolatey\\bin\\tshark.exe | CLI Wireshark |
"""


RESOURCE_DEFS = [
    ("flarevm://tools/inventory", "FlareVM tools inventory", "text/plain"),
    ("flarevm://config/fakenet-default", "Default FakeNet-NG config", "text/plain"),
    ("flarevm://docs/yara-rules", "YARA rules index", "text/markdown"),
    ("flarevm://docs/cheatsheet", "FlareVM MCP cheatsheet", "text/markdown"),
    ("flarevm://status/connection", "FlareVM connection status", "text/plain"),
]


