# MCP tool reference

All 55 tools exposed by `flarevm-mcp`, grouped by task. Generated from the tool registry by
`python -m flarevm_mcp.docs`; CI fails if this file is stale. Arguments are in each tool's JSON
schema (`list_tools`). Paths on the VM are always Windows paths — escape backslashes in JSON.

## Connection & file transfer

| Tool | Timeout | Purpose |
|------|---------|---------|
| `check_connection` | 30s | Test WinRM connection to FlareVM. Returns hostname, OS info, and IP. Resets the circuit breaker on success. |
| `execute_powershell` | 180s | Execute an arbitrary PowerShell command on FlareVM. Every command is audit-logged on the analyst host. |
| `read_file` | 60s | Read a text file from FlareVM (truncated at max_bytes). |
| `upload_file` | 400s | Upload a file from Kali to FlareVM via SMB with end-to-end SHA256 verification. local_path must be under FLAREVM_ALLOWED_UPLOAD_ROOTS. |
| `download_file` | 400s | Download a file from FlareVM to Kali via SMB with SHA256 verification. local_path must be under FLAREVM_ALLOWED_DOWNLOAD_ROOTS; the file is written 0600 and must never be executed on the host. |
| `get_file_hash` | 60s | Calculate MD5, SHA1 and SHA256 of a file on FlareVM. |
| `list_processes` | 30s | List running processes on FlareVM with optional name filter (wildcards allowed). |
| `take_screenshot` | 60s | Take a screenshot of the FlareVM desktop via nircmd in the interactive session. |

## Static analysis

| Tool | Timeout | Purpose |
|------|---------|---------|
| `die_analyze` | 60s | Run DetectItEasy (DIE) for packer/compiler detection. |
| `floss_extract_strings` | 600s | Run FLOSS for obfuscated string recovery. |
| `capa_analyze` | 600s | Run CAPA for capability detection and ATT&CK mapping. |
| `yara_scan` | 120s | Scan a file with YARA rules. |
| `strings_extract` | 60s | Extract printable strings from a file using Sysinternals strings. |
| `entropy_analysis` | 60s | Calculate per-section entropy for PE files to detect packing. |
| `dnspy_decompile` | 120s | Decompile a .NET assembly with dnSpy Console. |

## Dynamic analysis: process & registry

| Tool | Timeout | Purpose |
|------|---------|---------|
| `procmon_start` | 60s | Start Process Monitor (captures all process activity; summarise per process with procmon_stop). |
| `procmon_stop` | 180s | Stop ProcMon and export results to CSV with summary. |
| `procmon_export_csv` | 120s | Export a PML file to CSV format. |
| `process_hacker_info` | 60s | Get detailed info about a process: modules, threads, handles, connections. |
| `regshot_snapshot` | 300s | Registry before/after snapshot and comparison. |

## Dynamic analysis: network

| Tool | Timeout | Purpose |
|------|---------|---------|
| `monitor_network_realtime` | 180s | Monitor network connections for a duration, returning new connections and DNS cache. |
| `fakenet_start` | 120s | Start FakeNet-NG with WinRM-safe config (excludes management ports). |
| `fakenet_stop` | 60s | Stop FakeNet-NG and retrieve captured logs. |
| `wireshark_capture` | 120s | Start/stop packet capture with tshark. |

## Debuggers & GUI launchers

| Tool | Timeout | Purpose |
|------|---------|---------|
| `x64dbg_load` | 60s | Load a binary in x64dbg via scheduled task (interactive session). |
| `x64dbg_run_script` | 120s | Save and execute an x64dbg script. |
| `windbg_analyze_dump` | 300s | Open a crash/memory dump via mcp-windbg (cdb.exe) on FlareVM and run initial triage. Returns crash info, call stack, loaded modules and threads. Requires mcp-windbg HTTP server running on port 13338 (registered as MCP_WinDbg_Server scheduled task by setup.py). |
| `windbg_launch` | 60s | Launch WinDbg GUI with a dump file in the interactive console session. |
| `windbg_run_cmd` | 120s | Run an arbitrary cdb command on an already-opened dump session in mcp-windbg. Call windbg_analyze_dump first to open the session; subsequent windbg_run_cmd calls on the same dump_file reuse the persistent cdb.exe process. |
| `windbg_list_dumps` | 30s | List .dmp crash dump files on FlareVM via mcp-windbg. |
| `ida_launch_and_wait` | 180s | Launch IDA Pro with a binary and wait for MCP server (port 13337) to be ready. |

## Frida instrumentation

| Tool | Timeout | Purpose |
|------|---------|---------|
| `frida_list_processes` | 30s | List processes visible to Frida on FlareVM. |
| `frida_spawn_and_attach` | 120s | Spawn a process and attach Frida with a script. |
| `frida_attach_pid` | 120s | Attach Frida to a running process by PID. |
| `frida_run_script` | 120s | Execute an inline Frida script against a process (by name or PID). |

## Injection & unpacking

| Tool | Timeout | Purpose |
|------|---------|---------|
| `pe_sieve_scan` | 60s | Scan a process for code injection/hollowing with PE-sieve. |
| `hollows_hunter_scan` | 90s | Scan ALL running processes for injection/hollowing. |
| `upx_unpack` | 60s | Attempt UPX unpacking of a packed executable. |
| `unpack_detect_and_try` | 90s | Composite: detect packer, check entropy, attempt automated unpacking. |
| `injection_scan_all` | 180s | Scan all processes for code injection using hollows_hunter + pe-sieve. |

## IDA Pro proxy

| Tool | Timeout | Purpose |
|------|---------|---------|
| `ida_get_metadata` | 30s | Get metadata from IDA Pro (binary info, architecture, etc.). |
| `ida_list_functions` | 30s | List functions in the binary loaded in IDA Pro. |
| `ida_decompile_function` | 60s | Decompile a function in IDA Pro (Hex-Rays). |
| `ida_disassemble_function` | 60s | Get disassembly of a function in IDA Pro. |
| `ida_list_strings` | 30s | List strings found by IDA Pro. |
| `ida_set_comment` | 30s | Set a comment in IDA Pro at a given address. |
| `ida_rename_function` | 30s | Rename a function in IDA Pro. |

## Composite playbooks

| Tool | Timeout | Purpose |
|------|---------|---------|
| `triage_full` | 900s | Complete static analysis pipeline: hashes, DIE, entropy, CAPA, FLOSS, YARA. |
| `behavioral_full` | 1800s | Complete behavioral analysis: regshot, procmon, FakeNet, network monitoring, execute, collect. |
| `persistence_audit` | 120s | Full persistence mechanism scan: autoruns, registry, tasks, services, WMI, startup. |
| `execute_with_monitoring` | 300s | Execute a binary under full monitoring: starts Procmon capture, launches the executable, waits for the specified duration, then stops Procmon and returns a combined activity summary (file/reg/net events, new processes). |
| `autoruns_analyze` | 120s | Run Autoruns (autorunsc.exe) to enumerate all autostart entries: registry run keys, startup folders, scheduled tasks, services, browser extensions, drivers, etc. Returns a structured list with entry name, publisher, image path, and optionally signature status. |

## Integrity & availability

| Tool | Timeout | Purpose |
|------|---------|---------|
| `verify_tools` | 180s | Verify the SHA256 of every analysis tool on FlareVM against tool_manifest.json. Run with record=true against a CLEAN snapshot once to create the manifest; afterwards mismatches indicate tampering and (with FLAREVM_STRICT_INTEGRITY) block tool execution. |
| `vm_health` | 60s | Availability report: WinRM circuit-breaker state, VM disk/CPU/memory, WinRM service, flarevm-mcp scheduled tasks, and whether the VM is clean or dirty since the last snapshot revert. |
| `vm_snapshot` | 330s | Manage hypervisor snapshots of the FlareVM from the analyst host (vmrun / VBoxManage / virsh or custom commands via FLAREVM_SNAPSHOT_*_CMD). 'revert' restores the clean snapshot and marks the VM clean; 'mark_clean' records that you reverted by hand. |
