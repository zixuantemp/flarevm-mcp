# MCP tool reference

All 52 tools exposed by `flarevm-mcp`, grouped by task. Descriptions are the ones the
server advertises to the client; arguments are in each tool's JSON schema (`list_tools`).
Paths on the VM are always Windows paths — escape backslashes in JSON.

## Connection & file transfer

| Tool | Purpose |
|------|---------|
| `check_connection` | Test WinRM connection to FlareVM. Returns hostname, OS info, and IP. |
| `execute_powershell` | Execute a PowerShell command on FlareVM. |
| `read_file` | Read a file from FlareVM. Returns file content. |
| `upload_file` | Upload a file from Kali to FlareVM via SMB with SHA256 verification. |
| `download_file` | Download a file from FlareVM to Kali via SMB. |
| `get_file_hash` | Calculate MD5/SHA1/SHA256 hash of a file on FlareVM. |
| `list_processes` | List running processes on FlareVM with optional name filter. |
| `take_screenshot` | Take a screenshot of FlareVM desktop via nircmd and scheduled task. |

## Static analysis

| Tool | Purpose |
|------|---------|
| `die_analyze` | Run DetectItEasy (DIE) for packer/compiler detection. |
| `floss_extract_strings` | Run FLOSS for obfuscated string recovery. |
| `capa_analyze` | Run CAPA for capability detection and ATT&CK mapping. |
| `yara_scan` | Scan a file with YARA rules. |
| `strings_extract` | Extract printable strings from a file using Sysinternals strings. |
| `entropy_analysis` | Calculate per-section entropy for PE files to detect packing. |
| `dnspy_decompile` | Decompile a .NET assembly with dnSpy Console. |

## Monitoring & detonation

| Tool | Purpose |
|------|---------|
| `procmon_start` | Start Process Monitor with optional process filter. |
| `procmon_stop` | Stop ProcMon and export results to CSV with summary. |
| `procmon_export_csv` | Export a PML file to CSV format. |
| `process_hacker_info` | Get detailed info about a process: modules, threads, handles, connections. |
| `monitor_network_realtime` | Monitor network connections for a duration, returning new connections and DNS cache. |
| `wireshark_capture` | Start/stop packet capture with tshark. |
| `regshot_snapshot` | Registry before/after snapshot and comparison. |
| `autoruns_analyze` | Run Autoruns (autorunsc.exe) to enumerate all autostart entries: registry run  keys, startup folders, scheduled tasks, services, browser extensions, drivers,  etc.  Returns a structured list with entry name, publisher, image path, and  optionally signature status. |
| `execute_with_monitoring` | Execute a binary under full monitoring: starts Procmon capture, launches the  executable, waits for the specified duration, then stops Procmon and returns  a combined activity summary (file/reg/net events, new processes). |

## Network simulation (FakeNet-NG)

| Tool | Purpose |
|------|---------|
| `fakenet_start` | Start FakeNet-NG with WinRM-safe config (excludes management ports). |
| `fakenet_stop` | Stop FakeNet-NG and retrieve captured logs. |

## Memory & injection

| Tool | Purpose |
|------|---------|
| `pe_sieve_scan` | Scan a process for code injection/hollowing with PE-sieve. |
| `hollows_hunter_scan` | Scan ALL running processes for injection/hollowing. |
| `injection_scan_all` | Scan all processes for code injection using hollows_hunter + pe-sieve. |

## Unpacking

| Tool | Purpose |
|------|---------|
| `upx_unpack` | Attempt UPX unpacking of a packed executable. |
| `unpack_detect_and_try` | Composite: detect packer, check entropy, attempt automated unpacking. |

## Debuggers

| Tool | Purpose |
|------|---------|
| `x64dbg_load` | Load a binary in x64dbg via scheduled task (interactive session). |
| `x64dbg_run_script` | Save and execute an x64dbg script. |
| `windbg_launch` | Launch WinDbg GUI with a dump file in the interactive console session. |
| `windbg_list_dumps` | List .dmp crash dump files on FlareVM via mcp-windbg. |
| `windbg_analyze_dump` | Open a crash/memory dump via mcp-windbg (cdb.exe) on FlareVM and run initial  triage. Returns crash info, call stack, loaded modules and threads.  Requires mcp-windbg HTTP server running on port 13338 (registered as  MCP_WinDbg_Server scheduled task by setup.py). |
| `windbg_run_cmd` | Run an arbitrary cdb command on an already-opened dump session in mcp-windbg.  Call windbg_analyze_dump first to open the session; subsequent windbg_run_cmd  calls on the same dump_file reuse the persistent cdb.exe process. |

## Frida instrumentation

| Tool | Purpose |
|------|---------|
| `frida_list_processes` | List processes visible to Frida on FlareVM. |
| `frida_spawn_and_attach` | Spawn a process and attach Frida with a script. |
| `frida_attach_pid` | Attach Frida to a running process by PID. |
| `frida_run_script` | Execute an inline Frida script against a process (by name or PID). |

## IDA Pro (proxied to the VM's IDA MCP plugin)

| Tool | Purpose |
|------|---------|
| `ida_launch_and_wait` | Launch IDA Pro with a binary and wait for MCP server (port 13337) to be ready. |
| `ida_get_metadata` | Get metadata from IDA Pro (binary info, architecture, etc.). |
| `ida_list_functions` | List functions in the binary loaded in IDA Pro. |
| `ida_decompile_function` | Decompile a function in IDA Pro (Hex-Rays). |
| `ida_disassemble_function` | Get disassembly of a function in IDA Pro. |
| `ida_list_strings` | List strings found by IDA Pro. |
| `ida_set_comment` | Set a comment in IDA Pro at a given address. |
| `ida_rename_function` | Rename a function in IDA Pro. |

## Composite workflows

| Tool | Purpose |
|------|---------|
| `triage_full` | Complete static analysis pipeline: hashes, DIE, entropy, CAPA, FLOSS, YARA. |
| `behavioral_full` | Complete behavioral analysis: regshot, procmon, FakeNet, network monitoring, execute, collect. |
| `persistence_audit` | Full persistence mechanism scan: autoruns, registry, tasks, services, WMI, startup. |

## Keeping this file current

Generated from the `Tool(name=…, description=…)` entries in `server.py`. When you add a tool,
add it to `list_tools()`, implement `_handle_<name>()`, dispatch it in `call_tool()`, and add a
row here under the right heading (the CI import check will not catch a missing row).
