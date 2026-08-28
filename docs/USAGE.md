# Usage

The server is driven by an MCP client — in practice an AI agent. You describe the analysis; the
agent calls tools. The reference for every tool is [TOOLS.md](TOOLS.md).

## Ground rules

1. **Never run a sample on the analyst host.** Upload it and detonate on the VM.
2. **Snapshot the VM before detonation, revert after.** Treat the VM as compromised once a
   sample has run.
3. **Stage files under `C:\temp\`** on the VM. `upload_file` basenames paths there; use
   double backslashes in JSON (`"C:\\temp\\sample.exe"`).
4. **Network-aware samples need FakeNet.** Start it *before* detonating; stop it afterwards to
   collect logs. Without it the sample's `connect()` simply fails and looks benign.

## Typical workflows

**Static triage of an unknown binary**
`upload_file` → `get_file_hash` → `die_analyze` → `entropy_analysis` → `floss_extract_strings` →
`capa_analyze` → `yara_scan`. Or call `triage_full` for all of it in one step.

**Detonation with monitoring**
`fakenet_start` → `procmon_start` → `execute_with_monitoring` (or a direct `execute_powershell`
`Start-Process` for noisy samples — ProcMon caps at 10 k events) → `procmon_stop` →
`procmon_export_csv` → `regshot_snapshot` compare → `fakenet_stop` → `download_file`.
`behavioral_full` chains the common case.

**Packed sample**
`unpack_detect_and_try` (UPX and heuristics) → if that fails, `x64dbg_load` + `x64dbg_run_script`
or a Frida hook on the unpacking stub → `pe_sieve_scan` to dump the in-memory image.

**Injection / persistence hunt on a live VM**
`injection_scan_all` (PE-sieve + Hollows Hunter) → `persistence_audit` → `autoruns_analyze`.

**Reverse engineering**
`ida_launch_and_wait` → `ida_get_metadata` → `ida_list_functions` / `ida_list_strings` →
`ida_decompile_function` → `ida_set_comment` / `ida_rename_function`.
Requires the IDA MCP plugin listening on the VM at `localhost:13337`.

**Crash / dump analysis**
`windbg_launch` → `windbg_list_dumps` → `windbg_analyze_dump` → `windbg_run_cmd`.

## Prompts, resources, skills

- **Prompts** (`prompts/`): `triage_unknown_sample`, `behavioral_analysis`, `unpack_workflow`,
  `injection_hunt`, `persistence_audit_report` — pre-built multi-step instructions the client can
  invoke with arguments (e.g. `sample_path`, `duration`).
- **Resources**: `flarevm://tools/inventory` (live `Test-Path` of every tool),
  `flarevm://config/fakenet-default`, `flarevm://docs/yara-rules`, `flarevm://docs/cheatsheet`,
  `flarevm://status/connection`.
- **Claude Code skills** (`skills/`): `triage-malware-sample`, `incident-response-windows`,
  `automated-unpacking`. Copy into `.claude/skills/` to make them invocable.

## Timeouts

Each tool has a wall-clock budget (see `TOOL_TIMEOUTS` in `server.py`; long ones such as
`procmon_stop` and `behavioral_full` run to a few minutes). On expiry the WinRM session is reset so
a hung PowerShell never wedges the server. If a tool times out, the VM state is unknown — check
`list_processes` before retrying.
