"""Integrity / availability tools: verify_tools, vm_health, vm_snapshot."""
import socket

from .. import config
from ..integrity import (compare, hash_remote_files, load_manifest, run_snapshot, vm_state,
                         write_manifest)
from ..psquote import ps_ident
from ..registry import ToolError, tool
from ..winrm_client import breaker, run_ps_async


@tool(
    "verify_tools",
    description=("Verify the SHA256 of every analysis tool on FlareVM against tool_manifest.json. "
                 "Run with record=true against a CLEAN snapshot once to create the manifest; "
                 "afterwards mismatches indicate tampering and (with FLAREVM_STRICT_INTEGRITY) "
                 "block tool execution."),
    schema={"type": "object",
            "properties": {
                "record": {"type": "boolean", "default": False,
                           "description": "Write the observed hashes as the new manifest (only on a clean VM)"},
                "format": {"type": "string", "enum": ["text", "json"], "default": "text"}},
            "required": []},
    timeout=180, untrusted=False, category="integrity",
)
async def _handle_verify_tools(args):
    observed = await hash_remote_files(config.TOOL_PATHS)
    if args.get("record"):
        data = write_manifest(observed, config.FLAREVM_HOST)
        msg = "Manifest written to {} ({} tools hashed)".format(config.TOOL_MANIFEST, len(data["tools"]))
        return {"status": "recorded", "manifest": config.TOOL_MANIFEST, "tools": data["tools"]} \
            if args.get("format") == "json" else msg
    manifest = load_manifest()
    if not manifest:
        raise ToolError("No manifest at {}. Run verify_tools(record=true) on a clean snapshot first.".format(
            config.TOOL_MANIFEST))
    report = compare(manifest.get("tools", {}), observed)
    bad = [k for k, v in report.items() if v["status"] == "MISMATCH"]
    summary = {"status": "TAMPERED" if bad else "ok", "mismatched": bad,
               "strict": config.STRICT_INTEGRITY, "manifest_generated": manifest.get("generated"),
               "tools": report}
    if args.get("format") == "json":
        return summary
    lines = ["=== Tool integrity: {} ===".format(summary["status"]),
             "Manifest: {} (generated {})".format(config.TOOL_MANIFEST, manifest.get("generated")),
             "Strict mode: {}".format(config.STRICT_INTEGRITY), ""]
    for k in sorted(report):
        v = report[k]
        lines.append("{:<9} {:<15} {}".format(v["status"], k, v["path"]))
        if v["status"] == "MISMATCH":
            lines.append("          observed {}  expected {}".format(v["sha256"], v["expected"]))
    if bad:
        lines += ["", "!! {} tool(s) differ from the manifest. Treat all results as suspect and revert the VM.".format(len(bad))]
    return "\n".join(lines)


@tool(
    "vm_health",
    description=("Availability report: WinRM circuit-breaker state, VM disk/CPU/memory, WinRM service, "
                 "flarevm-mcp scheduled tasks, and whether the VM is clean or dirty since the last snapshot revert."),
    schema={"type": "object",
            "properties": {"format": {"type": "string", "enum": ["text", "json"], "default": "text"}},
            "required": []},
    timeout=60, untrusted=False, category="integrity",
)
async def _handle_vm_health(args):
    ps = r"""
$os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$svc = Get-Service WinRM -ErrorAction SilentlyContinue
$tasks = (Get-ScheduledTask -TaskName 'MCP_*' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TaskName)=$($_.State)" }) -join ','
$procs = (Get-Process | Measure-Object).Count
[pscustomobject]@{
  hostname = $env:COMPUTERNAME
  uptime_s = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  cpu_load_pct = $cpu
  mem_free_mb = [int]($os.FreePhysicalMemory / 1024)
  mem_total_mb = [int]($os.TotalVisibleMemorySize / 1024)
  disk_free_mb = [int]($disk.FreeSpace / 1MB)
  disk_total_mb = [int]($disk.Size / 1MB)
  winrm_service = "$($svc.Status)"
  mcp_tasks = $tasks
  process_count = $procs
} | ConvertTo-Json -Compress
"""
    import json
    guest = {}
    guest_error = None
    try:
        out, err, code = await run_ps_async(ps, timeout=40)
        if code == 0 and out.strip():
            guest = json.loads(out.strip().splitlines()[-1])
        else:
            guest_error = err or "no output"
    except Exception as exc:
        guest_error = str(exc)
    report = {"breaker": breaker.snapshot(), "vm_state": vm_state.snapshot(),
              "guest": guest, "guest_error": guest_error,
              "limits": {"max_concurrent": config.MAX_CONCURRENT, "max_output": config.MAX_OUTPUT,
                         "strict_integrity": config.STRICT_INTEGRITY}}
    warnings = []
    if guest.get("disk_free_mb") is not None and guest["disk_free_mb"] < 2048:
        warnings.append("low disk: {} MB free".format(guest["disk_free_mb"]))
    if guest.get("cpu_load_pct") is not None and guest["cpu_load_pct"] > 90:
        warnings.append("CPU saturated: {}%".format(guest["cpu_load_pct"]))
    if report["breaker"]["state"] == "open":
        warnings.append("circuit breaker OPEN")
    report["warnings"] = warnings
    if args.get("format") == "json":
        return report
    lines = ["=== FlareVM health ===",
             "Breaker: {} (failures {}/{})".format(report["breaker"]["state"], report["breaker"]["consecutive_failures"],
                                                  report["breaker"]["threshold"]),
             "VM state: {} ({} detonation(s) since clean)".format(vm_state.state, len(vm_state.detonations))]
    if guest_error:
        lines.append("Guest: UNREACHABLE — {}".format(guest_error))
    else:
        lines += ["Host: {}  uptime {}s  processes {}".format(guest.get("hostname"), guest.get("uptime_s"), guest.get("process_count")),
                  "CPU load: {}%  Memory free: {}/{} MB  Disk C: free {}/{} MB".format(
                      guest.get("cpu_load_pct"), guest.get("mem_free_mb"), guest.get("mem_total_mb"),
                      guest.get("disk_free_mb"), guest.get("disk_total_mb")),
                  "WinRM service: {}  MCP tasks: {}".format(guest.get("winrm_service"), guest.get("mcp_tasks") or "none")]
    if warnings:
        lines += ["", "WARNINGS: " + "; ".join(warnings)]
    return "\n".join(lines)


@tool(
    "vm_snapshot",
    description=("Manage hypervisor snapshots of the FlareVM from the analyst host (vmrun / VBoxManage / virsh "
                 "or custom commands via FLAREVM_SNAPSHOT_*_CMD). 'revert' restores the clean snapshot and marks "
                 "the VM clean; 'mark_clean' records that you reverted by hand."),
    schema={"type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["status", "list", "revert", "create", "mark_clean"]},
                "name": {"type": "string", "description": "Snapshot name (default FLAREVM_CLEAN_SNAPSHOT)"}},
            "required": ["action"]},
    timeout=330, untrusted=False, category="integrity",
)
async def _handle_vm_snapshot(args):
    action = args["action"]
    name = ps_ident(args.get("name") or config.CLEAN_SNAPSHOT, "snapshot name")
    if action == "status":
        s = vm_state.snapshot()
        return "VM state: {}\nDetonations since clean: {}\nHypervisor configured: {}".format(
            s["state"], len(s["detonations_since_clean"]),
            bool(config.VM_ID or config.SNAPSHOT_REVERT_CMD))
    if action == "mark_clean":
        vm_state.mark_clean("operator asserted a manual revert")
        return "VM marked clean (manual revert asserted by operator)."
    text = await run_snapshot(action, name)
    if action == "revert":
        vm_state.mark_clean("reverted to snapshot '{}'".format(name))
        from ..winrm_client import reset_sessions
        reset_sessions()
        breaker.reset()
        return "Reverted to snapshot '{}'. VM marked clean; WinRM sessions reset.\n{}".format(name, text)
    if action == "create":
        return "Snapshot '{}' created.\n{}".format(name, text)
    return text or "(no snapshots listed)"


_ = socket  # keep import for hostname use in future record() without VM
