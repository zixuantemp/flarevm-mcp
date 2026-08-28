"""Network tools (migrated from the 1.1.0 monolith)."""
import asyncio

from ..registry import tool
from ..winrm_client import run_ps_async
from ..guest import resolve_tool_path
from ..guest import launch_gui_app
from ..fakenet import generate_fakenet_config
from ._common import _text
from ..psquote import ps_ident, ps_int, ps_path, ps_quote, win_arg


@tool(
    'monitor_network_realtime',
    description='Monitor network connections for a duration, returning new connections and DNS cache.',
    schema={'type': 'object',
     'properties': {'duration': {'type': 'integer',
                                 'description': 'Monitoring duration in seconds (default 30)',
                                 'default': 30}},
     'required': []},
    timeout=180,
    category='network',
)
async def _handle_monitor_network_realtime(args):
    duration = ps_int(args.get("duration", 30), 1, 600, "duration")
    ps = """
$duration = {duration}
$allConnections = @()
$startTime = Get-Date

Write-Output "=== Network Monitoring ({duration}s) ==="
Write-Output "Start time: $startTime"
Write-Output ""

# Get baseline connections
$baseline = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
$baselineUdp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess

$newConnections = @()
$elapsed = 0

while ($elapsed -lt $duration) {{
    Start-Sleep -Seconds 1
    $elapsed++

    $current = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $current) {{
        $key = "$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
        $existing = $baseline | Where-Object {{
            $_.LocalPort -eq $conn.LocalPort -and $_.RemoteAddress -eq $conn.RemoteAddress -and $_.RemotePort -eq $conn.RemotePort
        }}
        if (-not $existing) {{
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $entry = "$($conn.State): $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [PID:$($conn.OwningProcess) $($proc.ProcessName)]"
            if ($entry -notin $newConnections) {{
                $newConnections += $entry
            }}
        }}
    }}
}}

Write-Output "--- New TCP Connections ---"
if ($newConnections.Count -gt 0) {{
    $newConnections | ForEach-Object {{ Write-Output "  $_" }}
}} else {{
    Write-Output "  No new connections detected"
}}
Write-Output ""

Write-Output "--- DNS Cache ---"
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 50
if ($dnsCache) {{
    $dnsCache | ForEach-Object {{
        Write-Output "  $($_.Entry) -> $($_.Data) (TTL: $($_.TimeToLive))"
    }}
}} else {{
    Write-Output "  DNS cache empty or unavailable"
}}
Write-Output ""

Write-Output "--- Current Listening Ports ---"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {{
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "  :$($_.LocalPort) [PID:$($_.OwningProcess) $($proc.ProcessName)]"
}}

Write-Output ""
Write-Output "Monitoring completed at $(Get-Date)"
""".format(duration=duration)
    stdout, stderr, code = await run_ps_async(ps, timeout=duration + 60)
    return _text(stdout)


@tool(
    'fakenet_start',
    description='Start FakeNet-NG with WinRM-safe config (excludes management ports).',
    schema={'type': 'object',
     'properties': {'extra_excluded_ports': {'type': 'string',
                                             'description': 'Comma-separated additional ports to '
                                                            'exclude',
                                             'default': ''}},
     'required': []},
    timeout=120,
    category='network',
)
async def _handle_fakenet_start(args):
    extra = args.get("extra_excluded_ports", "")
    excluded = [5985, 5986, 445, 139, 13337]
    if extra:
        for p in extra.split(","):
            p = p.strip()
            if p.isdigit():
                excluded.append(int(p))

    # Determine the analyst (Kali) host IP from the live WinRM connection so the
    # FakeNet HostBlackList actually shields it. The previous code passed the
    # port list positionally as kali_ip, producing an invalid HostBlackList.
    kali_ip = None
    try:
        ip_out, _, _ = await run_ps_async(
            "(Get-NetTCPConnection -LocalPort 5985 -State Established "
            "-ErrorAction SilentlyContinue | Select-Object -First 1).RemoteAddress",
            timeout=15)
        ip_out = ip_out.strip().split("\n")[0].strip()
        if ip_out.count(".") == 3:
            kali_ip = ip_out
    except Exception:
        kali_ip = None

    # ── Option C: idempotent default-gateway + DNS self-heal ──────────────────
    # FakeNet-NG 3.5 requires a default route for its WFP diverter to classify
    # traffic as "external". Without one it prints "No gateways configured" and
    # only intercepts localhost traffic. We add a fake next-hop derived from the
    # VM's own IP (replace last octet with .1 — works for any /8–/30 setup).
    # The fake GW doesn't need to be reachable; FakeNet's kernel hook fires first.
    # Both ActiveStore (immediate) and persistent via `route -p` (survives
    # reboot/snapshot restore).
    ps_gw = r"""
# Use the existing default gateway if one already exists; otherwise derive one
# from the VM's primary IPv4 address (replace last octet with .1).
$existingGw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
               Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($existingGw -and $existingGw -ne '0.0.0.0') {
    # A real (or previously-added) gateway already routes external traffic.
    Write-Output "GW_OK: default route already present via $existingGw — no change needed"
} else {
    # Derive fake gateway from the VM's primary non-loopback IPv4 address.
    $vmIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } |
             Sort-Object InterfaceIndex | Select-Object -First 1).IPAddress
    if (-not $vmIp) {
        Write-Output "GW_WARN: could not determine VM IP — FakeNet may only intercept local traffic"
    } else {
        $octets = $vmIp -split '\.'
        $gw = "$($octets[0]).$($octets[1]).$($octets[2]).1"
        $ifIdx = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
                  Sort-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex
        New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIdx -NextHop $gw `
            -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        & route -p add 0.0.0.0 mask 0.0.0.0 $gw metric 1 | Out-Null
        # Verify
        $check = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                  Where-Object { $_.NextHop -eq $gw } | Select-Object -First 1)
        if ($check) {
            Write-Output "GW_ADDED: fake gateway $gw derived from VM IP $vmIp (active + persistent)"
        } else {
            Write-Output "GW_WARN: could not add default route via $gw — FakeNet may only intercept local traffic"
        }
    }
}
"""
    gw_out, gw_err, _ = await run_ps_async(ps_gw, timeout=20)
    gw_status = gw_out.strip().split("\n")[0].strip()

    config = generate_fakenet_config(kali_ip=kali_ip, excluded_ports=excluded)

    # Write config to FlareVM
    config_escaped = config.replace("'", "''")
    ps_write = """
New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null
@'
{config}
'@ | Out-File -FilePath "C:\\temp\\fakenet_mcp.ini" -Encoding ASCII
Write-Output "Config written to C:\\temp\\fakenet_mcp.ini"
""".format(config=config_escaped)
    stdout, stderr, code = await run_ps_async(ps_write, timeout=30)
    if code != 0:
        return _text("Failed to write FakeNet config: {} {}".format(stderr, stdout))

    # Clear stale capture artifacts so fakenet_stop reports only this run.
    await run_ps_async(
        'New-Item -ItemType Directory -Path "C:\\temp\\fakenet_logs" -Force | Out-Null; '
        'Remove-Item "C:\\temp\\fakenet_logs\\*" -Recurse -Force -ErrorAction SilentlyContinue',
        timeout=20)

    # Launch FakeNet directly via scheduled task — it needs the interactive
    # session for DNS/driver interception. (A .bat wrapper to redirect the
    # console is unreliable through Task Scheduler, so we collect FakeNet's
    # own pcap/dump artifacts in fakenet_stop instead.)
    fakenet_path = await resolve_tool_path("fakenet", "fakenet")
    result = await launch_gui_app(
        fakenet_path,
        arguments='-c "C:\\temp\\fakenet_mcp.ini"',
        task_name="MCP_FakeNet",
    )
    await asyncio.sleep(3)

    return _text("=== FakeNet-NG Started ===\n"
                 "Gateway pre-flight: {}\n"
                 "Config: C:\\temp\\fakenet_mcp.ini\n"
                 "Excluded ports: {}\n"
                 "Task: {}\n\n"
                 "FakeNet is now intercepting network traffic.\n"
                 "Use fakenet_stop to retrieve logs.".format(
                     gw_status,
                     ",".join(str(p) for p in excluded), result
                 ))


@tool(
    'fakenet_stop',
    description='Stop FakeNet-NG and retrieve captured logs.',
    schema={'type': 'object', 'properties': {}, 'required': []},
    timeout=60,
    category='network',
)
async def _handle_fakenet_stop(args):
    ps = r"""
# Stop the scheduled task and the FakeNet process tree. FakeNet-NG runs as a
# PyInstaller bundle named fakenet.exe; the .bat launcher may have spawned it.
Unregister-ScheduledTask -TaskName "MCP_FakeNet" -Confirm:$false -ErrorAction SilentlyContinue
Stop-Process -Name "fakenet*" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Output "=== FakeNet-NG Stopped ==="
Write-Output ""

# FakeNet-NG writes a packet capture (packets_*.pcap) and HTTP POST dumps to
# its working directory. Launched via Task Scheduler that CWD is System32, so
# sweep the likely locations for artifacts from the last 15 minutes.
$cutoff = (Get-Date).AddMinutes(-15)
$searchDirs = @("C:\temp\fakenet_logs", "C:\temp", "C:\Windows\System32",
                "C:\Tools\fakenet\fakenet3.5",
                "$env:LOCALAPPDATA\FakeNet-NG",
                "$env:USERPROFILE\Desktop")
$artifacts = foreach ($d in $searchDirs) {
    Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $cutoff -and
            ($_.Name -match 'packets_.*\.pcap$' -or $_.Name -match '^(http|nbns|dns|fakenet).*\.(txt|log|html)$') }
}
if ($artifacts) {
    Write-Output "--- Captured FakeNet Artifacts ---"
    $artifacts | Sort-Object LastWriteTime -Descending | ForEach-Object {
        Write-Output "  $($_.FullName) - $($_.Length) bytes - $($_.LastWriteTime)"
    }
    # Move the pcap(s) into the log dir for easy retrieval/download.
    New-Item -ItemType Directory -Path "C:\temp\fakenet_logs" -Force | Out-Null
    $artifacts | Where-Object { $_.Name -match 'packets_.*\.pcap$' } | ForEach-Object {
        Move-Item $_.FullName -Destination "C:\temp\fakenet_logs\" -Force -ErrorAction SilentlyContinue
    }
    Write-Output ""
    Write-Output "PCAP(s) moved to C:\temp\fakenet_logs\ (use download_file to retrieve)."
} else {
    Write-Output "No FakeNet capture artifacts found in the last 15 min."
    Write-Output "Tip: FakeNet writes packets_*.pcap to its working directory (often"
    Write-Output "C:\Tools\fakenet\fakenet3.5\ or C:\Windows\System32 when run via Task Scheduler)."
    Write-Output "DNS interception is confirmed working; PCAP capture requires the WFP"
    Write-Output "diverter to log traffic from an interactive-session process, not WinRM session 0."
}
"""
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


@tool(
    'wireshark_capture',
    description='Start/stop packet capture with tshark.',
    schema={'type': 'object',
     'properties': {'action': {'type': 'string',
                               'description': 'start or stop',
                               'enum': ['start', 'stop']},
                    'duration': {'type': 'integer',
                                 'description': 'Capture duration in seconds (for start)',
                                 'default': 60},
                    'output_path': {'type': 'string',
                                    'description': 'PCAP output path',
                                    'default': 'C:\\temp\\capture.pcap'},
                    'interface': {'type': 'string',
                                  'description': 'Capture interface (default 1)',
                                  'default': '1'}},
     'required': ['action']},
    timeout=120,
    category='network',
)
async def _handle_wireshark_capture(args):
    action = args["action"]
    output_path = args.get("output_path", "C:\\temp\\capture.pcap")
    out_q = ps_path(output_path, "output_path")
    interface = ps_ident(args.get("interface", "1"), "interface")

    if action == "start":
        duration = ps_int(args.get("duration", 60), 1, 3600, "duration")
        # Find tshark
        ps_find = """
$paths = @("C:\\ProgramData\\chocolatey\\bin\\tshark.exe", "C:\\Program Files\\Wireshark\\tshark.exe")
foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; exit 0 } }
$w = where.exe tshark 2>$null | Select-Object -First 1
if ($w) { Write-Output $w } else { Write-Output "NOT_FOUND" }
"""
        tshark_stdout, _, _ = await run_ps_async(ps_find, timeout=15)
        tshark_path = tshark_stdout.strip().split("\n")[0].strip()
        if tshark_path == "NOT_FOUND":
            return _text("tshark not found on FlareVM")

        argl = "-i {} -w {} -a duration:{}".format(interface, win_arg(output_path, "output_path"), duration)
        ps = 'Start-Process -FilePath {} -ArgumentList {} -NoNewWindow -PassThru | Select-Object Id | Format-List'.format(
            ps_quote(tshark_path), ps_quote(argl))
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        return _text("=== Packet Capture Started ===\n"
                     "Interface: {}\nDuration: {}s\nOutput: {}\n{}".format(
                         interface, duration, output_path, stdout
                     ))
    else:  # stop
        ps = """
$p = {path}
Stop-Process -Name "tshark" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "dumpcap" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path -LiteralPath $p) {{
    $size = (Get-Item -LiteralPath $p).Length
    Write-Output "=== Packet Capture Stopped ==="
    Write-Output "File: $p"
    Write-Output "Size: $size bytes"
}} else {{
    Write-Output "Capture stopped but PCAP file not found at $p"
}}
""".format(path=out_q)
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        return _text(stdout)