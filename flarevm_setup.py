#!/usr/bin/env python3
"""
FlareVM MCP Setup — self-configuring, idempotent installer.

Run from the repo root after `git clone` and after the user has installed
FlareVM and enabled WinRM on the Windows VM:

    python3 flarevm_setup.py [--host IP] [--user USERNAME] [--share SHARENAME]

Steps performed:
  1. Prompt for FlareVM IP, username, password (or read from args/env)
  2. Store credentials in the system keyring
  3. Verify WinRM connectivity with a lightweight test
  4. Provision the FlareVM guest (idempotent):
       a. Create C:\\temp directory
       b. Create/verify SMB share (KaliShare -> C:\\temp)
       c. Set SMB share permissions for the MCP user
       d. Configure Windows Firewall to allow WinRM (5985) and SMB (445) from Kali
       e. Add fake default gateway derived from VM's own IP (subnet .1) if no gateway
          exists, so FakeNet-NG can intercept external traffic without a real internet path
       f. Verify key tool paths (DIE, CAPA, FLOSS, pe-sieve, hollows_hunter, FakeNet)
  5. Create a local .env file with non-secret config (host, user, share)
  6. Generate the Claude MCP client config snippet
"""

import argparse
import getpass
import json
import os
import subprocess
import sys
import textwrap
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HOST = None  # no default on purpose — the lab subnet is site-specific
DEFAULT_USER = "xtemp"
DEFAULT_SHARE = "KaliShare"
KEYRING_SERVICE = "flarevm"

# ── helpers ──────────────────────────────────────────────────────────────────

def _banner(msg):
    print("\n[*] " + msg)

def _ok(msg):
    print("    [+] " + msg)

def _warn(msg):
    print("    [!] " + msg)

def _err(msg):
    print("    [-] " + msg)

def _die(msg, hint=""):
    print("\nERROR: " + msg)
    if hint:
        print("       " + hint)
    sys.exit(1)


def _require_package(pkg, import_name=None):
    name = import_name or pkg
    try:
        __import__(name)
    except ImportError:
        _die(
            f"Python package '{pkg}' is not installed.",
            f"Run:  pip install {pkg}",
        )


# ── credential handling ───────────────────────────────────────────────────────

def store_credentials(user, password):
    import keyring
    keyring.set_password(KEYRING_SERVICE, user, password)
    _ok(f"Credentials stored in keyring (service='{KEYRING_SERVICE}', user='{user}')")


def get_stored_password(user):
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, user)
    except Exception:
        return None


# ── WinRM helpers ─────────────────────────────────────────────────────────────

def _winrm_session(host, user, password):
    import winrm
    return winrm.Session(
        host,
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
    )


def _run_ps(session, script, timeout=30):
    """Run a PowerShell snippet, return (stdout, stderr, exit_code)."""
    try:
        r = session.run_ps(script)
        return (
            r.std_out.decode("utf-8", errors="replace").strip(),
            r.std_err.decode("utf-8", errors="replace").strip(),
            r.status_code,
        )
    except Exception as e:
        return ("", str(e), 1)


# ── connectivity check ────────────────────────────────────────────────────────

def check_winrm(host, user, password):
    _banner(f"Testing WinRM connectivity → {host}:5985")
    _require_package("winrm", "winrm")

    session = _winrm_session(host, user, password)
    out, err, code = _run_ps(session, "$env:COMPUTERNAME + ' / ' + $env:OS")
    if code != 0:
        _err(f"WinRM connection failed: {err or out}")
        print(textwrap.dedent(f"""
          To enable WinRM on the Windows VM, run this in an elevated PowerShell:

              Enable-PSRemoting -Force
              # NTLM is enabled by default; Basic auth / AllowUnencrypted are NOT needed.
              Set-Item WSMan:\\localhost\\Service\\Auth\\Negotiate -Value $true
              netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985
              # Optional (recommended): HTTPS listener on 5986 — see docs/CONFIGURATION.md
        """).rstrip())
        return None
    _ok(f"WinRM OK: {out}")
    return session


# ── guest provisioning ────────────────────────────────────────────────────────

PROVISION_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$user  = '{user}'
$share = '{share}'
$path  = 'C:\temp'

# ── a) Create C:\temp ────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $path -Force | Out-Null
Write-Output "STEP_CTEMP: $(if (Test-Path $path) {{ 'OK' }} else {{ 'FAIL' }})"

# ── b) Create SMB share ───────────────────────────────────────────────────────
$existing = Get-SmbShare -Name $share -ErrorAction SilentlyContinue
if ($existing) {{
    Write-Output "STEP_SMB: EXISTS ($($existing.Path))"
}} else {{
    New-SmbShare -Name $share -Path $path -FullAccess "Everyone" | Out-Null
    $check = Get-SmbShare -Name $share -ErrorAction SilentlyContinue
    Write-Output "STEP_SMB: $(if ($check) {{ 'CREATED' }} else {{ 'FAIL' }})"
}}

# ── c) SMB share permissions ──────────────────────────────────────────────────
Grant-SmbShareAccess -Name $share -AccountName "Everyone" -AccessRight Full -Force | Out-Null
Write-Output "STEP_SMB_PERM: OK"

# ── d) Firewall — allow WinRM + SMB from any host on the subnet ───────────────
$rules = Get-NetFirewallRule -DisplayName "MCP-WinRM" -ErrorAction SilentlyContinue
if (-not $rules) {{
    New-NetFirewallRule -DisplayName "MCP-WinRM" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 5985 | Out-Null
}}
$rules = Get-NetFirewallRule -DisplayName "MCP-SMB" -ErrorAction SilentlyContinue
if (-not $rules) {{
    New-NetFirewallRule -DisplayName "MCP-SMB" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 445 | Out-Null
}}
Write-Output "STEP_FW: OK"

# ── e) Fake default gateway for FakeNet external interception ─────────────────
# Use existing gateway if one exists; otherwise derive from VM's own IP (.1 of subnet).
$existingGw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
               Sort-Object RouteMetric | Select-Object -First 1).NextHop
if ($existingGw -and $existingGw -ne '0.0.0.0') {{
    & route -p add 0.0.0.0 mask 0.0.0.0 $existingGw metric 1 2>&1 | Out-Null
    Write-Output "STEP_GW: EXISTS via $existingGw (persistent entry ensured)"
}} else {{
    $vmIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object {{ $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' }} |
             Sort-Object InterfaceIndex | Select-Object -First 1).IPAddress
    if (-not $vmIp) {{
        Write-Output "STEP_GW: WARN - could not determine VM IP"
    }} else {{
        $octets = $vmIp -split '\.'
        $gw     = "$($octets[0]).$($octets[1]).$($octets[2]).1"
        $ifIdx  = (Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} |
                   Sort-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex
        New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIdx -NextHop $gw `
            -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        & route -p add 0.0.0.0 mask 0.0.0.0 $gw metric 1 | Out-Null
        $check = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                  Where-Object {{ $_.NextHop -eq $gw }} | Select-Object -First 1)
        Write-Output "STEP_GW: $(if ($check) {{ 'ADDED fake gateway ' + $gw + ' derived from VM IP ' + $vmIp }} else {{ 'FAIL' }})"
    }}
}}

# ── f) Verify key tool paths ──────────────────────────────────────────────────
$tools = @{{
    'die'            = @('C:\Tools\die\die.exe',
                         'C:\ProgramData\chocolatey\bin\die.exe')
    'capa'           = @('C:\Tools\capa\capa.exe',
                         'C:\ProgramData\chocolatey\bin\capa.exe')
    'floss'          = @('C:\Tools\floss\floss.exe',
                         'C:\ProgramData\chocolatey\bin\floss.exe')
    'pe-sieve'       = @('C:\ProgramData\chocolatey\bin\pe-sieve.exe',
                         'C:\ProgramData\chocolatey\lib\pesieve\tools\pe-sieve.exe')
    'hollows_hunter' = @('C:\Tools\hollows_hunter\hollows_hunter.exe')
    'fakenet'        = @('C:\Tools\fakenet\fakenet3.5\fakenet.exe')
    'procmon'        = @('C:\Tools\Procmon\Procmon64.exe',
                         'C:\Tools\SysinternalsSuite\Procmon64.exe')
    'x64dbg'         = @('C:\Tools\x64dbg\release\x64\x64dbg.exe')
    'dnspy'          = @('C:\Tools\dnSpy\dnSpy.Console.exe')
    'wireshark'      = @('C:\Program Files\Wireshark\Wireshark.exe',
                         'C:\ProgramData\chocolatey\bin\wireshark.exe')
}}
$toolPaths = @{{}}
foreach ($t in $tools.Keys) {{
    $found = $null
    foreach ($p in $tools[$t]) {{
        if (Test-Path $p) {{ $found = $p; break }}
    }}
    if (-not $found) {{
        # Last resort: PATH lookup (PS 5.1 compatible — no ?. operator)
        $cmd = Get-Command $t -ErrorAction SilentlyContinue
        if ($cmd) {{ $found = $cmd.Source }}
    }}
    $toolPaths[$t] = if ($found) {{ $found }} else {{ 'NOT_FOUND' }}
}}
Write-Output "STEP_TOOLS_BEGIN"
foreach ($k in ($toolPaths.Keys | Sort-Object)) {{
    Write-Output "  $k : $($toolPaths[$k])"
}}
Write-Output "STEP_TOOLS_END"

# ── g) Install missing tools ──────────────────────────────────────────────────

# NirCmd (used by take_screenshot)
$nircmd = Get-Command nircmd -ErrorAction SilentlyContinue
if (-not $nircmd) {{
    Write-Output "STEP_NIRCMD: INSTALLING"
    choco install nircmd -y --no-progress 2>&1 | Out-Null
    $nircmd2 = Get-Command nircmd -ErrorAction SilentlyContinue
    Write-Output "STEP_NIRCMD: $(if ($nircmd2) {{ 'OK' }} else {{ 'FAIL - install nircmd manually' }})"
}} else {{
    Write-Output "STEP_NIRCMD: EXISTS"
}}

# Process Hacker / System Informer (used by process_hacker_info)
$phPaths = @(
    'C:\Program Files\Process Hacker 2\ProcessHacker.exe',
    'C:\Program Files\SystemInformer\SystemInformer.exe',
    'C:\Tools\ProcessHacker\ProcessHacker.exe'
)
$phFound = $null
foreach ($pp in $phPaths) {{ if (Test-Path $pp) {{ $phFound = $pp; break }} }}
if ($phFound) {{
    Write-Output "STEP_PROCESSHACKER: EXISTS $phFound"
}} else {{
    Write-Output "STEP_PROCESSHACKER: INSTALLING"
    choco install processhacker -y --no-progress 2>&1 | Out-Null
    foreach ($pp in $phPaths) {{ if (Test-Path $pp) {{ $phFound = $pp; break }} }}
    Write-Output "STEP_PROCESSHACKER: $(if ($phFound) {{ 'OK ' + $phFound }} else {{ 'FAIL - install Process Hacker manually' }})"
}}

# WinDbg (installs cdb.exe used by mcp-windbg)
$cdbPaths = @(
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe',
    'C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe',
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\cdbX64.exe"
)
$cdbFound = $null
foreach ($cp in $cdbPaths) {{ if (Test-Path $cp) {{ $cdbFound = $cp; break }} }}
if ($cdbFound) {{
    Write-Output "STEP_WINDBG: EXISTS $cdbFound"
}} else {{
    Write-Output "STEP_WINDBG: INSTALLING via winget"
    winget install Microsoft.WinDbg --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
    foreach ($cp in $cdbPaths) {{ if (Test-Path $cp) {{ $cdbFound = $cp; break }} }}
    Write-Output "STEP_WINDBG: $(if ($cdbFound) {{ 'OK ' + $cdbFound }} else {{ 'PENDING - reboot may be required to refresh WindowsApps PATH' }})"
}}

# mcp-windbg Python package (WinDbg MCP bridge)
Write-Output "STEP_MCP_WINDBG: UPGRADING"
pip install --upgrade mcp-windbg --quiet 2>&1 | Out-Null
$verLine = pip show mcp-windbg 2>&1 | Where-Object {{ $_ -match '^Version:' }}
Write-Output "STEP_MCP_WINDBG: $(if ($verLine) {{ 'OK ' + $verLine }} else {{ 'FAIL - pip install mcp-windbg failed' }})"

# ── h) Register mcp-windbg HTTP server as a login-time scheduled task ─────────
$taskName = 'MCP_WinDbg_Server'
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {{
    # Re-register if the existing task lacks Interactive LogonType (session-0 tasks
    # cannot launch cdbX64.exe from the Windows Store alias path).
    $needsUpdate = ($existingTask.Principal.LogonType -ne 'Interactive')
    if ($needsUpdate) {{
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $existingTask = $null
        Write-Output "STEP_WINDBG_SVC: UPDATING (LogonType was not Interactive)"
    }} else {{
        Write-Output "STEP_WINDBG_SVC: EXISTS (state: $($existingTask.State))"
    }}
}}
if (-not $existingTask) {{
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyCmd) {{ $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }}
    if ($pyCmd) {{
        $pyPath = $pyCmd.Source
    }} else {{
        $pyPath = 'python'
    }}
    $action    = New-ScheduledTaskAction -Execute $pyPath -Argument '-m mcp_windbg --transport streamable-http --port 13338'
    $trigger   = New-ScheduledTaskTrigger -AtLogon
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 `
                     -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    # Interactive LogonType is required: cdb.exe ships as a Windows Store app alias
    # (%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX64.exe) which only resolves in the
    # console user's session (session 1). SYSTEM / session-0 tasks get [WinError 5].
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    $regErr = $null
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force -ErrorVariable regErr | Out-Null
    if ($regErr) {{
        Write-Output "STEP_WINDBG_SVC: FAIL - $regErr"
    }} else {{
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $newTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Write-Output "STEP_WINDBG_SVC: REGISTERED (state: $($newTask.State), interpreter: $pyPath)"
    }}
}}
"""


def provision_guest(session, user, share):
    _banner("Provisioning FlareVM guest (idempotent)")
    script = PROVISION_SCRIPT.format(user=user, share=share)
    out, err, code = _run_ps(session, script)

    lines = out.splitlines()
    tool_lines = []
    in_tools = False
    for line in lines:
        if line.startswith("STEP_"):
            step, _, val = line.partition(": ")
            tag = step.replace("STEP_", "")
            if tag == "TOOLS_BEGIN":
                in_tools = True
            elif tag == "TOOLS_END":
                in_tools = False
            else:
                ok_words = ("OK", "EXISTS", "ADDED", "CREATED", "REGISTERED", "UPGRADING")
                status = "OK" if any(x in val for x in ok_words) else "WARN"
                if status == "OK":
                    _ok(f"{tag}: {val}")
                else:
                    _warn(f"{tag}: {val}")
        elif in_tools:
            tool_lines.append(line)

    if tool_lines:
        print("\n    Tool paths on FlareVM:")
        not_found = []
        for tl in tool_lines:
            parts = tl.strip().split(" : ", 1)
            if len(parts) == 2:
                name, path = parts
                if path == "NOT_FOUND":
                    not_found.append(name)
                    _warn(f"  {name:<18} NOT FOUND")
                else:
                    _ok(f"  {name:<18} {path}")
        if not_found:
            print(f"\n    Missing tools: {', '.join(not_found)}")
            print("    These tools must be installed in FlareVM for those MCP tools to work.")

    if err:
        _warn(f"Provisioning stderr: {err[:500]}")

    return code == 0


# ── SMB connectivity test from Kali ──────────────────────────────────────────

def check_smb(host, user, password, share):
    _banner(f"Testing SMB share \\\\{host}\\{share} from Kali")
    try:
        result = subprocess.run(
            ["smbclient", f"//{host}/{share}", "-U", f"{user}%{password}",
             "-c", "ls"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            _ok("SMB share accessible from Kali")
            return True
        else:
            _warn(f"SMB access failed: {result.stderr.strip()[:200]}")
            return False
    except FileNotFoundError:
        _warn("smbclient not found — install with: sudo apt install smbclient")
        return False
    except subprocess.TimeoutExpired:
        _warn("SMB connection timed out")
        return False


# ── local config ─────────────────────────────────────────────────────────────

def write_env(host, user, share, env_path):
    content = (
        f"FLAREVM_HOST={host}\n"
        f"FLAREVM_USER={user}\n"
        f"FLAREVM_SMB_SHARE={share}\n"
    )
    with open(env_path, "w") as f:
        f.write(content)
    _ok(f"Config written to {env_path}")


def generate_mcp_snippet(host, user, share, venv_python, server_path):
    snippet = {
        "mcpServers": {
            "flarevm": {
                "command": venv_python,
                "args": [server_path],
                "env": {
                    "FLAREVM_HOST": host,
                    "FLAREVM_USER": user,
                    "FLAREVM_SMB_SHARE": share,
                }
            }
        }
    }
    return json.dumps(snippet, indent=2)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="FlareVM MCP self-configuring setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--host",  default=None, help=f"FlareVM IP (default: {DEFAULT_HOST})")
    p.add_argument("--user",  default=None, help=f"Windows username (default: {DEFAULT_USER})")
    p.add_argument("--share", default=None, help=f"SMB share name (default: {DEFAULT_SHARE})")
    p.add_argument("--password", default=None,
                   help="Password (omit to prompt; keyring is used for storage)")
    p.add_argument("--skip-provision", action="store_true",
                   help="Skip guest-side provisioning (just store creds + gen config)")
    p.add_argument("--venv", default=None,
                   help="Path to Python venv to use (default: auto-detect)")
    args = p.parse_args()

    _require_package("winrm", "winrm")
    _require_package("keyring", "keyring")

    print("=" * 60)
    print("  FlareVM MCP — self-configuring setup")
    print("=" * 60)

    # ── 1. credentials ────────────────────────────────────────────────────────
    _banner("Credentials")
    host  = args.host  or os.environ.get("FLAREVM_HOST", DEFAULT_HOST)
    user  = args.user  or os.environ.get("FLAREVM_USER", DEFAULT_USER)
    share = args.share or os.environ.get("FLAREVM_SMB_SHARE", DEFAULT_SHARE)

    host  = input(f"  FlareVM IP [{host or 'required'}]: ").strip() or host
    while not host:
        host = input("  FlareVM IP (required): ").strip()
    user  = input(f"  Windows username [{user}]: ").strip() or user
    share = input(f"  SMB share name [{share}]: ").strip() or share

    password = args.password or get_stored_password(user)
    if password:
        use_stored = input(
            f"  Found stored password for '{user}'. Use it? [Y/n]: "
        ).strip().lower()
        if use_stored in ("n", "no"):
            password = None
    if not password:
        password = getpass.getpass(f"  Password for {user}@{host}: ")
    if not password:
        _die("Password is required.")

    store_credentials(user, password)

    # ── 2. WinRM connectivity ─────────────────────────────────────────────────
    session = check_winrm(host, user, password)
    if session is None:
        _die(
            "Cannot reach FlareVM over WinRM.",
            "Enable WinRM on the VM (see instructions above), then re-run flarevm_setup.py.",
        )

    # ── 3. Guest provisioning ─────────────────────────────────────────────────
    if not args.skip_provision:
        provision_guest(session, user, share)
        time.sleep(1)
        check_smb(host, user, password, share)
    else:
        _banner("Skipping guest provisioning (--skip-provision)")

    # ── 4. Local env + MCP config ─────────────────────────────────────────────
    _banner("Generating local configuration")

    env_path = os.path.join(SCRIPT_DIR, ".env")
    write_env(host, user, share, env_path)

    # Find venv python
    if args.venv:
        venv_python = os.path.join(args.venv, "bin", "python3")
    else:
        venv_candidates = [
            os.path.join(SCRIPT_DIR, "venv", "bin", "python3"),
            os.path.expanduser("~/.flarevm-mcp/venv/bin/python3"),
            os.path.expanduser("~/Desktop/venv/bin/python3"),
        ]
        venv_python = next((v for v in venv_candidates if os.path.isfile(v)), sys.executable)

    server_path = os.path.join(SCRIPT_DIR, "server.py")
    snippet = generate_mcp_snippet(host, user, share, venv_python, server_path)

    mcp_config_path = os.path.expanduser("~/.claude/.mcp.json")
    claude_dir = os.path.dirname(mcp_config_path)

    if os.path.isfile(mcp_config_path):
        try:
            with open(mcp_config_path) as f:
                existing = json.load(f)
        except json.JSONDecodeError:
            existing = {}
        existing.setdefault("mcpServers", {})["flarevm"] = json.loads(snippet)["mcpServers"]["flarevm"]
        with open(mcp_config_path, "w") as f:
            json.dump(existing, f, indent=2)
        _ok(f"Updated 'flarevm' entry in {mcp_config_path}")
    else:
        if os.path.isdir(claude_dir):
            with open(mcp_config_path, "w") as f:
                f.write(snippet)
            _ok(f"Wrote MCP config to {mcp_config_path}")
        else:
            _warn(f"{claude_dir} not found — copy the snippet below manually")

    print("\n" + "=" * 60)
    print("  MCP config snippet (add to ~/.claude/.mcp.json or")
    print("  claude_desktop_config.json → mcpServers):")
    print("=" * 60)
    print(snippet)
    print("=" * 60)
    print("\n[*] Setup complete.  Start a new Claude Code session to use flarevm tools.")


if __name__ == "__main__":
    main()
