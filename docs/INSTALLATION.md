# Installation

## Requirements

**Analyst host** (Kali or any Linux; macOS/WSL work for pip installs)
- Python 3.10+
- `smbclient` (`sudo apt install smbclient`) — only for transfers > 8 KB
- A network interface on the same isolated segment as the VM (see
  [CONFIGURATION.md → Lab network](CONFIGURATION.md#lab-network))

**FlareVM** (Windows 10/11 with [FlareVM](https://github.com/mandiant/flare-vm) installed)
- WinRM enabled (NTLM over HTTP 5985 is the default; HTTPS 5986 optional) — `flarevm_setup.py` does this for you
- SMB share `KaliShare` → `C:\Share` (optional; `flarevm_setup.py` creates it)
- The analysis binaries under `C:\Tools\…` listed in
  [../resources/tools-reference.md](../resources/tools-reference.md)
- IDA Pro + the [IDA MCP plugin](https://github.com/mandiant/ida-pro-mcp) only if you use the
  `ida_*` tools
- **No default gateway and no DNS.** The VM must be air-gapped; the server never needs it to
  reach anything but the analyst host.

## Install

### A. Guided (recommended)

```bash
git clone https://github.com/zixuantemp/flarevm-mcp.git
cd flarevm-mcp
pip install -e .            # or: python3 -m venv .venv && . .venv/bin/activate && pip install -e .
python3 flarevm_setup.py            # --host, --user, --share, --skip-provision are optional flags
```

`flarevm_setup.py` will:
1. prompt for the VM IP, Windows user and password, and store the password in your OS keyring
   (service `flarevm`);
2. test WinRM (NTLM), and if it is not enabled, print the `Enable-PSRemoting` + firewall steps to
   run on the VM;
3. create and verify the SMB share;
4. write `.env` next to `server.py` and print a ready-to-paste MCP client snippet.

### B. pip only (you configure everything yourself)

```bash
pip install git+https://github.com/zixuantemp/flarevm-mcp.git
cp .env.example .env        # or export FLAREVM_HOST=… in the client env block
flarevm-mcp                 # runs the server on stdio
```

### C. Docker

```bash
docker run -i --rm --env-file .env ghcr.io/zixuantemp/flarevm-mcp
# or:  -e FLAREVM_HOST=192.168.167.10 -e FLAREVM_USER=xtemp -e FLAREVM_PASSWORD=…
```
There is no keyring inside the container, so pass `FLAREVM_PASSWORD` explicitly.

## Prepare the VM by hand (if you skipped `flarevm_setup.py`)

Run as Administrator on the VM:

```powershell
# WinRM over HTTP with NTLM (enabled by default; Basic auth / AllowUnencrypted are NOT needed)
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985
# Optional, recommended: HTTPS listener on 5986 — see CONFIGURATION.md → Hardening settings

# SMB share for large transfers
New-Item -Path "C:\Share" -ItemType Directory -Force
New-SmbShare -Name "KaliShare" -Path "C:\Share" -FullAccess "Everyone"
```

## Register the MCP client

**Claude Code** — `~/.claude.json` (global) or `.mcp.json` in a project. The key is `mcpServers`
(camelCase):

```json
{
  "mcpServers": {
    "flarevm": {
      "command": "/path/to/venv/bin/python3",
      "args": ["/path/to/flarevm-mcp/server.py"],
      "env": { "FLAREVM_HOST": "192.168.167.10", "FLAREVM_USER": "xtemp" }
    }
  }
}
```

or, equivalently:

```bash
claude mcp add flarevm -e FLAREVM_HOST=192.168.167.10 -e FLAREVM_USER=xtemp -- /path/to/venv/bin/python3 /path/to/flarevm-mcp/server.py
```

If you rely on `.env` instead of the `env` block, the file must sit next to `server.py`.
Other MCP clients: point them at the same command; the transport is stdio.

## Verify

```bash
# 1. Module imports and configuration resolves (run from the repo directory)
python3 -c "import server; server._require_host(); print('host', server.FLAREVM_HOST, '| analyst IP', server._detect_kali_ip())"

# 2. The VM answers on WinRM — HTTP 405 on a bare GET is the healthy response
curl -s -o /dev/null -w 'WinRM -> HTTP %{http_code}\n' "http://$FLAREVM_HOST:5985/wsman"

# 3. (transfers > 8 KB) the share is reachable
smbclient "//$FLAREVM_HOST/KaliShare" -U xtemp -c ls
```

Then, from the MCP client, call `check_connection` — it returns the VM hostname, OS and IP.
Anything failing here: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Virtualenv isolation

flarevm-mcp requires the `mcp` 2.x SDK. Other MCP servers written against the 1.x API
(`mcp.server.fastmcp`, decorator-style `Server`) cannot coexist with it in one virtualenv, so keep
flarevm-mcp in its own dedicated virtualenv (`install.sh` uses `~/.flarevm-mcp/venv`) and point the
MCP client's `command` at that interpreter.
