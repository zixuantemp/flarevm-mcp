# Installation

## Requirements

**Analyst host** (Kali or any Linux; macOS/WSL work for pip installs)
- Python 3.10+
- `smbclient` (`sudo apt install smbclient`) — only for transfers > 8 KB
- A network interface on the same isolated segment as the VM (see
  [CONFIGURATION.md → Lab network](CONFIGURATION.md#lab-network))

**FlareVM** (Windows 10/11 with [FlareVM](https://github.com/mandiant/flare-vm) installed)
- WinRM enabled with Basic auth over HTTP (5985) — `setup.py` does this for you
- SMB share `KaliShare` → `C:\Share` (optional; `setup.py` creates it)
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
python3 setup.py            # --host, --user, --share, --skip-provision are optional flags
```

`setup.py` will:
1. prompt for the VM IP, Windows user and password, and store the password in your OS keyring
   (service `flarevm`);
2. test WinRM, and if it is not enabled, enable it on the VM (`Enable-PSRemoting`, Basic auth,
   firewall rule for 5985);
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

## Prepare the VM by hand (if you skipped `setup.py`)

Run as Administrator on the VM:

```powershell
# WinRM over HTTP with Basic auth (plaintext — isolated network only)
Enable-PSRemoting -Force
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985

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
