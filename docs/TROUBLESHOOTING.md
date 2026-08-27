# Troubleshooting

Work top-down: most failures are the address, then WinRM, then credentials, then the tool.

## Server does not start / vanishes from the MCP client

**`FLAREVM_HOST is not set`** — put it in the client's `env` block, export it, or copy
`.env.example` to `.env` next to `server.py`. There is no default by design.

**Import errors** — `pip install -e .` inside the same interpreter the client launches
(`command` in the MCP config must be that venv's `python3`).

## `check_connection` times out (~30 s), "VM busy"

Almost always a wrong or stale `FLAREVM_HOST`. Check the address, not the VM:

```bash
ping -c1 "$FLAREVM_HOST"
curl -s -o /dev/null -w '%{http_code}\n' "http://$FLAREVM_HOST:5985/wsman"   # 405 = healthy
```

- No ping → the VM is off, or on a different subnet than the analyst interface (`ip route get
  $FLAREVM_HOST` shows which interface would be used). Re-address one side; see
  [CONFIGURATION.md → Lab network](CONFIGURATION.md#lab-network).
- Ping but no 405 → WinRM is not listening. On the VM: `Enable-PSRemoting -Force` and the
  Basic/AllowUnencrypted settings in [INSTALLATION.md](INSTALLATION.md#prepare-the-vm-by-hand-if-you-skipped-setuppy),
  or re-run `python3 setup.py`.

## 401 / "the specified credentials were rejected"

Wrong password or the keyring entry is missing:

```bash
python3 -c "import keyring; print(bool(keyring.get_password('flarevm','xtemp')))"
python3 -c "import keyring; keyring.set_password('flarevm','xtemp','your-password')"
```

Or pass `FLAREVM_PASSWORD` explicitly. Remember the resolution order: env → keyring → `infected`.

## Uploads fail for files > 8 KB

Large transfers use SMB.

```bash
smbclient "//$FLAREVM_HOST/KaliShare" -U xtemp -c ls
```

- `smbclient: not found` → `sudo apt install smbclient`.
- `NT_STATUS_BAD_NETWORK_NAME` → the share does not exist; create it (INSTALLATION.md) or set
  `FLAREVM_SMB_SHARE` to the real name.
- Access denied → the share must grant the WinRM user (or Everyone) full access.
- Hash mismatch after upload → the VM disk is full; check `C:\temp`.

## FakeNet

**The session hangs right after `fakenet_start`** — FakeNet intercepted the server's own WinRM
or SMB traffic because `HostBlackList` got the wrong analyst IP. Set `KALI_IP` to the analyst
address on the VM-facing interface and restart.

**Sample shows no network activity** — FakeNet only diverts routed traffic. `fakenet_start`
adds a dead default route on the VM for this; confirm on the VM with
`Get-NetRoute -DestinationPrefix 0.0.0.0/0`. Also confirm FakeNet was started *before* detonation.

## "Tool not found" on the VM

The binary is missing or at a different path. Read `flarevm://tools/inventory` for a live
`Test-Path` of every tool, compare with
[../resources/tools-reference.md](../resources/tools-reference.md), and adjust `TOOL_PATHS` in
`server.py` or install the tool.

## `ida_*` tools fail

The IDA MCP plugin must be running **on the VM** and listening on `localhost:13337`
(`netstat -ano | findstr :13337` there). `ida_launch_and_wait` starts IDA but the plugin must be
installed. The same applies to WinDbg on `WINDBG_MCP_PORT` (13338).

## A tool timed out

The WinRM session is reset automatically. The VM state is unknown: call `list_processes`, kill
leftovers, or revert the snapshot before retrying. Long-running tools have larger budgets; see
`TOOL_TIMEOUTS` in `server.py`.
