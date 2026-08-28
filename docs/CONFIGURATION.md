# Configuration

Everything is read from the environment of the server process. Precedence:

1. variables already in the process environment (the MCP client's `env` block, `export`, Docker `-e`);
2. a `.env` file **next to `server.py`** — loaded at import, never overriding (1);
3. built-in defaults (where one exists).

No source edits are ever required. `flarevm_setup.py` writes `.env` for you; a template is in
[`.env.example`](../.env.example). `.env` is git-ignored.

## Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `FLAREVM_HOST` | **yes** | — | VM IP on the lab network. The server refuses to start without it; a hardcoded default would fail as a silent WinRM timeout whenever the subnet changes. |
| `FLAREVM_USER` | no | `xtemp` | Windows account for WinRM and SMB. |
| `FLAREVM_PASSWORD` | no | keyring, else `infected` | See [Credentials](#credentials). |
| `FLAREVM_SMB_SHARE` | no | `KaliShare` | Share name on the VM used for files > 8 KB. |
| `FLAREVM_SMB_LOCAL_PATH` | no | `C:\Share` | Directory backing that share on the VM. |
| `KALI_IP` | no | auto | Analyst-host IP written to FakeNet's `HostBlackList`. Auto-detected as the local address that routes to `FLAREVM_HOST`. Override only if the wrong interface is picked. |
| `WINDBG_MCP_PORT` | no | `13338` | WinDbg MCP proxy port on the VM. |

## Credentials

The password is resolved in this order: `FLAREVM_PASSWORD` env → OS keyring (service `flarevm`,
username = `FLAREVM_USER`) → the FlareVM default `infected`.

Use the keyring. `flarevm_setup.py` stores it; by hand:

```bash
python3 -c "import keyring; keyring.set_password('flarevm', 'xtemp', 'your-password')"
```

The password is never logged, echoed, or returned in a tool response. If you cannot use a keyring
(Docker), pass `FLAREVM_PASSWORD` explicitly.

## Lab network

The VM is **air-gapped by design**: an isolated host-only network, no default gateway, no DNS. The
server only ever needs the analyst host and the VM to see each other.

```
analyst host  eth1  192.168.167.50/24  ──host-only VMnet──  FlareVM  192.168.167.10/24  (no GW, no DNS)
```

- Put `FLAREVM_HOST` on that segment. Give the VM a static address; dynamic-DNS or DHCP leases
  drift and turn into "VM busy" timeouts.
- Keep the segment's subnet distinct from any real LAN the analyst host is bridged to —
  overlapping subnets silently misroute WinRM.
- WinRM is plaintext HTTP (5985) — acceptable only because of the isolation. Never expose it.

## FakeNet host protection

`fakenet_start` writes a FakeNet-NG config whose `HostBlackList` is the analyst host's IP, so the
VM never intercepts the server's own WinRM/SMB traffic. That IP is determined as:

1. the remote address of the live WinRM session, asked from the VM side (authoritative);
2. else `KALI_IP`;
3. else the local address the analyst host would route to `FLAREVM_HOST`;
4. else the tool fails rather than write an unsafe config.

FakeNet-NG only diverts *routed* traffic. Because the VM has no gateway, `fakenet_start` adds an
idempotent dead default route derived from the VM's own address (`x.x.x.1`) so outbound
connections reach the diverter, and removes nothing you configured yourself.

## Hardening settings (1.2.0)

All optional; defaults in `.env.example`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `FLAREVM_WINRM_SCHEME` / `FLAREVM_WINRM_PORT` | `http` / 5985 | `https` + 5986 to use a TLS listener |
| `FLAREVM_CA_BUNDLE` | — | CA file; with HTTPS enables certificate validation (otherwise a warning is logged) |
| `FLAREVM_MAX_CONCURRENT` | 4 | Concurrent WinRM operations |
| `FLAREVM_MAX_OUTPUT` | 1048576 | Bytes of stdout/stderr kept per call |
| `FLAREVM_READ_TIMEOUT` / `FLAREVM_OPERATION_TIMEOUT` | 60 / 30 | pywinrm HTTP timeouts (read must exceed operation) |
| `FLAREVM_BREAKER_THRESHOLD` / `FLAREVM_BREAKER_COOLDOWN` | 3 / 30 | Failures before failing fast, and for how long |
| `FLAREVM_TOOL_MANIFEST` | `./tool_manifest.json` | Where `verify_tools` reads/writes tool hashes |
| `FLAREVM_STRICT_INTEGRITY` | on if manifest exists | Block tools whose binary hash changed |
| `FLAREVM_ALLOWED_UPLOAD_ROOTS` | `~/Desktop:~/Downloads` | Where `upload_file` may read |
| `FLAREVM_ALLOWED_DOWNLOAD_ROOTS` | `~/Desktop/analysis` | Where `download_file` may write |
| `FLAREVM_VM_ID` | — | `.vmx` path (vmrun), VirtualBox name or libvirt domain for `vm_snapshot` |
| `FLAREVM_SNAPSHOT_LIST_CMD` / `_REVERT_CMD` / `_CREATE_CMD` | — | Custom commands with `{vm}` / `{name}` placeholders |
| `FLAREVM_CLEAN_SNAPSHOT` | `clean` | Snapshot name used by `revert`/`create` |
| `FLAREVM_REQUIRE_CLEAN_SNAPSHOT` | 1 | Detonation guard (`ack_dirty_vm=true` overrides per call) |
| `FLAREVM_REMOTE_TEMP` | `C:\temp` | Staging directory on the VM |

WinRM over HTTPS on the guest (elevated PowerShell):

```powershell
$c = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986
Export-Certificate -Cert $c -FilePath C:\Share\flarevm-ca.cer   # then convert to PEM on Kali for FLAREVM_CA_BUNDLE
```
