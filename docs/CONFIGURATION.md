# Configuration

Everything is read from the environment of the server process. Precedence:

1. variables already in the process environment (the MCP client's `env` block, `export`, Docker `-e`);
2. a `.env` file **next to `server.py`** — loaded at import, never overriding (1);
3. built-in defaults (where one exists).

No source edits are ever required. `setup.py` writes `.env` for you; a template is in
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

Use the keyring. `setup.py` stores it; by hand:

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
