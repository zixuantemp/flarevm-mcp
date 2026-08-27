# FlareVM MCP Server

[![CI](https://github.com/zixuantemp/flarevm-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/zixuantemp/flarevm-mcp/actions/workflows/ci.yml)
[![Tools](https://img.shields.io/badge/MCP%20tools-52-blue)](docs/TOOLS.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io/) server that lets an AI agent (Claude Code or any MCP
client) drive an **isolated, air-gapped [FlareVM](https://github.com/mandiant/flare-vm)** from a
Linux analyst host. Static triage, detonation with monitoring, unpacking, debugging, Frida and IDA
Pro — 52 tools behind one interface, with the malware never leaving the VM.

```
Claude / MCP client ──stdio──▶ flarevm-mcp (Kali) ──WinRM 5985──▶ FlareVM (Windows, no network)
                                        └──SMB KaliShare──▶  files > 8 KB
                                        └──HTTP JSON-RPC───▶  IDA :13337 · WinDbg :13338 (VM-local)
```

## Quick start

```bash
git clone https://github.com/zixuantemp/flarevm-mcp.git && cd flarevm-mcp
pip install -e .            # deps: mcp, pywinrm, keyring, requests
python3 setup.py            # stores the VM password in your keyring, enables WinRM + the
                            # SMB share on the VM, writes .env, prints the MCP client snippet
```

Then paste the printed snippet into `~/.claude.json` (or a project `.mcp.json`) and run
`check_connection` from your client. Prefer a manual route? See
[docs/INSTALLATION.md](docs/INSTALLATION.md).

The only required setting is the VM address, `FLAREVM_HOST` — there is deliberately no default.
Copy [`.env.example`](.env.example) to `.env` or pass it in the client's `env` block.
All settings: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Documentation

| Doc | What it covers |
|-----|----------------|
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Requirements, install paths (setup script · pip · Docker), preparing the VM, registering the MCP client, verifying |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every environment variable, `.env`, credentials, lab-network layout, FakeNet host protection |
| [docs/USAGE.md](docs/USAGE.md) | Analysis workflows, the bundled prompts / resources / skills, safety rules |
| [docs/TOOLS.md](docs/TOOLS.md) | Reference for all 52 MCP tools |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptoms → causes → fixes |
| [resources/tools-reference.md](resources/tools-reference.md) | The Windows binaries the tools call on the VM, and their paths |
| [SECURITY.md](SECURITY.md) | Threat model, credential handling, reporting a vulnerability |

## MCP capabilities

- **52 tools** — connection & transfer, static analysis, monitoring & detonation, FakeNet,
  memory/injection scanning, unpacking, x64dbg/WinDbg, Frida, IDA Pro, and composite workflows.
- **5 prompts** — `triage_unknown_sample`, `behavioral_analysis`, `unpack_workflow`,
  `injection_hunt`, `persistence_audit_report`.
- **5 resources** — `flarevm://tools/inventory`, `flarevm://config/fakenet-default`,
  `flarevm://docs/yara-rules`, `flarevm://docs/cheatsheet`, `flarevm://status/connection`.
- **3 Claude Code skills** in [`skills/`](skills/) — `triage-malware-sample`,
  `incident-response-windows`, `automated-unpacking`.

## Security in one paragraph

The analyst host is trusted and never executes samples; the VM is hostile and assumed compromised
after any detonation — snapshot before, revert after. WinRM runs in plaintext **only** because the
VM sits on an isolated host-only network; never expose port 5985 beyond it. FakeNet's
`HostBlackList` shields the analyst host's own control traffic. Full model: [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. CI runs import/registration checks, `ruff`, and `bandit`
on every push; keep `docs/TOOLS.md` in sync when adding a tool (see the note at the end of that file).

## License

[MIT](LICENSE) — © 2026 zixuantemp.
