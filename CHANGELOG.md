# Changelog

## 1.1.0 — 2026-08-27

### Breaking
- `FLAREVM_HOST` is **required**. The server no longer defaults to `192.168.100.10`; it refuses
  to start without an address (clear error instead of a silent WinRM timeout against a stale IP).
  Set it in the MCP client's `env` block or in `.env` next to `server.py`.

### Added
- `.env` support (zero-dependency): `KEY=VALUE` lines next to `server.py`, never overriding the
  process environment. `setup.py` writes it; `.env.example` documents it.
- `KALI_IP` override, and automatic detection of the analyst-host address used for FakeNet's
  `HostBlackList` (the local address that routes to `FLAREVM_HOST`). `generate_fakenet_config`
  now fails rather than write an unsafe blacklist.
- Documentation split: lean `README.md` plus `docs/INSTALLATION.md`, `docs/CONFIGURATION.md`,
  `docs/USAGE.md`, `docs/TOOLS.md` (all 52 MCP tools), `docs/TROUBLESHOOTING.md`.
- CI: configuration-contract test (importable without config, refuses to serve without
  `FLAREVM_HOST`, `.env` precedence, no private-range IP literals) and a `docs/TOOLS.md` ↔
  `list_tools()` sync check.

### Fixed
- README MCP snippet used `mcp_servers` / `~/.claude/claude.json`; correct is `mcpServers` /
  `~/.claude.json`. Removed the non-existent `mcp_client` Python examples and duplicated
  reference/security sections.
- `install.sh` / `setup.py` no longer pre-fill a stale lab IP.
- Lint: `raise … from exc` in the IDA/WinDbg RPC error paths; explicit `zip(strict=False)`.

## 1.0.0 — 2026-04-17
- Initial release: 48 tools, MCP prompts/resources, guided installer, WinDbg integration.
