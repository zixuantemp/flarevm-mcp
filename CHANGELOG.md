# Changelog

## 1.2.0 — 2026-08-28 (hardening release)

Threat model: a sample running on FlareVM must not be able to compromise the
availability or integrity of this tool, and VM-produced data must never be able to
harm the analyst host or steer the client. See `SECURITY.md` and `docs/HARDENING_PLAN.md`.

### Breaking
- `setup.py` is now `flarevm_setup.py` (setuptools executed the installer during `pip install -e .`).
- No default password: the server refuses to start unless the keyring or `FLAREVM_PASSWORD` has one.
- `upload_file.local_path` must be under `FLAREVM_ALLOWED_UPLOAD_ROOTS` (default `~/Desktop:~/Downloads`);
  `download_file.local_path` must be under `FLAREVM_ALLOWED_DOWNLOAD_ROOTS` (default `~/Desktop/analysis`).
- Tool failures are real MCP errors (`isError=true`) instead of `ERROR:` text; tracebacks are logged, not returned.
- Every tool result that contains VM-produced text is wrapped in an explicit
  `BEGIN/END UNTRUSTED VM OUTPUT` envelope.
- `procmon_start.process_filter` and `get_file_hash.algorithm` (both previously ignored) were removed from the schemas.
- Detonating tools (`execute_with_monitoring`, `behavioral_full`, runtime path of `unpack_detect_and_try`) refuse to
  run on a VM that is already dirty since the last snapshot revert unless `ack_dirty_vm=true`.

### Added
- Ported to the `mcp` 2.x low-level API (`Server(on_list_tools=…, on_call_tool=…)`; tool input is
  validated in `dispatch`; progress via `ctx.session.report_progress`). Requires `mcp>=2.1`.
- `flarevm_mcp/` package with a single `@tool` registry (schema + timeout + handler + trust level in one place);
  `docs/TOOLS.md` is generated from it (`python -m flarevm_mcp.docs`, checked in CI). Root `server.py` is a shim.
- NTLM WinRM transport; optional HTTPS (`FLAREVM_WINRM_SCHEME=https`, `FLAREVM_CA_BUNDLE`).
- Availability: per-thread WinRM sessions, `FLAREVM_MAX_CONCURRENT` semaphore, circuit breaker
  (`FLAREVM_BREAKER_THRESHOLD/COOLDOWN`), hard output cap (`FLAREVM_MAX_OUTPUT`), explicit pywinrm read/operation timeouts.
- Integrity: `verify_tools` tool + `tool_manifest.json` (SHA256 of every analysis binary; `FLAREVM_STRICT_INTEGRITY`
  blocks tools whose binary changed); staged scripts are hash-verified, executed and deleted in one PowerShell
  invocation under a unique name; `download_file` now verifies SHA256 too.
- `vm_health` (breaker, VM disk/CPU/memory, WinRM service, MCP tasks, clean/dirty state) and `vm_snapshot`
  (list/revert/create/status via vmrun, VBoxManage, virsh or `FLAREVM_SNAPSHOT_*_CMD`).
- Every client-supplied value that reaches PowerShell goes through `ps_quote/ps_path/ps_int/ps_ident/here_string`
  (single-quoted literals; here-strings reject early terminators). ANSI/control characters are stripped from output.
- `format: "json"` on `check_connection`, `get_file_hash`, `list_processes`, `upload_file`, `download_file`,
  `verify_tools`, `vm_health` returns structured content.
- MCP progress notifications from `triage_full`, `behavioral_full`, `execute_with_monitoring`.
- `execute_powershell` is audit-logged (sha256, length, preview) on the analyst host.
- `pytest` suite (quoting, breaker, semaphore, registry, transfer, integrity, handlers) run in CI on 3.10–3.13.

### Fixed
- SMB password no longer appears on the `smbclient` command line (sent via `PASSWD`).
- Concurrent tool calls no longer share one non-thread-safe pywinrm session or collide on staged file names.
- `smbclient` runs as an async subprocess instead of blocking the event loop for up to 5 minutes.
- `check_connection` uses CIM only; `clientInfo.version` reflects the package version; README tool count.

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
