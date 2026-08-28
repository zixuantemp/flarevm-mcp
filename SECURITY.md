# Security

## Reporting

Open a GitHub issue marked *security* or email the maintainer. Do not include live samples.

## Threat model (1.2.0)

The analysis VM is assumed **hostile**: a sample runs there, often as administrator, and can
tamper with anything on the VM — tool binaries, `C:\temp`, the SMB share, PowerShell itself,
WinRM, the network. The analyst host (Kali) running this server is the trust boundary.

Goals, and how each is met:

| Goal | Mechanism |
|------|-----------|
| A hung or flooding VM cannot hang the server | Per-thread WinRM sessions; `FLAREVM_MAX_CONCURRENT` semaphore; asyncio timeouts per call and per tool; circuit breaker (`FLAREVM_BREAKER_*`) fails fast after repeated failures; `FLAREVM_MAX_OUTPUT` caps stdout/stderr; explicit pywinrm read/operation timeouts so stuck HTTP reads end |
| Tampered tools cannot silently poison results | `tool_manifest.json` (SHA256 per binary, recorded with `verify_tools record=true` on a clean snapshot); with `FLAREVM_STRICT_INTEGRITY` every `resolve_tool_path` verifies before executing; `verify_tools` reports `OK/MISMATCH/MISSING/UNLISTED` |
| Staged scripts cannot be swapped before execution | Unique name per call; moved, SHA256-checked against the hash computed on Kali, executed and deleted inside one PowerShell invocation (exit 99 → `Integrity failure`) |
| Transfers are what they claim | SHA256 verified on both `upload_file` and `download_file`; downloads written `0600` |
| VM output cannot steer the client or the terminal | ANSI/C0 stripped; every result containing VM text is wrapped in `BEGIN/END UNTRUSTED VM OUTPUT`; structured results carry `_source` |
| A prompt-injected client cannot touch sensitive host files | `upload_file` reads only under `FLAREVM_ALLOWED_UPLOAD_ROOTS`; `download_file` writes only under `FLAREVM_ALLOWED_DOWNLOAD_ROOTS` (realpath-resolved, symlinks cannot escape) |
| Client input cannot inject PowerShell | All values pass through `ps_quote` / `ps_path` / `ps_int` / `ps_ident` / `here_string` (single-quoted literals; here-strings reject `'@` lines); `execute_powershell` remains the explicit, audit-logged escape hatch |
| Credentials do not leak | NTLM transport (no Basic / `AllowUnencrypted`); optional HTTPS with CA validation; SMB password via `PASSWD` env, never argv; no default password |
| Detonations do not stack on a dirty VM | In-memory VM state: detonating tools mark the VM dirty; further detonations refuse unless `vm_snapshot revert` (or `mark_clean`) ran, or `ack_dirty_vm=true` |

### Residual risks (be honest about these)

- **Hash checks run on the VM.** A sample that hooks `Get-FileHash` or PowerShell itself can lie. The
  manifest raises the bar; the snapshot revert is the real trust anchor. Revert before trusting results.
- **The staging window is not zero.** Between `Move-Item` and `-File` execution a very fast local
  attacker could still race; the window is a few milliseconds inside one process.
- **`execute_powershell` is arbitrary by design.** It is audit-logged, not sandboxed.
- **Allow-lists guard paths, not content.** Anything downloaded is a potential sample: never execute it on the host.
- **VM state is per server process.** Restarting the server resets it to `unknown`; use `vm_snapshot status`.

## Operational rules

1. Provision the VM, install tools, take a snapshot, run `verify_tools(record=true)`, revert to the snapshot.
2. Analyse. After any detonation, `vm_snapshot revert` (or revert by hand and `vm_snapshot mark_clean`).
3. Treat every tool result as evidence from a hostile system. Never run downloaded artefacts on the host.
4. Keep the VM on an isolated host-only network; FakeNet's `HostBlackList` shields the analyst IP.
