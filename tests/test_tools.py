"""Handler-level tests through dispatch: quoting, validation, structured output."""
import json

import pytest

import flarevm_mcp.tools  # noqa: F401
from flarevm_mcp import config, registry as r
from flarevm_mcp.psquote import UNTRUSTED_BEGIN


def call(run, name, args):
    return run(r.dispatch(name, args))


def test_all_tools_have_schema_and_timeout():
    for spec in r.specs():
        assert spec.schema["type"] == "object", spec.name
        assert spec.timeout > 0 and spec.description


def test_read_file_quotes_hostile_path(fake_vm, run):
    hostile = "C:\\temp\\a'; Remove-Item C:\\ -Recurse #$(calc)"
    fake_vm.respond("content")
    res = call(run, "read_file", {"file_path": hostile})
    script = fake_vm.last
    assert "$path = 'C:\\temp\\a''; Remove-Item C:\\ -Recurse #$(calc)'" in script
    assert res[0].text.startswith(UNTRUSTED_BEGIN) and "content" in res[0].text


def test_read_file_rejects_bad_args(fake_vm, run):
    with pytest.raises(r.ToolError, match="invalid file_path"):
        call(run, "read_file", {"file_path": "C:\\a\nb"})
    with pytest.raises(r.ToolError, match="encoding"):
        call(run, "read_file", {"file_path": "C:\\a", "encoding": "utf-8; calc"})


def test_get_file_hash_json_and_text(fake_vm, run):
    payload = json.dumps({"file": "C:\\s", "size": 3, "md5": "m", "sha1": "s1", "sha256": "s2"})
    fake_vm.respond(payload)
    d = call(run, "get_file_hash", {"file_path": "C:\\s", "format": "json"})
    assert d["sha256"] == "s2"
    fake_vm.respond(payload)
    t = call(run, "get_file_hash", {"file_path": "C:\\s"})[0].text
    assert "SHA256: s2" in t
    assert "-LiteralPath $path" in fake_vm.last


def test_list_processes_filter_validation(fake_vm, run):
    fake_vm.respond("tbl")
    call(run, "list_processes", {"filter": "mal*"})
    assert "Get-Process -Name 'mal*'" in fake_vm.last
    with pytest.raises(r.ToolError, match="invalid filter"):
        call(run, "list_processes", {"filter": "x'); calc; ('"})


def test_check_connection_resets_breaker(fake_vm, run):
    from flarevm_mcp.winrm_client import breaker
    breaker.failure("x")
    fake_vm.respond(json.dumps({"hostname": "VM", "os": "Win", "ip": "10.0.0.2", "uptime_s": 90000, "user": "u"}))
    t = call(run, "check_connection", {})[0].text
    assert "Hostname: VM" in t and "1d 1h" in t and not t.startswith(UNTRUSTED_BEGIN)
    assert breaker.failures == 0


def test_execute_powershell_is_audited(fake_vm, run, caplog):
    fake_vm.respond("hi", "", 0)
    with caplog.at_level("INFO", logger="flarevm-mcp.audit"):
        t = call(run, "execute_powershell", {"command": "Get-Date"})[0].text
    assert "Exit Code: 0" in t
    assert any("execute_powershell sha256=" in m for m in caplog.messages)


def test_static_tools_quote_paths(fake_vm, run):
    hostile = "C:\\s'a$(x).exe"
    fake_vm.respond("C:\\Tools\\die\\diec.exe")   # resolve_tool_path
    fake_vm.respond("PE64 packer")                 # die
    call(run, "die_analyze", {"file_path": hostile})
    assert "'C:\\s''a$(x).exe'" in fake_vm.last and '"{}"'.format(hostile) not in fake_vm.last


def test_procmon_and_process_info_validate(fake_vm, run):
    with pytest.raises(r.ToolError):
        call(run, "process_hacker_info", {"pid": "1; calc"})
    with pytest.raises(r.ToolError, match="invalid output_path"):
        call(run, "procmon_start", {"output_path": "C:\\a\x00b"})


def test_detonation_guard_via_tool(fake_vm, run, monkeypatch):
    from flarevm_mcp import integrity
    st = integrity.VMState()
    monkeypatch.setattr(integrity, "vm_state", st)
    monkeypatch.setattr(config, "REQUIRE_CLEAN_SNAPSHOT", True)
    st.mark_dirty("earlier sample")
    with pytest.raises(r.ToolError, match="DIRTY"):
        call(run, "execute_with_monitoring", {"executable": "C:\\temp\\b.exe"})


def test_docs_render_lists_every_tool():
    from flarevm_mcp.docs import render
    md = render()
    for spec in r.specs():
        assert "`{}`".format(spec.name) in md
