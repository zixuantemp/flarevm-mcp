import json

import pytest

from flarevm_mcp import config, integrity as it
from flarevm_mcp.registry import ToolError


def test_compare_statuses():
    manifest = {"die": {"path": "C:\\d", "sha256": "aa"}, "capa": {"path": "C:\\c", "sha256": "bb"}, "gone": {"path": "C:\\g", "sha256": "cc"}}
    observed = {"die": ("C:\\d", "AA"), "capa": ("C:\\c", "zz"), "new": ("C:\\n", "dd"), "gone": ("C:\\g", None)}
    rep = it.compare(manifest, observed)
    assert rep["die"]["status"] == "OK"
    assert rep["capa"]["status"] == "MISMATCH"
    assert rep["new"]["status"] == "UNLISTED"
    assert rep["gone"]["status"] == "MISSING"


def test_verify_binary_blocks_on_mismatch(fake_vm, run, monkeypatch, tmp_path):
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps({"tools": {"die": {"path": "C:\\d", "sha256": "aa"}}}))
    monkeypatch.setattr(config, "TOOL_MANIFEST", str(mf))
    monkeypatch.setattr(config, "STRICT_INTEGRITY", True)
    it._verified.clear()
    fake_vm.respond("die|bb")
    with pytest.raises(ToolError, match="INTEGRITY FAILURE"):
        run(it.verify_binary("die", "C:\\d"))
    fake_vm.respond("die|aa")
    run(it.verify_binary("die", "C:\\d"))
    assert "die" in it._verified
    calls = len(fake_vm.calls)
    run(it.verify_binary("die", "C:\\d"))      # cached within TTL
    assert len(fake_vm.calls) == calls
    run(it.verify_binary("unlisted", "C:\\u"))  # not in manifest → no call
    assert len(fake_vm.calls) == calls


def test_verify_binary_noop_when_not_strict(fake_vm, run, monkeypatch):
    monkeypatch.setattr(config, "STRICT_INTEGRITY", False)
    run(it.verify_binary("die", "C:\\d"))
    assert fake_vm.calls == []


def test_write_manifest_roundtrip(tmp_path, monkeypatch):
    path = str(tmp_path / "tool_manifest.json")
    data = it.write_manifest({"die": ("C:\\d", "aa"), "missing": ("C:\\m", None)}, "VM", path)
    assert list(data["tools"]) == ["die"]
    assert it.load_manifest(path)["tools"]["die"]["sha256"] == "aa"


def test_detonation_guard(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_CLEAN_SNAPSHOT", True)
    st = it.VMState()
    monkeypatch.setattr(it, "vm_state", st)
    it.require_clean_for("behavioral_full", {})          # unknown → allowed
    st.mark_dirty("ran C:\\temp\\a.exe")
    with pytest.raises(ToolError, match="DIRTY"):
        it.require_clean_for("behavioral_full", {})
    it.require_clean_for("behavioral_full", {"ack_dirty_vm": True})
    st.mark_clean("revert")
    it.require_clean_for("behavioral_full", {})


def test_snapshot_command_custom_and_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "VM_ID", None)
    for k in ("SNAPSHOT_LIST_CMD", "SNAPSHOT_REVERT_CMD", "SNAPSHOT_CREATE_CMD"):
        monkeypatch.setattr(config, k, None)
    assert it.snapshot_command("revert", "clean") is None
    monkeypatch.setattr(config, "SNAPSHOT_REVERT_CMD", "vmrun revertToSnapshot {vm} {name}")
    monkeypatch.setattr(config, "VM_ID", "/vms/f.vmx")
    assert it.snapshot_command("revert", "clean") == ["vmrun", "revertToSnapshot", "/vms/f.vmx", "clean"]
