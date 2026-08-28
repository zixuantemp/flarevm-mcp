import hashlib
import os

import pytest

from flarevm_mcp import config, transfer as tr
from flarevm_mcp.registry import ToolError


def test_check_local_path(tmp_path):
    root = str(tmp_path)
    inside = tmp_path / "a.bin"
    inside.write_bytes(b"x")
    assert tr.check_local_path(str(inside), [root], must_exist=True) == os.path.realpath(str(inside))
    with pytest.raises(tr.PathNotAllowed):
        tr.check_local_path("/etc/passwd", [root])
    with pytest.raises(tr.PathNotAllowed):
        tr.check_local_path(str(tmp_path) + "_sibling/x", [root])   # prefix trick
    link = tmp_path / "link"
    link.symlink_to("/etc/passwd")
    with pytest.raises(tr.PathNotAllowed):                          # realpath escapes root
        tr.check_local_path(str(link), [root])


def test_run_ps_script_inline_for_short(fake_vm, run):
    fake_vm.respond("ok")
    out, _, _ = run(tr.run_ps_script("Write-Output ok"))
    assert out == "ok" and fake_vm.last == "Write-Output ok"


def test_run_ps_script_stages_verifies_and_cleans(fake_vm, run, monkeypatch):
    puts = []

    async def fake_put(local, name):
        puts.append((open(local, "rb").read(), name))
    monkeypatch.setattr(tr, "smb_put", fake_put)
    script = "Write-Output 'x'\n" * 200
    fake_vm.respond("done")
    run(tr.run_ps_script(script, script_name="big.ps1"))
    data, name = puts[0]
    assert name.startswith("big_") and name.endswith(".ps1") and data == script.encode()
    runner = fake_vm.last
    assert hashlib.sha256(data).hexdigest() in runner
    assert "Get-FileHash" in runner and "exit 99" in runner and "Remove-Item" in runner
    assert "-File 'C:\\temp\\{}'".format(name) in runner
    # unique per call
    fake_vm.respond("done")
    run(tr.run_ps_script(script, script_name="big.ps1"))
    assert puts[1][1] != name


def test_run_ps_script_tamper_detected(fake_vm, run, monkeypatch):
    async def fake_put(local, name):
        pass
    monkeypatch.setattr(tr, "smb_put", fake_put)
    fake_vm.respond("", "STAGED SCRIPT HASH MISMATCH", 99)
    with pytest.raises(ToolError, match="Integrity failure"):
        run(tr.run_ps_script("x" * 2000))


def test_smb_password_goes_via_env_not_argv(fake_vm, run, monkeypatch):
    seen = {}

    class P:
        returncode = 0

        async def communicate(self):
            return b"", b""

        def kill(self):
            pass

    async def fake_exec(*argv, **kw):
        seen["argv"] = argv
        seen["env"] = kw["env"]
        return P()
    monkeypatch.setattr(tr.asyncio, "create_subprocess_exec", fake_exec)
    run(tr._smb_exec('put "a" "b"'))
    assert "test-password" not in " ".join(seen["argv"])
    assert seen["env"]["PASSWD"] == "test-password"
    assert seen["argv"][0] == "smbclient" and "-U" in seen["argv"]


def test_upload_verifies_hash(fake_vm, run, monkeypatch, tmp_path):
    f = tmp_path / "s.exe"
    f.write_bytes(b"MZ-sample")
    monkeypatch.setattr(config, "ALLOWED_UPLOAD_ROOTS", [str(tmp_path)])

    async def fake_put(local, name):
        assert local == str(f) and name.startswith("up_") and name.endswith(".exe")
    monkeypatch.setattr(tr, "smb_put", fake_put)
    good = hashlib.sha256(b"MZ-sample").hexdigest()
    fake_vm.respond(good)
    res = run(tr.upload_file(str(f), "C:\\temp\\s.exe"))
    assert res["verified"] and res["sha256"] == good
    assert "'C:\\temp\\s.exe'" in fake_vm.last
    fake_vm.respond("deadbeef")
    with pytest.raises(ToolError, match="HASH MISMATCH"):
        run(tr.upload_file(str(f), "C:\\temp\\s.exe"))
    with pytest.raises(tr.PathNotAllowed):
        run(tr.upload_file("/etc/hostname", "C:\\temp\\x"))


def test_download_verifies_hash_and_perms(fake_vm, run, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ALLOWED_DOWNLOAD_ROOTS", [str(tmp_path)])
    dest = tmp_path / "out" / "dump.bin"
    payload = b"dumped"

    async def fake_get(name, local):
        assert name.startswith("dl_")
        open(local, "wb").write(payload)
    monkeypatch.setattr(tr, "smb_get", fake_get)
    fake_vm.respond("{} {}".format(len(payload), hashlib.sha256(payload).hexdigest()))
    fake_vm.respond("")  # cleanup
    res = run(tr.download_file("C:\\temp\\dump.bin", str(dest)))
    assert res["verified"] and dest.read_bytes() == payload
    assert oct(dest.stat().st_mode & 0o777) == "0o600"
    assert "Remove-Item" in fake_vm.last
    fake_vm.respond("6 0000")
    fake_vm.respond("")
    with pytest.raises(ToolError, match="HASH MISMATCH"):
        run(tr.download_file("C:\\temp\\dump.bin", str(dest)))
    with pytest.raises(tr.PathNotAllowed):
        run(tr.download_file("C:\\x", os.path.expanduser("~/.ssh/authorized_keys")))
