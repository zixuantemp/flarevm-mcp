import asyncio
import time

import pytest

from flarevm_mcp import config, winrm_client as wc


def test_run_ps_async_ok(fake_vm, run):
    fake_vm.respond("hello", "", 0)
    assert run(wc.run_ps_async("Write-Output hello")) == ("hello", "", 0)
    assert fake_vm.last == "Write-Output hello"
    assert wc.breaker.snapshot()["state"] == "closed"


def test_timeout_returns_tuple_and_counts_failure(fake_vm, run, monkeypatch):
    def slow(script):
        time.sleep(0.3)
        return ("late", "", 0)
    monkeypatch.setattr(wc, "run_ps", slow)
    gen = wc._generation
    out, err, code = run(wc.run_ps_async("slow", timeout=0.05))
    assert code == 1 and "TIMEOUT" in err
    assert wc._generation == gen + 1          # sessions reset
    assert wc.breaker.failures == 1


def test_breaker_opens_and_fails_fast(fake_vm, run, monkeypatch):
    monkeypatch.setattr(wc.breaker, "threshold", 2)
    monkeypatch.setattr(wc.breaker, "cooldown", 60)

    def boom(script):
        raise ConnectionError("refused")
    monkeypatch.setattr(wc, "run_ps", boom)
    for _ in range(2):
        with pytest.raises(wc.VMUnavailable):
            run(wc.run_ps_async("x"))
    assert wc.breaker.is_open
    # third call never reaches the seam
    monkeypatch.setattr(wc, "run_ps", lambda s: ("should not run", "", 0))
    with pytest.raises(wc.VMUnavailable, match="Circuit breaker OPEN"):
        run(wc.run_ps_async("x"))
    wc.breaker.reset()
    assert run(wc.run_ps_async("x"))[0] == "should not run"


def test_non_transport_errors_propagate_without_tripping(fake_vm, run, monkeypatch):
    def bug(script):
        raise KeyError("bug")
    monkeypatch.setattr(wc, "run_ps", bug)
    with pytest.raises(KeyError):
        run(wc.run_ps_async("x"))
    assert wc.breaker.failures == 0


def test_output_is_capped_and_sanitised(monkeypatch):
    monkeypatch.setattr(config, "MAX_OUTPUT", 8)

    class R:
        std_out = b"\x1b[31mabcdefghijkl"
        std_err = b""
        status_code = 0

    class S:
        def run_ps(self, c):
            return R()
    monkeypatch.setattr(wc, "_session", lambda: S())
    out, err, code = wc.run_ps("x")
    assert out.startswith("abcdefgh") and "TRUNCATED" in out and "\x1b" not in out


def test_semaphore_limits_concurrency(fake_vm, run, monkeypatch):
    monkeypatch.setattr(config, "MAX_CONCURRENT", 2)
    wc._sems.clear()
    active = {"now": 0, "max": 0}

    def slow(script):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        time.sleep(0.05)
        active["now"] -= 1
        return ("", "", 0)
    monkeypatch.setattr(wc, "run_ps", slow)

    async def many():
        await asyncio.gather(*(wc.run_ps_async("x") for _ in range(6)))
    run(many())
    assert active["max"] <= 2
