"""Shared fixtures. ``fake_vm`` replaces the synchronous WinRM seam so every
layer above it (semaphore, breaker, dispatch, handlers) runs for real."""
import asyncio
import os

import pytest

os.environ.setdefault("FLAREVM_HOST", "10.0.0.9")
os.environ.setdefault("FLAREVM_PASSWORD", "test-password")

from flarevm_mcp import config, winrm_client  # noqa: E402


class FakeVM:
    """Records every PowerShell script and answers from a queue or a rule."""

    def __init__(self):
        self.calls = []
        self.queue = []
        self.rule = None          # callable(script) -> (out, err, code)
        self.default = ("", "", 0)

    def respond(self, out="", err="", code=0):
        self.queue.append((out, err, code))
        return self

    def __call__(self, script):
        self.calls.append(script)
        if self.rule is not None:
            r = self.rule(script)
            if r is not None:
                return r
        if self.queue:
            return self.queue.pop(0)
        return self.default

    @property
    def last(self):
        return self.calls[-1]


@pytest.fixture
def fake_vm(monkeypatch):
    vm = FakeVM()
    monkeypatch.setattr(winrm_client, "run_ps", vm)
    winrm_client.breaker.reset()
    monkeypatch.setattr(config, "FLAREVM_HOST", "10.0.0.9")
    monkeypatch.setattr(config, "get_password", lambda: "test-password")
    monkeypatch.setattr(config, "STRICT_INTEGRITY", False)
    return vm


@pytest.fixture
def run():
    def _run(coro):
        return asyncio.run(coro)
    return _run
