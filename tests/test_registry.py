import asyncio

import pytest
from mcp.types import TextContent

from flarevm_mcp import registry as r
from flarevm_mcp.psquote import UNTRUSTED_BEGIN


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(r, "REGISTRY", {})
    return r


def test_register_and_list(fresh):
    @fresh.tool("t1", description="d", timeout=5, category="c")
    async def h(args):
        return "x"
    assert [t.name for t in fresh.mcp_tools()] == ["t1"]
    assert fresh.REGISTRY["t1"].schema["type"] == "object"


def test_duplicate_name_rejected(fresh):
    @fresh.tool("dup", description="d")
    async def h(args):
        return ""
    with pytest.raises(RuntimeError):
        @fresh.tool("dup", description="d")
        async def h2(args):
            return ""


def test_dispatch_wraps_text_in_envelope_and_sanitises(fresh, run):
    @fresh.tool("t", description="d")
    async def h(args):
        return "out\x1b[0m"
    res = run(fresh.dispatch("t", {}))
    assert isinstance(res[0], TextContent)
    assert res[0].text.startswith(UNTRUSTED_BEGIN) and "\x1b" not in res[0].text


def test_dispatch_trusted_text_and_dict(fresh, run):
    @fresh.tool("t", description="d", untrusted=False)
    async def h(args):
        return "plain"

    @fresh.tool("j", description="d")
    async def j(args):
        return {"a": 1}
    assert run(fresh.dispatch("t", {}))[0].text == "plain"
    d = run(fresh.dispatch("j", {}))
    assert d["a"] == 1 and "_source" in d


def test_tool_error_and_crash_become_tool_errors(fresh, run):
    @fresh.tool("e", description="d")
    async def e(args):
        raise fresh.ToolError("nope")

    @fresh.tool("c", description="d")
    async def c(args):
        raise KeyError("boom")

    @fresh.tool("v", description="d")
    async def v(args):
        raise ValueError("invalid path")
    with pytest.raises(fresh.ToolError, match="nope"):
        run(fresh.dispatch("e", {}))
    with pytest.raises(fresh.ToolError, match="KeyError"):
        run(fresh.dispatch("c", {}))
    with pytest.raises(fresh.ToolError, match="invalid path"):
        run(fresh.dispatch("v", {}))
    with pytest.raises(fresh.ToolError, match="Unknown tool"):
        run(fresh.dispatch("nah", {}))


def test_dispatch_timeout(fresh, run):
    @fresh.tool("slow", description="d", timeout=0.05)
    async def slow(args):
        await asyncio.sleep(1)
    with pytest.raises(fresh.ToolError, match=r"\[TIMEOUT\]"):
        run(fresh.dispatch("slow", {}))


def test_progress_is_noop_without_app(run):
    run(r.progress("hi", 1, 2))  # must not raise
