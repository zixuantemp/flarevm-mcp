"""MCP server assembly. Entry point: ``python server.py`` (repo root shim) or ``flarevm-mcp``."""
import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import __version__, config
from . import prompts as _prompts
from . import resources as _resources
from . import tools  # noqa: F401  registers every tool
from .registry import dispatch, mcp_tools, set_app

app = Server("flarevm-mcp", version=__version__)
set_app(app)


@app.list_tools()
async def list_tools():
    return mcp_tools()


@app.call_tool()
async def call_tool(name, arguments):
    return await dispatch(name, arguments)


@app.list_prompts()
async def list_prompts():
    return _prompts.list_prompts()


@app.get_prompt()
async def get_prompt(name, arguments=None):
    return _prompts.get_prompt(name, arguments)


@app.list_resources()
async def list_resources():
    return _resources.list_resources()


@app.read_resource()
async def read_resource(uri):
    return await _resources.read_resource(uri)


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main_sync():
    config.require_host()
    config.LOG.info("flarevm-mcp %s starting: endpoint=%s strict_integrity=%s max_concurrent=%s",
                    __version__, config.winrm_endpoint(), config.strict_integrity(), config.MAX_CONCURRENT)
    asyncio.run(main())
