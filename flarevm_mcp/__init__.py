"""flarevm-mcp — MCP server bridging a Kali analyst host to a Windows FlareVM."""
try:
    from importlib.metadata import PackageNotFoundError, version as _version
    try:
        __version__ = _version("flarevm-mcp")
    except PackageNotFoundError:  # running from a checkout without pip install
        __version__ = "1.2.0"
except Exception:  # pragma: no cover
    __version__ = "1.2.0"
