#!/usr/bin/env python3
"""flarevm-mcp entry point.

Kept at the repository root so existing MCP client configurations
(``"args": ["/path/to/flarevm-mcp/server.py"]``) keep working. All code lives
in the ``flarevm_mcp`` package.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flarevm_mcp.server import main_sync  # noqa: E402

if __name__ == "__main__":
    main_sync()
