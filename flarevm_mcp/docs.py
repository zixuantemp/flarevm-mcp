"""Generate docs/TOOLS.md from the registry: ``python -m flarevm_mcp.docs [--check]``."""
import os
import sys

from . import config  # noqa: F401  (ensures .env is loaded before tools import)
from . import tools  # noqa: F401
from .registry import specs

CATEGORY_TITLES = {
    "system": "Connection & file transfer", "static": "Static analysis", "dynamic": "Dynamic analysis: process & registry",
    "network": "Dynamic analysis: network", "debuggers": "Debuggers & GUI launchers", "frida": "Frida instrumentation",
    "injection": "Injection & unpacking", "ida": "IDA Pro proxy", "playbooks": "Composite playbooks",
    "integrity": "Integrity & availability",
}


def render():
    by_cat = {}
    for s in specs():
        by_cat.setdefault(s.category, []).append(s)
    out = ["# MCP tool reference", "",
           "All {} tools exposed by `flarevm-mcp`, grouped by task. Generated from the tool registry by".format(len(specs())),
           "`python -m flarevm_mcp.docs`; CI fails if this file is stale. Arguments are in each tool's JSON",
           "schema (`list_tools`). Paths on the VM are always Windows paths — escape backslashes in JSON.", ""]
    for cat in CATEGORY_TITLES:
        items = by_cat.get(cat)
        if not items:
            continue
        out += ["## {}".format(CATEGORY_TITLES[cat]), "", "| Tool | Timeout | Purpose |", "|------|---------|---------|"]
        for s in items:
            desc = " ".join(s.description.split())
            out.append("| `{}` | {}s | {} |".format(s.name, s.timeout, desc.replace("|", "\\|")))
        out.append("")
    return "\n".join(out)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    path = os.path.join(config.REPO_ROOT, "docs", "TOOLS.md")
    text = render()
    if "--check" in argv:
        current = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
        if current != text:
            sys.exit("docs/TOOLS.md is stale — run: python -m flarevm_mcp.docs")
        print("docs/TOOLS.md in sync ({} tools)".format(len(specs())))
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote {} ({} tools)".format(path, len(specs())))


if __name__ == "__main__":
    main()
