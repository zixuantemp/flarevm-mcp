"""Ida tools (migrated from the 1.1.0 monolith)."""
import json

from ..registry import tool
from ..rpc import ida_rpc_call
from ..rpc import _ida_resolve_address
from ._common import _text


def _ida_unwrap_list(res):
    """The MCP list_* tools return {'data': [...], 'next_offset': N}."""
    if isinstance(res, dict) and "data" in res:
        return res["data"]
    return res if isinstance(res, list) else [res]


@tool(
    'ida_get_metadata',
    description='Get metadata from IDA Pro (binary info, architecture, etc.).',
    schema={'type': 'object', 'properties': {}, 'required': []},
    timeout=30,
    category='ida',
)
async def _handle_ida_get_metadata(args):
    md = await ida_rpc_call("get_metadata")
    return _text("=== IDA Pro Metadata ===\n" + json.dumps(md, indent=2))


@tool(
    'ida_list_functions',
    description='List functions in the binary loaded in IDA Pro.',
    schema={'type': 'object',
     'properties': {'filter': {'type': 'string',
                               'description': 'Optional name filter',
                               'default': ''},
                    'count': {'type': 'integer',
                              'description': 'Max functions to return',
                              'default': 100}},
     'required': []},
    timeout=30,
    category='ida',
)
async def _handle_ida_list_functions(args):
    offset = args.get("offset", 0)
    count = args.get("count") or 100
    flt = args.get("filter")
    if flt:
        res = await ida_rpc_call("list_functions_filter",
                                 {"offset": offset, "count": count, "filter": flt})
    else:
        res = await ida_rpc_call("list_functions", {"offset": offset, "count": count})
    funcs = _ida_unwrap_list(res)
    lines = ["=== IDA Functions ({} shown) ===".format(len(funcs)), ""]
    for f in funcs:
        if isinstance(f, dict):
            lines.append("  {}: {} (size: {})".format(
                f.get("address", "?"), f.get("name", "?"), f.get("size", "?")))
        else:
            lines.append("  " + str(f))
    return _text("\n".join(lines))


@tool(
    'ida_decompile_function',
    description='Decompile a function in IDA Pro (Hex-Rays).',
    schema={'type': 'object',
     'properties': {'function_name': {'type': 'string', 'description': 'Function name or address'}},
     'required': ['function_name']},
    timeout=60,
    category='ida',
)
async def _handle_ida_decompile_function(args):
    target = args["function_name"]
    addr = await _ida_resolve_address(target)
    code = await ida_rpc_call("decompile_function", {"address": addr})
    body = code if isinstance(code, str) else json.dumps(code, indent=2)
    return _text("=== Decompiled: {} ({}) ===\n\n{}".format(target, addr, body))


@tool(
    'ida_disassemble_function',
    description='Get disassembly of a function in IDA Pro.',
    schema={'type': 'object',
     'properties': {'function_name': {'type': 'string', 'description': 'Function name or address'}},
     'required': ['function_name']},
    timeout=60,
    category='ida',
)
async def _handle_ida_disassemble_function(args):
    target = args["function_name"]
    addr = await _ida_resolve_address(target)
    asm = await ida_rpc_call("disassemble_function", {"start_address": addr})
    body = asm if isinstance(asm, str) else json.dumps(asm, indent=2)
    return _text("=== Disassembly: {} ({}) ===\n\n{}".format(target, addr, body))


@tool(
    'ida_list_strings',
    description='List strings found by IDA Pro.',
    schema={'type': 'object',
     'properties': {'filter': {'type': 'string',
                               'description': 'Optional string filter (regex)',
                               'default': ''},
                    'count': {'type': 'integer',
                              'description': 'Max strings to return',
                              'default': 200}},
     'required': []},
    timeout=30,
    category='ida',
)
async def _handle_ida_list_strings(args):
    offset = args.get("offset", 0)
    count = args.get("count") or 100
    flt = args.get("filter")
    if flt:
        res = await ida_rpc_call("list_strings_filter",
                                 {"offset": offset, "count": count, "filter": flt})
    else:
        res = await ida_rpc_call("list_strings", {"offset": offset, "count": count})
    strings = _ida_unwrap_list(res)
    lines = ["=== IDA Strings ({} shown) ===".format(len(strings)), ""]
    for s in strings:
        if isinstance(s, dict):
            val = s.get("string", s.get("value", s.get("text", "?")))
            lines.append("  {}: {}".format(s.get("address", "?"), val))
        else:
            lines.append("  " + str(s))
    return _text("\n".join(lines))


@tool(
    'ida_set_comment',
    description='Set a comment in IDA Pro at a given address.',
    schema={'type': 'object',
     'properties': {'address': {'type': 'string',
                                'description': 'Address (hex string like 0x401000)'},
                    'comment': {'type': 'string', 'description': 'Comment text'}},
     'required': ['address', 'comment']},
    timeout=30,
    category='ida',
)
async def _handle_ida_set_comment(args):
    await ida_rpc_call("set_comment", {
        "address": args["address"],
        "comment": args["comment"],
    })
    return _text("Comment set at {}: {}".format(args["address"], args["comment"]))


@tool(
    'ida_rename_function',
    description='Rename a function in IDA Pro.',
    schema={'type': 'object',
     'properties': {'old_name': {'type': 'string',
                                 'description': 'Current function name or address'},
                    'new_name': {'type': 'string', 'description': 'New function name'}},
     'required': ['old_name', 'new_name']},
    timeout=30,
    category='ida',
)
async def _handle_ida_rename_function(args):
    old = args["old_name"]
    addr = await _ida_resolve_address(old)
    await ida_rpc_call("rename_function", {
        "function_address": addr,
        "new_name": args["new_name"],
    })
    return _text("Function renamed: {} ({}) -> {}".format(old, addr, args["new_name"]))
