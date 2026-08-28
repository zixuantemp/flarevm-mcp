"""MCP prompts (workflow recipes)."""
from mcp.types import GetPromptResult, ListPromptsResult, Prompt, PromptArgument, PromptMessage, TextContent

from ._prompt_data import PROMPT_DEFS, _prompt_body


def list_prompts():
    return ListPromptsResult(prompts=[
        Prompt(name=p["name"], description=p["description"],
               arguments=[PromptArgument(name=a["name"], description=a["description"],
                                         required=a.get("required", False)) for a in p["arguments"]])
        for p in PROMPT_DEFS])


def get_prompt(name, arguments=None):
    args = arguments or {}
    return GetPromptResult(
        description=next((p["description"] for p in PROMPT_DEFS if p["name"] == name), name),
        messages=[PromptMessage(role="user", content=TextContent(type="text", text=_prompt_body(name, args)))])
