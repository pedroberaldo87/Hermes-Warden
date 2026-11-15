"""Hermes Warden: pilot the Bitwarden CLI without secrets ever entering the conversation.

Unified Hermes plugin:

- ``hermes_warden/``          broker (in-memory session), bw runner, sanitizer, tools.
- ``dashboard/plugin_api.py`` backend for the Desktop tab, mounted at /api/plugins/hermes-warden/.
- ``desktop/plugin.js``       the lock-icon tab, masked dialogs and clipboard delivery.
- ``skills/bitwarden``        how the agent should use the tools.

Importing this file registers nothing; Hermes calls ``register(ctx)``.
"""
import logging
import sys
from pathlib import Path


def register(ctx):
    if sys.platform.startswith("win"):
        # The broker needs Unix sockets and process groups; Windows is not supported.
        logging.getLogger(__name__).warning("Hermes Warden runs on macOS and Linux only; not loaded on Windows.")
        return
    # Relative import: Hermes loads this directory under a synthetic package name.
    from .hermes_warden import tools

    for schema, handler, emoji in tools.TOOLS:
        ctx.register_tool(name=schema["name"], toolset=tools.TOOLSET, schema=schema,
                          handler=tools.safe(handler), description=schema["description"], emoji=emoji)
    ctx.register_command("warden", tools.slash,
                         description="Bitwarden through Hermes Warden (status, unlock, lock, sync, login)",
                         args_hint="status | unlock | lock | sync | login | logout | install | help")
    if callable(getattr(ctx, "register_hook", None)):
        ctx.register_hook("pre_tool_call", tools.guard_terminal)
    skill = Path(__file__).resolve().parent / "skills" / "bitwarden" / "SKILL.md"
    if callable(getattr(ctx, "register_skill", None)) and skill.exists():
        ctx.register_skill("bitwarden", skill)
