#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spl_guard.py — read-only guardrail for LLM-generated SPL.
=========================================================
The agent cases let the model author its own SPL, which is then executed with the
full permissions of the user running the search. Nothing in the prompt prevents the
model from emitting a destructive or exfiltrating command, and prompt instructions
are not a security control.

``check_read_only()`` rejects any query containing a command that writes, sends,
executes, or reads credentials. It is a denylist over command *positions* — every
token that appears immediately after a ``|`` or a subsearch ``[`` is checked, so
commands hidden inside subsearches are caught too.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Commands that mutate data, leave the Splunk process, or read secrets.
_BLOCKED_COMMANDS = {
    # --- write to indexes, lookups, or disk ---
    "delete", "outputlookup", "outputcsv", "outputtext", "dump",
    "collect", "tscollect", "mcollect", "meventcollect", "summaryindex",
    # --- leave the Splunk process ---
    "sendemail", "sendalert", "script", "runshellscript", "external", "crawl",
    # --- read configuration and credentials (e.g. /services/storage/passwords) ---
    "rest",
    # --- execute arbitrary pre-saved logic the guardrail cannot inspect ---
    "savedsearch",
}

# Quoted literals are stripped before scanning so that a command name mentioned
# inside a string (e.g. search "user ran | delete") is not treated as a command.
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')

# A command name is the first bare word after a pipe or a subsearch bracket.
_COMMAND_POSITION = re.compile(r'[|\[]\s*([a-zA-Z_][a-zA-Z0-9_]*)')

# Macro calls hide their body from this check, so they are refused outright.
_MACRO = re.compile(r'`[^`]+`')


class SPLRejected(ValueError):
    """Raised when a generated query is not provably read-only."""


def check_read_only(spl: str) -> str:
    """
    Return ``spl`` unchanged if it is safe to execute, else raise SPLRejected.

    Raising rather than silently rewriting is deliberate: a rejected query should
    be surfaced to the agent so it can choose a different approach, and to the
    operator's logs so the attempt is visible.
    """
    if not spl or not spl.strip():
        raise SPLRejected("Empty query.")

    scannable = _QUOTED.sub(" ", spl)

    if _MACRO.search(scannable):
        raise SPLRejected(
            "Macro calls (`...`) are not allowed because their expansion cannot be "
            "inspected for write commands. Inline the search instead."
        )

    # Prepend a pipe so the leading command of a "| command ..." or bare search
    # is evaluated in the same way as every later stage.
    candidates = _COMMAND_POSITION.findall("|" + scannable.lstrip().lstrip("|"))

    for name in candidates:
        if name.lower() in _BLOCKED_COMMANDS:
            raise SPLRejected(
                f"Command '{name}' is blocked: this agent may only run read-only "
                f"searches. Blocked commands: {', '.join(sorted(_BLOCKED_COMMANDS))}."
            )

    return spl


def guarded(spl: str) -> tuple[bool, str]:
    """
    Non-raising wrapper for tool implementations.

    Returns ``(True, spl)`` when the query is safe, or ``(False, reason)`` so the
    caller can hand the reason back to the model as a tool observation.
    """
    try:
        return True, check_read_only(spl)
    except SPLRejected as exc:
        logger.warning("Rejected LLM-generated SPL: %s | query=%r", exc, spl)
        return False, str(exc)
