#!/usr/bin/env python
# coding=utf-8
"""
mcp_agent.py — Splunk Generating Command (Case 4: Autonomous ReAct Agent)
==========================================================================
Usage:
    | mcpagent prompt="<task description>" [provider=Ollama] [model=<name>] [max_steps=3]

Executes a ReAct loop (Plan SPL → Execute → Observe → Report) using tool calling.
The LLM autonomously decides which Splunk searches to run and synthesizes a final report.

LLM endpoint and model are resolved in priority order:
    1. Explicit Option parameters (api_url=..., model=...)
    2. agent_config.conf [ollama] or [gemini] section
    3. Built-in defaults (Ollama localhost)
"""

import sys
import os
import json
import time
import configparser
import logging
import urllib.request
import urllib.error

from ai_secrets import resolve_api_key
from spl_guard import guarded
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [MCPAgent] %(message)s',
    stream=sys.stderr,
)

_DEFAULT_API_URL = "http://localhost:11434/v1/chat/completions"
_DEFAULT_MODEL = "qwen3:latest"


# ─────────────────────────────────────────────────────────────────────────────
# Config helper
# ─────────────────────────────────────────────────────────────────────────────
def _load_app_config() -> configparser.ConfigParser:
    """Load agent_config.conf relative to this script (no searchinfo required)."""
    bin_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.normpath(os.path.join(bin_dir, '..', 'default', 'agent_config.conf'))
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    return cfg


def _resolve_endpoint(cfg: configparser.ConfigParser,
                       provider: str,
                       option_api_url: str,
                       option_model: str) -> tuple[str, str]:
    """
    Return (api_url, model) — preferring explicit Option values, then agent_config.conf.
    Falls back to built-in defaults if neither is provided.
    """
    section = provider.lower()  # 'ollama' or 'gemini'

    # api_url: use Option only if it differs from the built-in default
    if option_api_url and option_api_url != _DEFAULT_API_URL:
        api_url = option_api_url
    elif section in cfg:
        base = cfg.get(section, 'base_url', fallback='http://localhost:11434/v1').rstrip('/')
        api_url = base + '/chat/completions'
    else:
        api_url = _DEFAULT_API_URL

    # model: use Option only if it differs from the built-in default
    if option_model and option_model != _DEFAULT_MODEL:
        model = option_model
    elif section in cfg:
        model = cfg.get(section, 'model_name', fallback=_DEFAULT_MODEL)
    else:
        model = _DEFAULT_MODEL

    return api_url, model


# ─────────────────────────────────────────────────────────────────────────────
@Configuration()
class MCPAgentCommand(GeneratingCommand):
    """
    Autonomous ReAct agent: the LLM autonomously plans and executes Splunk
    searches via tool calling, then synthesises a final investigation report.
    """

    prompt = Option(
        require=True,
        doc="Task description / investigation goal for the agent",
    )
    mcp_server = Option(
        require=False,
        doc="(Reserved) MCP server address — not yet used",
    )
    provider = Option(
        require=False,
        default="ollama",
        doc="LLM provider: 'ollama' or 'gemini'",
    )
    model = Option(
        require=False,
        default=_DEFAULT_MODEL,
        doc=f"Model name (default: {_DEFAULT_MODEL}). Overrides agent_config.conf.",
    )
    max_steps = Option(
        require=False,
        default=3,
        validate=validators.Integer(),
        doc="Maximum number of ReAct iterations before forcing a final report",
    )
    api_url = Option(
        require=False,
        default=_DEFAULT_API_URL,
        doc="Full chat completions endpoint URL. Overrides agent_config.conf.",
    )

    # ── Splunk search tool ────────────────────────────────────────────────────

    def run_splunk_search(self, spl_query: str) -> str:
        """Execute a Splunk one-shot search and return results as a JSON string."""
        spl_query = spl_query.strip()
        if not spl_query.startswith("|") and not spl_query.startswith("search"):
            spl_query = "search " + spl_query

        # The query came from the model, so it is untrusted input even though it
        # will run with the search user's full permissions.
        allowed, reason = guarded(spl_query)
        if not allowed:
            return json.dumps({"error": f"Query refused by the read-only guardrail. {reason}"})

        try:
            raw = self.service.jobs.oneshot(spl_query, output_mode="json")
            data = json.loads(raw.read().decode("utf-8"))
            results = data.get("results", [])
            # Cap at 10 rows to prevent LLM context overflow
            return json.dumps(results[:10], ensure_ascii=False)
        except Exception as exc:
            return json.dumps({"error": f"SPL execution failed: {exc}"})

    # ── LLM call (OpenAI-compatible tool calling) ─────────────────────────────

    def _call_llm(self, api_url: str, model: str, messages: list, tools: list,
                  api_key: str = "") -> dict:
        """Send a chat completion request and return the parsed response dict."""
        payload = {
            "model": model,
            "messages": messages,
            "tools": tools,
            "stream": False,
        }
        headers = {"Content-Type": "application/json"}
        # Gemini (and any other hosted OpenAI-compatible endpoint) rejects the
        # request with 401 unless the key is presented as a bearer token.
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        req = urllib.request.Request(
            api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))

    # ── Main generate handler ─────────────────────────────────────────────────

    def generate(self):
        thought_process: list[str] = []
        executed_queries: list[str] = []
        final_report = ""

        # ── Resolve endpoint from config ──────────────────────────────────────
        cfg = _load_app_config()
        api_url, model = _resolve_endpoint(
            cfg, self.provider, self.api_url, self.model,
        )
        info = self._metadata.searchinfo
        try:
            api_key = resolve_api_key(
                self.provider,
                info.session_key,
                cfg.get(self.provider.lower(), 'api_key', fallback=None),
                app=info.app,
            )
        except Exception as exc:
            yield {
                "_time": time.time(),
                "task": self.prompt,
                "provider": self.provider,
                "model": model,
                "agent_thought_process": "No actions taken.",
                "executed_spl_queries": "No queries executed.",
                "final_investigation_report": f"Credential error: {exc}",
            }
            return

        logger.info("MCPAgent starting: provider=%s model=%s endpoint=%s",
                    self.provider, model, api_url)

        # ── Tool schema ───────────────────────────────────────────────────────
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "execute_splunk_search",
                    "description": (
                        "Executes a Splunk SPL query and returns log results in JSON format. "
                        "Use this tool to investigate events in Splunk."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "spl_query": {
                                "type": "string",
                                "description": (
                                    "The Splunk SPL query to execute. "
                                    "Example: 'search index=_audit action=search | head 5'"
                                ),
                            },
                            "reasoning": {
                                "type": "string",
                                "description": "Why you need to run this specific query.",
                            },
                        },
                        "required": ["spl_query", "reasoning"],
                    },
                },
            }
        ]

        # ── Initial conversation ──────────────────────────────────────────────
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an elite Splunk Platform Security Auditor. "
                    "Use the execute_splunk_search tool to investigate events autonomously. "
                    "Always use hardcoded values in SPL — never use variables or placeholders. "
                    "Your searches are restricted to read-only SPL: commands that write, send, or "
                    "execute (delete, outputlookup, collect, sendemail, script, rest, savedsearch) "
                    "and macro calls will be refused. "
                    "Once you reach a solid conclusion, output the final report directly "
                    "without calling any further tools."
                ),
            },
            {"role": "user", "content": self.prompt},
        ]

        # ── ReAct loop ────────────────────────────────────────────────────────
        for step in range(int(self.max_steps)):
            try:
                response_data = self._call_llm(api_url, model, messages, tools, api_key)
            except urllib.error.URLError as exc:
                final_report = f"Agent API request failed: {exc}"
                break
            except Exception as exc:
                final_report = f"Agent runtime error: {exc}"
                break

            message = response_data.get("choices", [{}])[0].get("message", {})
            messages.append(message)

            if message.get("tool_calls"):
                for tool_call in message["tool_calls"]:
                    if tool_call["function"]["name"] != "execute_splunk_search":
                        continue

                    try:
                        args = json.loads(tool_call["function"]["arguments"])
                    except json.JSONDecodeError:
                        args = {}

                    spl_query = args.get("spl_query", "")
                    reasoning = args.get("reasoning", "Gathering more context.")

                    thought_process.append(f"[Step {step + 1} Thought] {reasoning}")
                    thought_process.append(f"[Step {step + 1} Action] Executing SPL query.")
                    executed_queries.append(f"{step + 1}. {spl_query}")

                    # Execute the search
                    search_result = self.run_splunk_search(spl_query)

                    # Safe result count (handles both list and error dict)
                    try:
                        parsed_result = json.loads(search_result)
                        result_count = len(parsed_result) if isinstance(parsed_result, list) else 0
                    except (json.JSONDecodeError, TypeError):
                        result_count = 0

                    thought_process.append(
                        f"[Step {step + 1} Observation] Retrieved {result_count} log events."
                    )
                    logger.info("Step %d: executed SPL, got %d events", step + 1, result_count)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": "execute_splunk_search",
                        "content": search_result,
                    })
            else:
                # LLM chose not to call a tool → final report
                final_report = message.get("content", "")
                thought_process.append("[Completed] Investigation finished.")
                logger.info("Agent completed in %d step(s)", step + 1)
                break

        # Fallback if max steps reached without a final report
        if not final_report:
            final_report = (
                f"Maximum steps ({self.max_steps}) reached without a conclusive report. "
                "Please review the executed queries and observations above."
            )
            logger.warning("Agent hit max_steps=%s without generating a final report", self.max_steps)

        # ── Yield single result row ───────────────────────────────────────────
        yield {
            "_time": time.time(),
            "task": self.prompt,
            "provider": self.provider,
            "model": model,
            "agent_thought_process": "\n\n".join(thought_process) or "No actions taken.",
            "executed_spl_queries": "\n\n".join(executed_queries) or "No queries executed.",
            "final_investigation_report": final_report,
        }


if __name__ == "__main__":
    dispatch(MCPAgentCommand, sys.argv, sys.stdin, sys.stdout, __name__)