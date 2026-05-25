#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llmchat.py — Splunk Streaming Command
======================================
Usage:
    <your SPL> | head 50 | llmchat session="<id>" prompt="<question>" [provider="ollama"|"gemini"]

Consumes search results from the pipeline and sends them to an LLM for
analysis, supporting multi-turn KV Store conversation memory.

Model configuration is shared with ai_agent.py via agent_config.conf:
    [ollama]
    base_url  = http://localhost:11434/v1
    model_name = gemma4
    api_key   = none

    [gemini]
    base_url  = https://generativelanguage.googleapis.com/v1beta/openai/
    model_name = gemini-2.0-flash
    api_key   = <your-api-key>
"""

import sys
import os
import json
import copy
import time
import asyncio
import configparser
import logging
import urllib.parse

import requests

# ── Vendored lib path (openai SDK, httpx, etc.) ──────────────────────────────
_app_bin = os.path.dirname(os.path.abspath(__file__))
_lib_dir = os.path.join(_app_bin, "lib")
if _lib_dir not in sys.path:
    sys.path.insert(0, _lib_dir)

import openai  # openai >= 1.x from bin/lib/

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

logger = logging.getLogger(__name__)
CA_TRUST_STORE = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'openssl', 'cert.pem')
_ssl_cert_file = os.environ.get("SSL_CERT_FILE", "")
if _ssl_cert_file and not os.path.exists(_ssl_cert_file):
    del os.environ["SSL_CERT_FILE"]

# ─────────────────────────────────────────────────────────────────────────────
# Helper: extract text from a content that might be str or list of blocks
# ─────────────────────────────────────────────────────────────────────────────
def _extract_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.text if hasattr(block, "text") else str(block) for block in content
        )
    if hasattr(content, "text"):
        return content.text
    return str(content)


# ─────────────────────────────────────────────────────────────────────────────
@Configuration()
class LLMDataChatCommand(StreamingCommand):
    """
    Streaming command: consumes pipeline records → sends to LLM → yields one
    result row containing {user_prompt, ai_response, analyzed_count, chat_history}.
    """

    prompt = Option(
        require=True,
        doc="The user's question regarding the current search results",
    )
    session = Option(
        require=False,
        default="",
        doc="Session ID used for KV Store conversation memory",
    )
    provider = Option(
        require=False,
        default="ollama",
        doc="LLM provider to use: 'ollama' or 'gemini' (reads from agent_config.conf)",
    )
    max_events = Option(
        default=50,
        doc="Maximum number of log events to feed into the LLM context window",
    )

    # ── Config loading (shared with ai_agent.py) ──────────────────────────────

    def _get_config(self, provider_name: str) -> dict:
        """Read the [<provider>] section from agent_config.conf."""
        try:
            info = self._get_searchinfo()
            app_name = info.app
            splunk_home = os.environ.get("SPLUNK_HOME", "")
            if not splunk_home:
                raise EnvironmentError("SPLUNK_HOME is not set")

            config_path = os.path.join(
                splunk_home, "etc", "apps", app_name, "default", "agent_config.conf"
            )
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"agent_config.conf not found at: {config_path}")

            cfg = configparser.ConfigParser()
            cfg.read(config_path)

            if provider_name not in cfg:
                raise KeyError(
                    f"Provider '{provider_name}' not found in agent_config.conf. "
                    f"Available sections: {list(cfg.sections())}"
                )

            conf = dict(cfg[provider_name])

            if "model_name" not in conf:
                raise ValueError(f"'model_name' is required in [{provider_name}]")
            if provider_name.lower() != "ollama" and "api_key" not in conf:
                raise ValueError(f"'api_key' is required in [{provider_name}]")
            if "base_url" not in conf:
                raise ValueError(f"'base_url' is required in [{provider_name}]")

            logger.info(
                "Loaded config for provider=%s model=%s",
                provider_name,
                conf["model_name"],
            )
            return conf

        except Exception as exc:
            logger.error("Failed to load agent_config.conf: %s", exc)
            raise

    def _get_searchinfo(self):
        if hasattr(self, "searchinfo") and self.searchinfo is not None:
            return self.searchinfo
        elif hasattr(self, "_metadata") and self._metadata is not None:
            return self._metadata.searchinfo
        elif hasattr(self, "metadata") and self.metadata is not None:
            return self.metadata.searchinfo
        raise RuntimeError(
            "Could not find searchinfo — ensure passauth = true in commands.conf"
        )

    # ── OpenAI-compatible LLM call (works for Ollama + Gemini) ───────────────

    def _call_llm(self, messages: list[dict], conf: dict) -> str:
        """
        Send a chat completion request using the openai SDK.
        Both Ollama and Gemini expose an OpenAI-compatible endpoint,
        so we use a single code path for both providers.
        """
        provider_name = self.provider.lower()

        if provider_name == "gemini":
            # Gemini's OpenAI-compatible base URL (must end with /openai/)
            base_url = conf.get("base_url", "https://generativelanguage.googleapis.com/v1beta/openai/")
            # Ensure it ends properly for the openai SDK
            if not base_url.endswith("/"):
                base_url += "/"
            api_key = conf.get("api_key", "")
        else:
            # Ollama / any other OpenAI-compatible provider
            base_url = conf.get("base_url", "http://localhost:11434/v1")
            api_key = conf.get("api_key", "ollama")  # Ollama accepts any non-empty key
            if not api_key or api_key.lower() == "none":
                api_key = "ollama"

        model_name = conf["model_name"]

        logger.info(
            "Calling LLM: provider=%s model=%s base_url=%s messages=%d",
            provider_name, model_name, base_url, len(messages),
        )

        try:
            client = openai.OpenAI(base_url=base_url, api_key=api_key)
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                timeout=120,
            )
            answer = response.choices[0].message.content or ""
            logger.info("LLM responded, chars=%d", len(answer))
            return answer
        except openai.APIConnectionError as exc:
            raise RuntimeError(
                f"Cannot reach LLM endpoint ({base_url}). "
                f"Is the service running? Detail: {exc}"
            ) from exc
        except openai.AuthenticationError as exc:
            raise RuntimeError(
                f"Authentication failed for provider '{provider_name}'. "
                f"Check api_key in agent_config.conf. Detail: {exc}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"LLM call failed: {exc}") from exc

    # ── KV Store conversation memory ─────────────────────────────────────────

    def _get_kvstore_url(self) -> str:
        info = self._get_searchinfo()
        return (
            f"{info.splunkd_uri}/servicesNS/nobody/{info.app}"
            f"/storage/collections/data/chat_sessions"
        )

    def _get_headers(self) -> dict:
        info = self._get_searchinfo()
        return {
            "Authorization": f"Splunk {info.session_key}",
            "Content-Type": "application/json",
        }

    def _load_history(self) -> tuple[str | None, list[dict]]:
        """Return (kv_record_key, messages_list) from KV Store."""
        url = self._get_kvstore_url()
        query = json.dumps({"session_id": self.session})
        req_url = f"{url}?query={urllib.parse.quote(query)}"
        try:
            r = requests.get(req_url, headers=self._get_headers(), verify=False, timeout=5)
            r.raise_for_status()
            records = r.json()
            if records:
                rec = records[0]
                return rec.get("_key"), json.loads(rec.get("messages", "[]"))
        except Exception as exc:
            logger.warning("Could not load KV Store history: %s", exc)

        # Fresh session — seed with system prompt
        return None, [
            {
                "role": "system",
                "content": (
                    "You are an expert Splunk data analyst and cybersecurity expert. "
                    "Analyze the provided Splunk log events and answer the user's question "
                    "accurately and concisely. Previous conversation context is included "
                    "to help maintain continuity across turns."
                ),
            }
        ]

    def _save_history(self, record_key: str | None, messages: list[dict]) -> None:
        url = self._get_kvstore_url()
        payload = {"session_id": self.session, "messages": json.dumps(messages)}
        try:
            endpoint = f"{url}/{record_key}" if record_key else url
            requests.post(endpoint, headers=self._get_headers(), json=payload, verify=False, timeout=5)
        except Exception as exc:
            logger.warning("Could not save KV Store history: %s", exc)

    def _format_history_for_display(self, messages: list[dict]) -> str:
        """
        Produce a human-readable transcript of all past turns for the frontend.
        Raw log data injected in previous user messages is stripped out.
        """
        lines = []
        turn = 1
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                continue
            if role == "user":
                # Strip the bulk log data prefix we added, keep only the question
                if "### User Question:\n" in content:
                    content = content.split("### User Question:\n")[-1]
                content = content.replace(
                    "\n(Note: Current round's raw log data was provided and analyzed.)", ""
                ).strip()
                lines.append(f"--- Turn {turn} ---\n🧑‍💻 You: {content}")
            elif role == "assistant":
                lines.append(f"🤖 AI: {content.strip()}\n")
                turn += 1
        return "\n".join(lines).strip() or "No previous conversation history in this session."

    # ── Main streaming handler ────────────────────────────────────────────────

    def stream(self, records):
        # 1. Collect log events from the pipeline
        events: list[dict] = []
        for record in records:
            if len(events) >= int(self.max_events):
                break
            clean = {
                k: v
                for k, v in record.items()
                if not k.startswith("_") or k in ("_raw", "_time")
            }
            events.append(clean)

        if not events:
            logger.warning("llmchat received 0 events from pipeline — nothing to analyze")
            return

        # 2. Load agent_config.conf for the chosen provider
        try:
            conf = self._get_config(self.provider)
        except Exception as exc:
            yield {
                "_time": time.time(),
                "user_prompt": self.prompt,
                "ai_response": f"❌ Config error: {exc}",
                "analyzed_count": 0,
                "chat_history": "",
            }
            return

        # 3. Restore KV Store conversation memory
        record_key = None
        if self.session:
            record_key, messages = self._load_history()
        else:
            messages = [
                {
                    "role": "system",
                    "content": "You are an expert Splunk data analyst. Analyze the logs below.",
                }
            ]

        # 4. Build display-friendly history (extracted before appending new user msg)
        history_text = self._format_history_for_display(messages)

        # 5. Assemble current-turn user message: logs + question
        user_content = (
            f"### Current Log Data ({len(events)} events):\n"
            f"{json.dumps(events, ensure_ascii=False, indent=2)}\n\n"
            f"### User Question:\n{self.prompt}"
        )
        messages.append({"role": "user", "content": user_content})

        # 6. Call LLM via openai SDK (OpenAI-compatible: works for Ollama + Gemini)
        try:
            answer = self._call_llm(messages, conf)
        except Exception as exc:
            answer = f"❌ LLM invocation failed: {exc}"
            logger.error("LLM call error: %s", exc, exc_info=True)

        # 7. Persist updated conversation to KV Store (strip bulk log data to save space)
        messages.append({"role": "assistant", "content": answer})
        if self.session:
            saved = copy.deepcopy(messages)
            # Replace the full JSON logs in the user turn with a compact note
            saved[-2]["content"] = (
                f"### User Question:\n{self.prompt}\n"
                "(Note: Current round's raw log data was provided and analyzed.)"
            )
            self._save_history(record_key, saved)

        # 8. Yield the single result row consumed by the dashboard JS / loadjob
        yield {
            "_time": events[0].get("_time", time.time()) if events else time.time(),
            "user_prompt": self.prompt,
            "ai_response": answer,
            "analyzed_count": len(events),
            "chat_history": history_text,
            "provider": self.provider,
            "model": conf.get("model_name", "unknown"),
        }


if __name__ == "__main__":
    dispatch(LLMDataChatCommand, sys.argv, sys.stdin, sys.stdout, __name__)