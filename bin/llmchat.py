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
    model_name = gemini-3.1-flash-lite

API keys are NOT read from this file — see bin/ai_secrets.py.
"""

import sys
import os
import base64
import json
import copy
import time
import configparser
import logging
import re

# ── Vendored lib path ─────────────────────────────────────────────────────────
# NOTE: We intentionally do NOT import `openai` (which pulls in pydantic_core,
# a compiled .so that fails macOS hardened-runtime library-validation when
# copied from another machine).  Instead we call the OpenAI-compatible REST
# API directly via `requests`, which is pure Python.
_app_bin = os.path.dirname(os.path.abspath(__file__))
_lib_dir = os.path.join(_app_bin, "lib")
if _lib_dir not in sys.path:
    sys.path.insert(0, _lib_dir)

import requests  # pure-Python, no compiled extensions required

from ai_secrets import resolve_api_key
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

logger = logging.getLogger(__name__)
CA_TRUST_STORE = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'openssl', 'cert.pem')


def _tls_verify():
    """Verify target for outbound calls that carry an API key."""
    return CA_TRUST_STORE if os.path.exists(CA_TRUST_STORE) else True

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
        require=False,
        default="",
        doc="The user's question regarding the current search results",
    )
    prompt_b64 = Option(
        require=False,
        default="",
        doc="Base64-encoded UTF-8 prompt. Used by callers that build SPL "
            "programmatically, so free-form text never reaches the SPL parser "
            "as a string literal. Takes precedence over 'prompt'.",
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
            if "base_url" not in conf:
                raise ValueError(f"'base_url' is required in [{provider_name}]")

            # The key comes from storage/passwords; the conf value is only a
            # deprecated fallback for existing installs.
            conf["api_key"] = resolve_api_key(
                provider_name,
                info.session_key,
                conf.get("api_key"),
                app=app_name,
            )

            logger.info(
                "Loaded config for provider=%s model=%s",
                provider_name,
                conf["model_name"],
            )
            return conf

        except Exception as exc:
            logger.error("Failed to load agent_config.conf: %s", exc)
            raise

    def _resolve_prompt(self) -> str:
        """
        Return the effective prompt, preferring the base64 form.

        Decoding is strict: a malformed value is reported rather than silently
        falling back to the plain option, so a broken caller is visible instead
        of quietly sending the model the wrong question.
        """
        if self.prompt_b64:
            try:
                return base64.b64decode(self.prompt_b64, validate=True).decode("utf-8")
            except Exception as exc:
                raise ValueError(f"prompt_b64 is not valid base64-encoded UTF-8: {exc}") from exc

        if self.prompt:
            return self.prompt

        raise ValueError("Either 'prompt' or 'prompt_b64' is required.")

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

    # ── OpenAI-compatible LLM call via plain requests (Ollama + Gemini) ────────

    def _call_llm(self, messages: list[dict], conf: dict) -> str:
        """
        Send a chat completion request using direct HTTP (requests library).
        Both Ollama and Gemini expose an OpenAI-compatible /chat/completions
        endpoint, so we use a single code path for both providers.

        This avoids importing the `openai` SDK (and pydantic_core), which
        contains compiled .so files that fail macOS library-validation when
        copied from another machine.
        """
        provider_name = self.provider.lower()

        # ── resolve base_url and api_key ──────────────────────────────────────
        if provider_name == "gemini":
            base_url = conf.get("base_url",
                                "https://generativelanguage.googleapis.com/v1beta/openai/")
            if not base_url.endswith("/"):
                base_url += "/"
            api_key = conf.get("api_key", "")
        else:
            base_url = conf.get("base_url", "http://localhost:11434/v1")
            api_key = conf.get("api_key", "ollama")
            if not api_key or api_key.lower() == "none":
                api_key = "ollama"

        model_name = conf["model_name"]

        # ── build the endpoint URL ────────────────────────────────────────────
        # base_url may be like "http://host:port/v1" or end with "/"
        endpoint = base_url.rstrip("/") + "/chat/completions"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model_name,
            "messages": messages,
        }

        logger.info(
            "Calling LLM (requests): provider=%s model=%s endpoint=%s messages=%d",
            provider_name, model_name, endpoint, len(messages),
        )

        try:
            resp = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=120,
                verify=_tls_verify(),
            )
            resp.raise_for_status()
            data = resp.json()
            answer = data["choices"][0]["message"]["content"] or ""
            logger.info("LLM responded, chars=%d", len(answer))
            return answer
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Cannot reach LLM endpoint ({endpoint}). "
                f"Is the service running? Detail: {exc}"
            ) from exc
        except requests.exceptions.HTTPError as exc:
            raise RuntimeError(
                f"HTTP error from LLM provider '{provider_name}' ({exc.response.status_code}): "
                f"{exc.response.text[:500]}"
            ) from exc
        except (KeyError, IndexError, ValueError) as exc:
            raise RuntimeError(
                f"Unexpected response format from LLM: {exc}"
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

    def _kv_key(self) -> str:
        """
        Derive the KV Store ``_key`` from the session id.

        Using the session id as the record key makes writes idempotent: there is
        no read-then-write window in which a failed read could cause a duplicate
        record to be inserted and the conversation history to be silently lost.
        """
        return re.sub(r"[^A-Za-z0-9_-]", "_", self.session)[:200]

    def _load_history(self) -> tuple[bool, list[dict]]:
        """
        Return (loaded_ok, messages_list) from KV Store.

        ``loaded_ok`` distinguishes "this session has no history yet" (True, with
        a seeded message list) from "the KV Store could not be read" (False), so
        the caller can decline to overwrite history it was unable to read.
        """
        url = f"{self._get_kvstore_url()}/{self._kv_key()}"
        try:
            # verify=False: splunkd_uri is loopback with a self-signed cert whose
            # CN does not match 127.0.0.1. No API key is sent on this call.
            r = requests.get(url, headers=self._get_headers(), verify=False, timeout=5)
            if r.status_code == 404:
                logger.info("No prior history for session '%s' — starting fresh", self.session)
            else:
                r.raise_for_status()
                rec = r.json()
                return True, json.loads(rec.get("messages", "[]"))
        except Exception as exc:
            logger.warning("Could not load KV Store history for session '%s': %s",
                           self.session, exc)
            return False, self._seed_messages()

        return True, self._seed_messages()

    @staticmethod
    def _seed_messages() -> list[dict]:
        return [
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

    def _save_history(self, messages: list[dict]) -> None:
        """Upsert the conversation under a deterministic _key."""
        base = self._get_kvstore_url()
        key = self._kv_key()
        payload = {
            "_key": key,
            "session_id": self.session,
            "messages": json.dumps(messages),
        }
        try:
            r = requests.post(f"{base}/{key}", headers=self._get_headers(),
                              json=payload, verify=False, timeout=5)
            if r.status_code == 404:
                # Record does not exist yet — insert it with the explicit _key.
                r = requests.post(base, headers=self._get_headers(),
                                  json=payload, verify=False, timeout=5)
            r.raise_for_status()
        except Exception as exc:
            logger.warning("Could not save KV Store history for session '%s': %s",
                           self.session, exc)

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
        # 0. Resolve the prompt (plain option or base64 transport)
        try:
            prompt = self._resolve_prompt()
        except ValueError as exc:
            yield {
                "_time": time.time(),
                "user_prompt": "",
                "ai_response": f"❌ {exc}",
                "analyzed_count": 0,
                "chat_history": "",
            }
            return

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
                "user_prompt": prompt,
                "ai_response": f"❌ Config error: {exc}",
                "analyzed_count": 0,
                "chat_history": "",
            }
            return

        # 3. Restore KV Store conversation memory
        history_ok = False
        if self.session:
            history_ok, messages = self._load_history()
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
            f"### User Question:\n{prompt}"
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
        if self.session and history_ok:
            saved = copy.deepcopy(messages)
            # Replace the full JSON logs in the user turn with a compact note
            saved[-2]["content"] = (
                f"### User Question:\n{prompt}\n"
                "(Note: Current round's raw log data was provided and analyzed.)"
            )
            self._save_history(saved)
        elif self.session:
            logger.warning(
                "Skipping history save for session '%s': prior history could not be read, "
                "so overwriting it would discard earlier turns.", self.session
            )

        # 8. Yield the single result row consumed by the dashboard JS / loadjob
        yield {
            "_time": events[0].get("_time", time.time()) if events else time.time(),
            "user_prompt": prompt,
            "ai_response": answer,
            "analyzed_count": len(events),
            "chat_history": history_text,
            "provider": self.provider,
            "model": conf.get("model_name", "unknown"),
        }


if __name__ == "__main__":
    dispatch(LLMDataChatCommand, sys.argv, sys.stdin, sys.stdout, __name__)