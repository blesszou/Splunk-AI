#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_rag.py — Splunk Streaming Command (Case 3: RAG + LLM)
==========================================================
Usage:
    <your SPL> | fields event | airag prompt="<question>" provider=ollama model=llama3:latest

Retrieves semantically similar historical incidents from a Milvus vector DB,
then uses an LLM to identify the responsible department for a security event.

All infrastructure settings are read from agent_config.conf (default/):

    [ollama]
    base_url = http://localhost:11434/v1
    model_name = llama3:latest
    api_key = none

    [gemini]
    base_url = https://generativelanguage.googleapis.com/v1beta/openai/
    model_name = gemini-2.0-flash
    api_key = <your-key>

    [milvus]
    host = 127.0.0.1
    port = 19530

    [embedding]
    model = all-minilm
"""

import sys
import os
import json
import configparser
import logging
import requests

from ai_secrets import resolve_api_key
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

logger = logging.getLogger(__name__)

CA_TRUST_STORE = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'openssl', 'cert.pem')


def _tls_verify():
    """Verify target for outbound calls that carry an API key."""
    return CA_TRUST_STORE if os.path.exists(CA_TRUST_STORE) else True


# ─────────────────────────────────────────────────────────────────────────────
# Config helper (path relative to this script — no searchinfo required)
# ─────────────────────────────────────────────────────────────────────────────
def _load_app_config() -> configparser.ConfigParser:
    """Load agent_config.conf from the app's default/ directory."""
    bin_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.normpath(os.path.join(bin_dir, '..', 'default', 'agent_config.conf'))
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
@Configuration()
class LLMRAGCommand(StreamingCommand):
    """
    Streaming command: RAG retrieval from Milvus + LLM analysis.

    For each input record containing an ``event`` field, the command:
    1. Embeds the event text via the configured embedding model.
    2. Queries Milvus for the top-N most similar historical incidents.
    3. Sends the context + question to the LLM and returns the response.
    """

    prompt = Option(
        require=True,
        doc="User question regarding the security event",
    )
    provider = Option(
        require=True,
        doc="LLM provider: 'ollama' or 'gemini'",
        validate=validators.Match("provider", r"^(ollama|gemini)$"),
    )
    model = Option(
        require=True,
        doc="Model name, e.g. 'llama3:latest' or 'gemini-2.0-flash'",
    )
    collection_name = Option(
        default="security_incidents",
        doc="Milvus collection name to search",
    )
    debug = Option(
        default=False,
        validate=validators.Boolean(),
        doc="Enable verbose debug logging",
    )
    max_records = Option(
        default=5,
        validate=validators.Integer(),
        doc="Maximum number of context records to retrieve from Milvus",
    )

    # ── Lazy-loaded config ────────────────────────────────────────────────────

    @property
    def _cfg(self) -> configparser.ConfigParser:
        if not hasattr(self, '_cached_cfg'):
            self._cached_cfg = _load_app_config()
        return self._cached_cfg

    def _ollama_base_url(self) -> str:
        """Return the Ollama OpenAI-compatible base URL (e.g. http://host:port/v1)."""
        return self._cfg.get('ollama', 'base_url', fallback='http://localhost:11434/v1').rstrip('/')

    def _milvus_base_url(self) -> str:
        host = self._cfg.get('milvus', 'host', fallback='127.0.0.1')
        port = self._cfg.get('milvus', 'port', fallback='19530')
        return f"http://{host}:{port}"

    def _embedding_model(self) -> str:
        return self._cfg.get('embedding', 'model', fallback='all-minilm')

    def _resolve_key(self, provider: str) -> str:
        """Fetch the provider's API key from storage/passwords (requires passauth)."""
        info = getattr(self, '_metadata', None)
        session_key = info.searchinfo.session_key if info else None
        app = info.searchinfo.app if info else 'splunk_ai'
        return resolve_api_key(
            provider,
            session_key,
            self._cfg.get(provider, 'api_key', fallback=None),
            app=app,
        )

    # ── Main stream handler ───────────────────────────────────────────────────

    def stream(self, records):
        for record in records:
            event_value = record.get("event", "")

            # 1. RAG: retrieve semantically similar historical incidents
            context_records = self.retrieve_context(
                event_value, self.collection_name,
                debug=self.debug, limit=int(self.max_records),
            )

            # 2. Build enriched prompt
            if context_records:
                context_str = "\n".join([
                    f"[Record {i + 1}]\n" +
                    "\n".join(f"{k}: {v}" for k, v in r.items() if k not in ("score", "vector"))
                    for i, r in enumerate(context_records)
                ])
                enhanced_prompt = (
                    "You are an experienced SOC analyst. "
                    "Based on the historical incidents below, determine which department or role "
                    "is primarily responsible for handling this security event. "
                    "Use the department and contact fields from the historical incidents.\n\n"
                    f"Context (historical incidents):\n{context_str}\n\n"
                    f"Question:\n{event_value}\n\n"
                    "Return your answer in strictly valid JSON format:\n"
                    "{\n"
                    "  \"responsible_department\": \"...\",\n"
                    "  \"responsible_contact\": \"...\",\n"
                    "  \"reasoning\": \"...\"\n"
                    "}"
                )
            else:
                enhanced_prompt = event_value

            # 3. Call LLM
            response_text = self.call_llm(enhanced_prompt)

            # 4. Extract top-2 records' department/contact for quick reference fields
            top_records = context_records[:2] if context_records else []
            department = ", ".join({str(r.get("department", "")) for r in top_records if r.get("department")})
            contact = ", ".join({str(r.get("contact", "")) for r in top_records if r.get("contact")})
            if not department:
                department = "N/A"
            if not contact:
                contact = "N/A"

            # 5. Yield: original fields + AI-enriched fields
            output_record = dict(record)
            output_record.update({
                "answer": response_text,
                "department": department,
                "contact": contact,
                "matched_records": json.dumps(top_records, ensure_ascii=False),
            })
            yield output_record

    # ── RAG: Milvus retrieval ─────────────────────────────────────────────────

    def retrieve_context(self, query: str, collection_name: str,
                         debug: bool = False, limit: int = 5) -> list:
        """Retrieve the top-N most similar records from Milvus for the given query."""
        try:
            # Get query embedding
            query_embedding = self.get_embedding(query)
            if not query_embedding:
                if debug:
                    logger.warning("[RAG] Empty embedding returned for query")
                return []

            milvus_base = self._milvus_base_url()

            # Describe collection to discover schema dynamically
            desc_resp = requests.post(
                f"{milvus_base}/v2/vectordb/collections/describe",
                json={"collectionName": collection_name},
                timeout=10,
            )
            desc_resp.raise_for_status()
            desc_data = desc_resp.json()

            if desc_data.get("code") != 0:
                if debug:
                    logger.warning("[Milvus Describe Error] %s", desc_data.get("message"))
                return []

            embedding_field = "vector"
            available_fields: list[str] = []

            for f in desc_data.get("data", {}).get("fields", []):
                ftype = str(f.get("type", "")).lower()
                fdtype = str(f.get("dataType", "")).lower()
                if "vector" in ftype or "vector" in fdtype:
                    embedding_field = f.get("name", embedding_field)
                else:
                    available_fields.append(f.get("name"))

            # Ensure dynamic fields are requested (Milvus may omit them otherwise)
            for dyn in ("title", "description", "incident", "analyst",
                         "department", "contact", "resolution"):
                if dyn not in available_fields:
                    available_fields.append(dyn)

            # Vector similarity search
            search_resp = requests.post(
                f"{milvus_base}/v2/vectordb/entities/search",
                json={
                    "collectionName": collection_name,
                    "data": [query_embedding],
                    "annsField": embedding_field,
                    "limit": limit,
                    "outputFields": available_fields,
                },
                timeout=15,
            )
            search_resp.raise_for_status()
            search_data = search_resp.json()

            if search_data.get("code") != 0:
                if debug:
                    logger.warning("[Milvus Search Error] %s", search_data.get("message"))
                return []

            return [
                {**{field: hit.get(field, "") for field in available_fields},
                 "score": float(hit.get("distance", 0.0))}
                for hit in search_data.get("data", [])
            ]

        except Exception as exc:
            logger.error("[RAG retrieve_context error] %s", exc, exc_info=debug)
            return []

    def get_embedding(self, text: str) -> list:
        """
        Get a text embedding vector via the OpenAI-compatible /v1/embeddings endpoint.
        Works with Ollama (and any other compatible embedding server).
        """
        url = f"{self._ollama_base_url()}/embeddings"
        try:
            r = requests.post(
                url,
                json={"model": self._embedding_model(), "input": text},
                timeout=30,
                verify=_tls_verify(),
            )
            r.raise_for_status()
            return r.json()["data"][0]["embedding"]
        except Exception as exc:
            logger.error("[Embedding error] model=%s url=%s: %s",
                         self._embedding_model(), url, exc)
            return []

    def call_llm(self, prompt_text: str) -> str:
        """
        Call the LLM via the OpenAI-compatible /chat/completions endpoint.
        Supports both Ollama and Gemini — reads base_url / api_key from agent_config.conf.
        """
        provider_name = self.provider.lower()

        if provider_name == "gemini":
            base_url = self._cfg.get(
                'gemini', 'base_url',
                fallback='https://generativelanguage.googleapis.com/v1beta/openai/'
            ).rstrip('/')
            api_key = self._resolve_key('gemini')
        else:
            base_url = self._ollama_base_url()
            api_key = self._resolve_key('ollama') or 'ollama'

        url = f"{base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt_text}],
            # Ask for JSON output (supported by Ollama; Gemini ignores gracefully)
            "response_format": {"type": "json_object"},
        }

        try:
            r = requests.post(
                url,
                headers={"Authorization": f"Bearer {api_key}",
                         "Content-Type": "application/json"},
                json=payload,
                timeout=60,
                verify=_tls_verify(),
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.error("[LLM call_llm error] provider=%s url=%s: %s",
                         provider_name, url, exc)
            return json.dumps({"error": f"LLM call failed: {exc}"})


if __name__ == "__main__":
    dispatch(LLMRAGCommand, sys.argv, sys.stdin, sys.stdout, __name__)
