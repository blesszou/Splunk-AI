#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_secrets.py — resolve LLM API keys from Splunk's encrypted credential store.
==============================================================================
API keys must never be stored in agent_config.conf: that file lives in the app
directory, is world-readable to anyone with filesystem access, and is trivially
swept into a git commit or an app package.

Store the key once via storage/passwords instead (realm ``splunk_ai``, username
= provider name), and this module will retrieve it at search time:

    curl -k -u <admin> \\
      https://localhost:8089/servicesNS/nobody/splunk_ai/storage/passwords \\
      -d realm=splunk_ai -d name=gemini -d password='<YOUR_KEY>'

Requires ``passauth = true`` in commands.conf so the search command receives a
session key it can use to read the credential store.
"""

import logging
import os
import sys

_app_bin = os.path.dirname(os.path.abspath(__file__))
_lib_dir = os.path.join(_app_bin, "lib")
if _lib_dir not in sys.path:
    sys.path.insert(0, _lib_dir)

import splunklib.client as client

logger = logging.getLogger(__name__)

REALM = "splunk_ai"

# Providers that talk to a local, unauthenticated endpoint and need no secret.
_KEYLESS_PROVIDERS = {"ollama"}

# Placeholder values that mean "no key was configured".
_EMPTY_VALUES = {"", "none", "null", "changeme", "<your-api-key>"}


def _is_empty(value) -> bool:
    return not value or str(value).strip().lower() in _EMPTY_VALUES


def resolve_api_key(provider: str, session_key: str,
                    conf_value: str | None = None,
                    app: str = "splunk_ai") -> str:
    """
    Return the API key for ``provider``, preferring Splunk's credential store.

    Lookup order:
      1. storage/passwords, realm=splunk_ai, username=<provider>
      2. ``conf_value`` from agent_config.conf — deprecated, logs a warning
      3. "" for keyless providers such as Ollama, otherwise raises ValueError
    """
    provider = (provider or "").strip().lower()

    if session_key:
        try:
            service = client.connect(token=session_key, owner="nobody", app=app)
            for cred in service.storage_passwords:
                if cred.realm == REALM and cred.username == provider:
                    if not _is_empty(cred.clear_password):
                        logger.info("Resolved API key for provider '%s' from storage/passwords",
                                    provider)
                        return cred.clear_password
            logger.debug("No storage/passwords entry for realm=%s username=%s", REALM, provider)
        except Exception as exc:
            logger.warning("Could not read storage/passwords for provider '%s': %s",
                           provider, exc)

    if not _is_empty(conf_value):
        logger.warning(
            "Provider '%s' is using an API key from agent_config.conf. This is insecure — "
            "the key is stored in plaintext on disk. Migrate it to storage/passwords "
            "(realm=%s, username=%s) and remove it from the conf file.",
            provider, REALM, provider,
        )
        return str(conf_value).strip()

    if provider in _KEYLESS_PROVIDERS:
        return ""

    raise ValueError(
        f"No API key found for provider '{provider}'. Store one with:\n"
        f"  curl -k -u <admin> "
        f"https://localhost:8089/servicesNS/nobody/{app}/storage/passwords "
        f"-d realm={REALM} -d name={provider} -d password='<YOUR_KEY>'"
    )
