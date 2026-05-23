#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import json
import asyncio
import queue
import threading
import configparser

app_bin_dir = os.path.dirname(os.path.abspath(__file__))
lib_dir = os.path.join(app_bin_dir, 'lib')
if lib_dir not in sys.path:
    sys.path.insert(0, lib_dir)

import importlib.metadata
try:
    _original_version = importlib.metadata.version

    def _mock_version(package_name):
        if package_name == "splunk-sdk": return "3.0.0"
        return _original_version(package_name)

    importlib.metadata.version = _mock_version
except Exception:
    pass

CA_TRUST_STORE = "/opt/splunk/openssl/cert.pem"
if os.environ.get("SSL_CERT_FILE") == CA_TRUST_STORE and not os.path.exists(CA_TRUST_STORE):
    os.environ["SSL_CERT_FILE"] = ""

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
import splunklib.client as client

from splunklib.ai import Agent, GoogleModel, OpenAIModel
from splunklib.ai.messages import HumanMessage
from splunklib.ai.tool_settings import ToolSettings
from splunklib.ai.hooks import before_model, after_model
from splunklib.ai.middleware import (
    ModelRequest, ModelResponse, tool_middleware, ToolMiddlewareHandler, ToolRequest, ToolResponse
)


def _extract_text(content) -> str:
    """Handles str, TextBlock, or list of TextBlock from model responses."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.text if hasattr(block, 'text') else str(block)
            for block in content
        )
    if hasattr(content, 'text'):
        return content.text
    return str(content)


@Configuration()
class AIAgentCommand(GeneratingCommand):
    prompt = Option(require=True)
    provider = Option(require=False, default="gemini")

    def _get_config(self, provider_name):
        app_name = self._metadata.searchinfo.app
        config = configparser.ConfigParser()
        config.read(os.path.join(
            os.environ.get('SPLUNK_HOME', '/opt/splunk'),
            'etc', 'apps', app_name, 'default', 'agent_config.conf'
        ))
        return dict(config[provider_name])

    async def run_agent_async(self, service, ui_queue):
        conf = self._get_config(self.provider)

        if self.provider.lower() == "gemini":
            model = GoogleModel(model=conf.get("model_name"), api_key=conf.get("api_key"))
        else:
            model = OpenAIModel(model=conf.get("model_name"), base_url=conf.get("base_url"), api_key="ignored")

        @before_model
        def emit_thinking(req: ModelRequest) -> None:
            ui_queue.put({'type': '🔄 Thinking...', 'content': 'Agent is planning...'})

        @after_model
        def emit_thought(resp: ModelResponse) -> None:
            text = _extract_text(resp.message.content)
            if text:
                ui_queue.put({'type': '🤔 Agent Reasoning', 'content': text})

        @tool_middleware
        async def intercept_tool(request: ToolRequest, handler: ToolMiddlewareHandler) -> ToolResponse:
            ui_queue.put({'type': '⚙️ Executing Query', 'content': str(request.call.args)})
            resp = await handler(request)
            ui_queue.put({'type': '👀 Observation', 'content': 'Query executed.'})
            return resp

        async with Agent(
            model=model,
            system_prompt="You are a helpful Splunk security analyst. Use run_splunk_query to search Splunk data and answer the user's question accurately.",
            service=service,
            tool_settings=ToolSettings(local=True, remote=None),
            middleware=[emit_thinking, emit_thought, intercept_tool]
        ) as agent:
            result = await agent.invoke([HumanMessage(content=self.prompt)])
            ui_queue.put({'type': '✅ Final Report', 'content': _extract_text(result.final_message.content)})
        ui_queue.put(None)

    def generate(self):
        session_key = self._metadata.searchinfo.session_key
        service = client.connect(token=session_key)
        ui_queue = queue.Queue()
        threading.Thread(target=lambda: asyncio.run(self.run_agent_async(service, ui_queue))).start()
        step = 1
        while True:
            event = ui_queue.get()
            if event is None: break
            event.update({'_time': time.time(), 'step': step})
            yield event
            step += 1


if __name__ == "__main__":
    dispatch(AIAgentCommand, sys.argv, sys.stdin, sys.stdout, __name__)