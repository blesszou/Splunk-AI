import sys
import os
import time
import json
import asyncio
import queue
import threading
import configparser
import logging

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

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [AIAgent] %(message)s',
    stream=sys.stderr
)

CA_TRUST_STORE = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'openssl', 'cert.pem')
_ssl_cert_file = os.environ.get("SSL_CERT_FILE", "")
if _ssl_cert_file and not os.path.exists(_ssl_cert_file):
    del os.environ["SSL_CERT_FILE"]

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
        """Read configuration for the specified AI provider."""
        try:
            app_name = self._metadata.searchinfo.app
            splunk_home = os.environ.get('SPLUNK_HOME')
            if not splunk_home:
                logger.error("SPLUNK_HOME environment variable is not set")
                raise EnvironmentError("SPLUNK_HOME is not set")

            config_path = os.path.join(splunk_home, 'etc', 'apps', app_name, 'default', 'agent_config.conf')

            if not os.path.exists(config_path):
                logger.error(f"Configuration file not found: {config_path}")
                raise FileNotFoundError(f"Config file not found: {config_path}")

            config = configparser.ConfigParser()
            config.read(config_path)

            if provider_name not in config:
                logger.error(f"Provider '{provider_name}' not found in configuration")
                raise KeyError(f"Provider '{provider_name}' not configured")

            conf = dict(config[provider_name])

            # Validate required fields
            if 'model_name' not in conf:
                raise ValueError(f"'model_name' is required for provider '{provider_name}'")

            if provider_name.lower() == "gemini" and 'api_key' not in conf:
                raise ValueError(f"'api_key' is required for Gemini provider")

            if provider_name.lower() != "gemini" and 'base_url' not in conf:
                raise ValueError(f"'base_url' is required for provider '{provider_name}'")

            logger.info(f"Successfully loaded config for provider: {provider_name}")
            return conf

        except Exception as e:
            logger.error(f"Failed to read configuration: {str(e)}")
            raise

    async def run_agent_async(self, service, ui_queue):
        """Run the AI agent asynchronously with error handling."""
        try:
            conf = self._get_config(self.provider)

            if self.provider.lower() == "gemini":
                model = GoogleModel(model=conf.get("model_name"), api_key=conf.get("api_key"))
                logger.info(f"Initialized Gemini model: {conf.get('model_name')}")
            else:
                model = OpenAIModel(model=conf.get("model_name"), base_url=conf.get("base_url"), api_key="ignored")
                logger.info(f"Initialized OpenAI-compatible model: {conf.get('model_name')} at {conf.get('base_url')}")

            @before_model
            def emit_thinking(req: ModelRequest) -> None:
                try:
                    ui_queue.put({'type': '🔄 Thinking...', 'content': 'Agent is planning...'}, timeout=5)
                except queue.Full:
                    logger.warning("Queue full, dropping thinking event")

            @after_model
            def emit_thought(resp: ModelResponse) -> None:
                try:
                    text = _extract_text(resp.message.content)
                    if text:
                        ui_queue.put({'type': '🤔 Agent Reasoning', 'content': text}, timeout=5)
                except queue.Full:
                    logger.warning("Queue full, dropping reasoning event")
                except Exception as e:
                    logger.error(f"Error extracting thought: {str(e)}")

            @tool_middleware
            async def intercept_tool(request: ToolRequest, handler: ToolMiddlewareHandler) -> ToolResponse:
                try:
                    ui_queue.put({'type': '⚙️ Executing Query', 'content': str(request.call.args)}, timeout=5)
                    resp = await handler(request)
                    ui_queue.put({'type': '👀 Observation', 'content': 'Query executed.'}, timeout=5)
                    return resp
                except queue.Full:
                    logger.warning("Queue full, dropping tool event")
                    return await handler(request)
                except Exception as e:
                    logger.error(f"Error in tool middleware: {str(e)}")
                    raise

            async with Agent(
                    model=model,
                    system_prompt="You are a helpful Splunk security analyst. Use run_splunk_query to search Splunk data and answer the user's question accurately.",
                    service=service,
                    tool_settings=ToolSettings(local=True, remote=None),
                    middleware=[emit_thinking, emit_thought, intercept_tool]
            ) as agent:
                result = await agent.invoke([HumanMessage(content=self.prompt)])
                ui_queue.put({'type': '✅ Final Report', 'content': _extract_text(result.final_message.content)},
                             timeout=5)

        except Exception as e:
            logger.error(f"Agent execution failed: {str(e)}", exc_info=True)
            try:
                ui_queue.put({
                    'type': '❌ Error',
                    'content': f"Agent failed: {str(e)}"
                }, timeout=5)
            except queue.Full:
                logger.error("Queue full, cannot report error")
        finally:
            ui_queue.put(None)

    def generate(self):
        """Generate results for the search command."""
        session_key = None
        try:
            session_key = self._metadata.searchinfo.session_key
            if not session_key:
                raise ValueError("No session key available")

            service = client.connect(token=session_key)
            logger.info("Connected to Splunk service")

            # Use bounded queue to prevent memory issues
            ui_queue = queue.Queue(maxsize=1000)

            # Start agent in daemon thread so it won't block Splunk shutdown
            agent_thread = threading.Thread(
                target=lambda: asyncio.run(self.run_agent_async(service, ui_queue)),
                daemon=True,
                name=f"AIAgent-{id(self)}"
            )
            agent_thread.start()
            logger.debug("Started agent thread")

            step = 1
            while True:
                try:
                    # Add timeout to prevent infinite blocking
                    event = ui_queue.get(timeout=300)  # 5 minute timeout
                    if event is None:
                        logger.info("Agent completed successfully")
                        break

                    event.update({'_time': time.time(), 'step': step})
                    yield event
                    step += 1

                except queue.Empty:
                    logger.error("Agent timed out after 5 minutes")
                    yield {
                        '_time': time.time(),
                        'step': step,
                        'type': '❌ Timeout',
                        'content': 'Agent execution timed out after 5 minutes'
                    }
                    break

        except Exception as e:
            logger.error(f"Search command failed: {str(e)}", exc_info=True)
            yield {
                '_time': time.time(),
                'step': 0,
                'type': '❌ Fatal Error',
                'content': f"Command failed: {str(e)}"
            }


if __name__ == "__main__":
    dispatch(AIAgentCommand, sys.argv, sys.stdin, sys.stdout, __name__)
