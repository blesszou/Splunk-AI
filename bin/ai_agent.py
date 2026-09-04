import sys
import os
import time
import json
import asyncio
import queue
import threading
import configparser
import logging
import urllib.parse

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

from ai_secrets import resolve_api_key
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client

from splunklib.ai import Agent, GoogleModel, OpenAIModel, AnthropicModel
from splunklib.ai.messages import HumanMessage, AIMessage
from splunklib.ai.tool_settings import ToolSettings, RemoteToolSettings, ToolAllowlist
from splunklib.ai.hooks import before_model, after_model
from splunklib.ai.middleware import (
    ModelRequest, ModelResponse, tool_middleware, ToolMiddlewareHandler, ToolRequest, ToolResponse
)


def _extract_text(content, extras=None) -> str:
    """Handles str, TextBlock, list of TextBlock, or reasoning_content/thought in extras."""
    text = ""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(
            block.text if hasattr(block, 'text') else str(block)
            for block in content if block
        )
    elif hasattr(content, 'text'):
        text = str(content.text)
    elif content is not None:
        text = str(content)

    if not text.strip() and extras and isinstance(extras, dict):
        text = extras.get("thought") or extras.get("reasoning_content") or ""

    return text.strip()


def _format_exception(e: BaseException) -> str:
    """Recursively unwraps ExceptionGroup / TaskGroup to expose the true root-cause error."""
    if hasattr(e, 'exceptions') and getattr(e, 'exceptions'):
        sub_errors = [_format_exception(sub) for sub in getattr(e, 'exceptions')]
        return " | ".join(sub_errors)
    return str(e)


@Configuration()
class AIAgentCommand(GeneratingCommand):
    prompt = Option(require=True, doc="The prompt / task instruction for the agent")
    llm_connection = Option(require=False, default="", doc="Name of the LLM connection configured in AI Toolkit (Splunk_ML_Toolkit)")
    model = Option(require=False, default="", doc="Model name (e.g. 'gemma4', 'qwen2.5:14b'). Overrides connection or config default.")
    mcp_connection = Option(require=False, default="", doc="Name of the MCP connection configured in AI Toolkit ('local_mcp', 'local', or remote connection name)")
    provider = Option(require=False, default="gemini", doc="Fallback provider from agent_config.conf ('gemini' or 'ollama')")
    timeout = Option(require=False, default=900, validate=validators.Integer(), doc="Execution timeout in seconds (default: 900)")
    mcp_tools = Option(require=False, default="", doc="Optional: explicit filter for remote MCP tools (comma-separated, or 'all')")
    local_tools = Option(require=False, default=True, validate=validators.Boolean(), doc="Enable local tools in bin/tools.py")

    def _get_aitk_llm_model(self, service, connection_name: str):
        """Fetch LLM connection configuration from Splunk_ML_Toolkit KV Store and Passwords."""
        logger.info("Querying AI Toolkit (Splunk_ML_Toolkit) for LLM connection: '%s'", connection_name)
        
        # 1. Fetch connection metadata from Splunk_ML_Toolkit KV Store
        endpoint = "/servicesNS/nobody/Splunk_ML_Toolkit/storage/collections/data/aitk_llm_connection"
        
        records = []
        try:
            query_val = json.dumps({"name": connection_name})
            resp = service.get(endpoint, query=query_val, output_mode="json")
            records = json.loads(resp.body.read().decode('utf-8'))
        except Exception as e:
            logger.warning("Targeted query failed (%s), trying full collection retrieval...", e)
            try:
                resp = service.get(endpoint, output_mode="json")
                all_records = json.loads(resp.body.read().decode('utf-8'))
                records = [r for r in all_records if str(r.get("name", "")).strip().lower() == connection_name.strip().lower()]
            except Exception as e2:
                logger.error("Failed to query aitk_llm_connection from Splunk_ML_Toolkit: %s", e2)
                raise ValueError(f"Could not retrieve AI Toolkit connections: {e2}")
            
        if not records:
            raise ValueError(f"LLM connection '{connection_name}' was not found in Splunk_ML_Toolkit (AI Toolkit).")
            
        config_doc = records[0]
        provider = (config_doc.get("provider") or "").lower()
        # Only allow custom model override for Ollama or custom providers; keep AITK model for cloud connections
        if self.model and "ollama" in provider:
            model_name = self.model.strip()
        else:
            model_name = config_doc.get("model") or ""
            
        conn_details = config_doc.get("connection_details", {})
        base_url = conn_details.get("base_url") or conn_details.get("endpoint") or ""
        
        # 2. Fetch secret (API Key / Token) from storage/passwords across Splunk_ML_Toolkit namespace
        api_key = ""
        try:
            pw_endpoints = [
                "/servicesNS/nobody/Splunk_ML_Toolkit/storage/passwords",
                "/servicesNS/nobody/-/storage/passwords",
                "/services/storage/passwords"
            ]
            for ep in pw_endpoints:
                try:
                    resp = service.get(ep, output_mode="json")
                    pw_data = json.loads(resp.body.read().decode('utf-8'))
                    for entry in pw_data.get("entry", []):
                        content = entry.get("content", {})
                        realm = content.get("realm", "")
                        username = content.get("username", "")
                        clear_pw = content.get("clear_password", "")
                        if username == connection_name or (realm == "aitk_llm_secrets" and username == connection_name):
                            api_key = clear_pw
                            break
                    if api_key:
                        break
                except Exception as ep_err:
                    logger.debug("Endpoint %s failed: %s", ep, ep_err)
        except Exception as e:
            logger.warning("Could not read storage_passwords for '%s': %s", connection_name, e)

        # 3. Fallback checks if secret not in storage_passwords
        if not api_key:
            api_key = conn_details.get("access_token") or conn_details.get("api_key") or ""
            
        if not api_key:
            # Fallback to the splunk_ai credential store (then agent_config.conf)
            try:
                local_cfg = self._read_local_agent_config()
                api_key = self._resolve_key(
                    provider, local_cfg.get(provider, {}).get('api_key')
                )
            except Exception as e:
                logger.debug("No fallback API key for provider '%s': %s", provider, e)

        logger.info("Resolved AITK LLM Connection: provider=%s, model=%s, has_api_key=%s", 
                    provider, model_name, bool(api_key and api_key != "none"))

        # 4. Instantiate corresponding splunklib.ai Model
        if "gemini" in provider or "google" in provider:
            return GoogleModel(model=model_name, api_key=api_key or None)
        elif "anthropic" in provider or "claude" in provider:
            return AnthropicModel(model=model_name, api_key=api_key, base_url=base_url or "https://api.anthropic.com")
        elif "ollama" in provider:
            ollama_url = base_url or "http://localhost:11434/v1"
            return OpenAIModel(
                model=model_name, 
                base_url=ollama_url, 
                api_key=api_key or "ollama",
                extra_body={"options": {"num_ctx": 8192}}
            )
        else:
            # OpenAI / Azure / Custom OpenAI-compatible
            openai_url = base_url or "https://api.openai.com/v1"
            return OpenAIModel(model=model_name, base_url=openai_url, api_key=api_key or "none")

    def _read_local_agent_config(self) -> dict:
        """Read dict from default/agent_config.conf relative to this script."""
        bin_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.normpath(os.path.join(bin_dir, '..', 'default', 'agent_config.conf'))
        cfg = configparser.ConfigParser()
        cfg.read(config_path)
        return {s: dict(cfg[s]) for s in cfg.sections()}

    def _resolve_key(self, provider_name: str, conf_value: str | None) -> str:
        """Fetch the provider's API key from storage/passwords (requires passauth)."""
        info = self._metadata.searchinfo
        return resolve_api_key(provider_name, info.session_key, conf_value, app=info.app)

    def _get_agent_config_model(self, provider_name: str):
        """Read fallback model configuration from agent_config.conf."""
        try:
            config = self._read_local_agent_config()
            if provider_name not in config:
                raise KeyError(f"Provider '{provider_name}' not configured in agent_config.conf")

            conf = config[provider_name]
            api_key = self._resolve_key(provider_name, conf.get("api_key"))

            if provider_name.lower() == "gemini":
                model_name = self.model.strip() if self.model else conf.get("model_name")
                if not model_name:
                    raise ValueError(f"'model_name' is required for provider '{provider_name}'")
                return GoogleModel(model=model_name, api_key=api_key)
            else:
                model_name = self.model.strip() if self.model else conf.get("model_name")
                if not model_name:
                    raise ValueError(f"'model_name' is required for provider '{provider_name}'")
                base_url = conf.get("base_url", "http://localhost:11434/v1")
                api_key = api_key or "ollama"
                return OpenAIModel(
                    model=model_name, 
                    base_url=base_url, 
                    api_key=api_key,
                    extra_body={"options": {"num_ctx": 8192}}
                )

        except Exception as e:
            logger.error("Failed to read agent_config.conf: %s", e)
            raise

    def _get_aitk_mcp_tool_settings(self, service, mcp_name: str) -> ToolSettings:
        """Resolve ToolSettings from Splunk_ML_Toolkit MCP connection configuration."""
        clean_name = mcp_name.strip()
        logger.info("Resolving MCP connection '%s'", clean_name)

        # 1. Handle local MCP cases
        if clean_name.lower() in ("local", "local_mcp"):
            return ToolSettings(local=True, remote=None)

        # 2. Handle 'all' case (enable both local and all remote MCP tools)
        if clean_name.lower() == "all":
            return ToolSettings(
                local=True,
                remote=RemoteToolSettings(
                    allowlist=ToolAllowlist(custom_predicate=lambda _: True)
                )
            )

        # 3. Query aitk_mcp_collection in Splunk_ML_Toolkit
        endpoint = "/servicesNS/nobody/Splunk_ML_Toolkit/storage/collections/data/aitk_mcp_collection"
        
        allowed_tools = []
        try:
            query_val = json.dumps({"name": clean_name})
            resp = service.get(endpoint, query=query_val, output_mode="json")
            records = json.loads(resp.body.read().decode('utf-8'))
            if not records:
                # Fallback scan all records
                resp_all = service.get(endpoint, output_mode="json")
                all_recs = json.loads(resp_all.body.read().decode('utf-8'))
                records = [r for r in all_recs if str(r.get("name", "")).strip().lower() == clean_name.lower()]

            if records:
                mcp_doc = records[0]
                details = mcp_doc.get("details", {})
                allowed_tools = details.get("tools", [])
                logger.info("Found AITK MCP connection '%s' (type=%s, tools=%s)", 
                            clean_name, mcp_doc.get("type"), len(allowed_tools))
            else:
                logger.warning("MCP connection '%s' not found in aitk_mcp_collection; connecting to Splunk MCP directly", clean_name)
        except Exception as e:
            logger.warning("Failed to query aitk_mcp_collection: %s", e)

        # Build remote allowlist: if specific tools defined, use them; otherwise allow all tools from MCP
        if allowed_tools:
            allowlist = ToolAllowlist(names=allowed_tools)
        else:
            allowlist = ToolAllowlist(custom_predicate=lambda _: True)

        return ToolSettings(
            local=bool(self.local_tools),
            remote=RemoteToolSettings(allowlist=allowlist)
        )

    def _build_tool_settings(self, service) -> ToolSettings:
        """Construct ToolSettings based on mcp_connection or mcp_tools options."""
        if self.mcp_connection:
            return self._get_aitk_mcp_tool_settings(service, self.mcp_connection)

        # Fallback to mcp_tools parameter if specified
        remote_settings = None
        if self.mcp_tools:
            mcp_tools_str = self.mcp_tools.strip()
            if mcp_tools_str.lower() in ("all", "*", "true"):
                remote_settings = RemoteToolSettings(
                    allowlist=ToolAllowlist(custom_predicate=lambda _: True)
                )
            else:
                tool_names = [t.strip() for t in mcp_tools_str.split(",") if t.strip()]
                remote_settings = RemoteToolSettings(
                    allowlist=ToolAllowlist(names=tool_names)
                )

        return ToolSettings(
            local=bool(self.local_tools),
            remote=remote_settings
        )

    async def run_agent_async(self, service, ui_queue):
        """Run the AI agent asynchronously with error handling."""
        try:
            # 1. Resolve LLM Model (AITK connection has higher precedence, fallback to agent_config.conf)
            if self.llm_connection:
                model = self._get_aitk_llm_model(service, self.llm_connection)
                ui_queue.put({'type': '🔄 Thinking...', 'content': f"Loaded AI Toolkit LLM connection: '{self.llm_connection}'"}, timeout=5)
            else:
                model = self._get_agent_config_model(self.provider)
                ui_queue.put({'type': '🔄 Thinking...', 'content': f"Loaded fallback provider '{self.provider}' from agent_config.conf"}, timeout=5)

            # 2. Build MCP Tool Settings
            tool_settings = self._build_tool_settings(service)
            mcp_desc = self.mcp_connection or ("Remote + Local" if tool_settings.remote else "Local Tools")
            ui_queue.put({'type': '⚙️ MCP Config', 'content': f"MCP Mode: {mcp_desc} (tools autonomously chosen by LLM)"}, timeout=5)

            last_reasoning_text = ""

            # 3. Agent Hook & Middleware Listeners
            @before_model
            def emit_thinking(req: ModelRequest) -> None:
                try:
                    ui_queue.put({'type': '🔄 Thinking...', 'content': 'Agent is planning next step...'}, timeout=5)
                except queue.Full:
                    logger.warning("Queue full, dropping thinking event")

            @after_model
            def emit_thought(resp: ModelResponse) -> None:
                nonlocal last_reasoning_text
                try:
                    text = _extract_text(resp.message.content, getattr(resp.message, 'extras', None))
                    if text:
                        last_reasoning_text = text
                        ui_queue.put({'type': '🤔 Agent Reasoning', 'content': text}, timeout=5)
                except queue.Full:
                    logger.warning("Queue full, dropping reasoning event")
                except Exception as e:
                    logger.error(f"Error extracting thought: {str(e)}")

            @tool_middleware
            async def intercept_tool(request: ToolRequest, handler: ToolMiddlewareHandler) -> ToolResponse:
                try:
                    tool_name = getattr(request.call, 'name', 'tool')
                    ui_queue.put({'type': '⚙️ Executing Query', 'content': f"Calling tool [{tool_name}] with args: {str(request.call.args)}"}, timeout=5)
                    resp = await handler(request)
                    ui_queue.put({'type': '👀 Observation', 'content': f"Tool [{tool_name}] executed successfully."}, timeout=5)
                    return resp
                except queue.Full:
                    logger.warning("Queue full, dropping tool event")
                    return await handler(request)
                except Exception as e:
                    logger.error(f"Error in tool middleware: {str(e)}")
                    raise

            # 4. Invoke Agent
            async with Agent(
                    model=model,
                    system_prompt=(
                        "You are an expert Splunk Security & Platform Auditor AI Agent with autonomous ReAct (Reason + Act) capabilities. "
                        "You have access to the 'run_splunk_query' tool to query and inspect Splunk data.\n\n"
                        "INVESTIGATION BEST PRACTICES:\n"
                        "1. Efficient Aggregate SPL: Instead of running multiple separate queries for different counts or values, write comprehensive aggregate SPL queries (e.g. 'index=ccure earliest=0 | stats count by sourcetype, action, status' or '| top limit=20 ...') to obtain all statistics in 1-2 powerful searches.\n"
                        "2. Time Windows: Splunk demo environments often contain historical logs. Use 'earliest=0' (all time) or 'earliest=-30d' when exploring if recent searches return no events.\n"
                        "3. Read-Only Guardrail: your searches are restricted to read-only SPL. Commands that write, send, or execute (delete, outputlookup, collect, sendemail, script, rest, savedsearch, and similar) plus macro calls will be refused. Investigate with search, stats, top, timechart, table and similar reporting commands.\n"
                        "4. Conclude with Final Report: Once you have gathered sufficient log evidence, analyze the numbers and write a comprehensive, structured Final Report covering: incident overview, event counts & distributions, affected users/devices, root causes, and security recommendations."
                    ),
                    service=service,
                    tool_settings=tool_settings,
                    middleware=[emit_thinking, emit_thought, intercept_tool]
            ) as agent:
                result = await agent.invoke([HumanMessage(content=self.prompt)])
                
                # Robust extraction of final message content
                final_content = _extract_text(result.final_message.content, getattr(result.final_message, 'extras', None))
                
                # If final message is empty, search backwards through message history
                if not final_content and hasattr(result, 'messages'):
                    for msg in reversed(result.messages):
                        if isinstance(msg, AIMessage):
                            cand = _extract_text(msg.content, getattr(msg, 'extras', None))
                            if cand:
                                final_content = cand
                                break
                                
                # Fallback to last recorded reasoning text or summary
                if not final_content and last_reasoning_text:
                    final_content = last_reasoning_text
                    
                if not final_content:
                    final_content = "Investigation completed. All target SPL searches and observations were executed successfully."
                    
                ui_queue.put({'type': '✅ Final Report', 'content': final_content}, timeout=5)

        except Exception as e:
            err_msg = _format_exception(e)
            logger.error(f"Agent execution failed: {err_msg}", exc_info=True)
            try:
                ui_queue.put({
                    'type': '❌ Error',
                    'content': f"Agent failed: {err_msg}"
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

            ui_queue = queue.Queue(maxsize=1000)

            agent_thread = threading.Thread(
                target=lambda: asyncio.run(self.run_agent_async(service, ui_queue)),
                daemon=True,
                name=f"AIAgent-{id(self)}"
            )
            agent_thread.start()
            logger.debug("Started agent thread")

            step = 1
            max_seconds = int(self.timeout) if self.timeout and int(self.timeout) > 0 else 900
            deadline = time.time() + max_seconds  # Configurable timeout (default 15 mins)
            while True:
                try:
                    event = ui_queue.get(timeout=30)
                    if event is None:
                        logger.info("Agent completed successfully")
                        break

                    event.update({'_time': time.time(), 'step': step})
                    yield event
                    step += 1

                except queue.Empty:
                    if not agent_thread.is_alive():
                        logger.warning("Agent thread ended without sentinel")
                        break

                    if time.time() >= deadline:
                        mins = max_seconds // 60
                        logger.error("Agent timed out after %d minutes", mins)
                        yield {
                            '_time': time.time(),
                            'step': step,
                            'type': '❌ Timeout',
                            'content': f'Agent execution timed out after {mins} minutes'
                        }
                        break

                    logger.debug("Emitting heartbeat to prevent search auto-cancel")
                    yield {
                        '_time': time.time(),
                        'step': step,
                        'type': '⏳ Working...',
                        'content': 'Agent is processing, please wait...'
                    }
                    step += 1

        except Exception as e:
            err_msg = _format_exception(e)
            logger.error(f"Search command failed: {err_msg}", exc_info=True)
            yield {
                '_time': time.time(),
                'step': 0,
                'type': '❌ Fatal Error',
                'content': f"Command failed: {err_msg}"
            }


if __name__ == "__main__":
    dispatch(AIAgentCommand, sys.argv, sys.stdin, sys.stdout, __name__)
