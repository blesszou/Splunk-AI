# Splunk AI Toolkit Showcase 🤖🔍

Welcome to the **Splunk AI Toolkit Showcase**. This application is a gallery designed to
demonstrate the integration of Generative AI (LLMs) with Splunk Enterprise. Each dashboard
is a self-contained example built on a *different* architectural approach, so you can compare
the trade-offs side by side.

All sample data ships with the app as lookups — **Splunk Enterprise Security is not required.**

## ✨ Showcase Gallery (Use Cases)

Seven dashboards, each demonstrating a different way to reach an AI model from inside Splunk:

* **Case 1: LLM-enhanced analysis**
  LLM-enhanced security event analysis and automated Indicator of Compromise (IOC) extraction
  from raw, unstructured log data.

* **Case 2: Multi-model collaboration**
  A multi-model collaborative workflow. Three different models hand off tasks to each other to
  perform threat hunting and enrich security context.

* **Case 3: Vector search in LLM (RAG Pipeline)**
  A Retrieval-Augmented Generation pipeline using vector search (Milvus) to look up an internal
  knowledge base of historical incidents and route an event to the responsible team.

* **Case 4: Hand-rolled ReAct Auditor**
  Autonomous platform auditing via a ReAct loop implemented from scratch on top of OpenAI-style
  tool calling. Useful as a contrast to Case 7: same goal, no SDK, no MCP.
  *(Note: despite the `mcpagent` command name, this case does not use MCP — the `mcp_server`
  option is reserved and unused. See Case 7 for the real MCP integration.)*

* **Case 5: Talk to Your Logs (AI Chat)**
  A multi-turn conversational interface that reasons over your *actual* log payload, with
  conversation memory persisted in the KV Store.

* **Case 6: Dynamic Alert Triage & Playbook Generation**
  Click any raw security alert to trigger a "Tier 3" analysis. The model reasons over the
  context, generates a markdown Investigation Playbook (including ready-to-run SPL for further
  hunting), and drafts a formatted JIRA ticket for copy-pasting.

* **Case 7: Autonomous SOC Agent**
  A true agentic workflow using the ReAct framework on the `splunklib.ai` SDK. The agent pulls
  data through an MCP server and streams its "Chain of Thought" to the dashboard in real time as
  it plans, executes SPL, and analyzes observations to reach a verdict.

## ⚙️ Prerequisites

| | Requirement | Needed by |
|---|---|---|
| 1 | **Splunk Enterprise** 9.x / 10.x with the built-in Python 3 | All cases |
| 2 | **Splunk AI Toolkit** (app namespace `Splunk_ML_Toolkit`) — provides the `\| ai` command | **Cases 1, 2**, and the LLM/MCP connection picker in Case 7 |
| 3 | **Ollama** running locally | Cases 1–7 (default provider) |
| 4 | **Milvus** vector database | **Case 3** only |
| 5 | **Splunk MCP server** | **Case 7** only |
| 6 | **Google Gemini API key** | Optional — only if you select the Gemini provider |

> Cases 1 and 2 will fail with `Unknown search command 'ai'` if the Splunk AI Toolkit is not
> installed. It is a separate app and is **not** bundled here.

## 🚀 Installation & Configuration

### 1. Build the dependencies

`bin/lib` holds this app's Python dependencies. It is a build artifact and is **not** tracked in
git, because it contains platform-specific compiled extensions (`.so`) that fail macOS hardened
runtime library validation when copied between machines. Build it in place instead:

```bash
./build.sh              # installs the pinned set from requirements.lock.txt
./build.sh --freeze     # re-resolve from requirements.txt and rewrite the lock
```

The script requires Python 3.13+ and defaults to `$SPLUNK_HOME/bin/python3`, matching
`python.required` in `commands.conf`. Override with `SPLUNK_PYTHON=/path/to/python3`.

Each run wipes `bin/lib` before installing. That is deliberate: installing over an existing tree
is what left the directory with three different `openai` dist-info folders and two each of
`anyio`, `certifi`, `idna` and `tqdm`, which makes `importlib.metadata` report wrong versions.

### 2. Pull the local models

The showcase uses several specific models to demonstrate multi-model collaboration and
security-tuned reasoning:

```bash
ollama pull gemma4                                                          # Cases 5, 6, 7 (default)
ollama pull hf.co/DevQuasar/fdtn-ai.Foundation-Sec-8B-Instruct-GGUF:Q4_K_M  # Cases 1, 2
ollama pull aya:8b-23                                                       # Case 2
ollama pull llama3:latest                                                   # Cases 2, 3
ollama pull qwen3:latest                                                    # Case 4
ollama pull all-minilm:latest                                               # Case 3 (embeddings)
```

`gemma4` is the default for every case that reads `agent_config.conf` (5, 6, 7). The other
models are pinned per-dashboard in the SPL, so a case will fail if its specific model is absent.

Verify with `ollama list` before opening the dashboards — a missing model surfaces as an opaque
LLM error rather than a clear "model not found".

**The embedding model is not interchangeable.** `bin/init_milvus.py` creates the Milvus
collection with `dimension: 384`, which matches `all-minilm`. Substituting a different embedding
model (e.g. `nomic-embed-text`, which outputs 768 dimensions) requires changing that dimension
and re-running `init_milvus.py` to rebuild the collection.

### 3. Review `default/agent_config.conf`

Endpoints and default model names live here. Defaults assume Ollama on `localhost:11434` and
Milvus on `127.0.0.1:19530`.

### 4. Store your API key (only if using Gemini)

**Never put an API key in `agent_config.conf`.** Keys are read from Splunk's encrypted
credential store at search time (see `bin/ai_secrets.py`). Register yours once:

```bash
curl -k -u <admin> \
  https://localhost:8089/servicesNS/nobody/splunk_ai/storage/passwords \
  -d realm=splunk_ai -d name=gemini -d password='<YOUR_KEY>'
```

Reading the credential store requires the `list_storage_passwords` capability, so run the
Gemini-backed dashboards as a user who has it.

### 5. Point Case 7 at your own connections

The Case 7 dropdowns reference connection names from the author's environment
(`gemini_flash_lite`, `spl_hosted_oss_120b`, `splunkeszou_mcp`). Edit the `<choice>` values in
`default/data/ui/views/ai_case_7.xml` to match the LLM and MCP connections configured in your
own AI Toolkit instance.

## 🧩 Custom Search Commands

| Command | File | Used by |
|---|---|---|
| `airag` | `bin/llm_rag.py` | Case 3 |
| `mcpagent` | `bin/mcp_agent.py` | Case 4 |
| `llmchat` | `bin/llmchat.py` | Cases 5, 6 |
| `aiagentx` | `bin/ai_agent.py` | Case 7 |

All four require `passauth = true` (already set in `default/commands.conf`) so they can obtain a
session key for KV Store access and credential lookup.

## ⚠️ Security Notes

This is demo code intended for a lab environment. Before adapting any of it:

* **Cases 4 and 7 execute SPL generated by the LLM** with the full permissions of the user
  running the search. `bin/spl_guard.py` screens every generated query and refuses commands that
  write, send, execute, or read credentials (`delete`, `outputlookup`, `collect`, `sendemail`,
  `script`, `rest`, `savedsearch`, …) as well as macro calls, whose expansion it cannot inspect.
  A refusal is returned to the model as a tool observation so it can pick another approach, and
  logged with the offending query.
* **The guardrail only covers queries routed through this app.** Case 7 can also be pointed at a
  *remote* MCP server, whose tools execute server-side and are out of reach of `spl_guard`. Those
  need equivalent restrictions on the MCP server itself.
* Case 7's MCP tool allowlist is permissive by default (all remote tools enabled).
* Prompts are interpolated into SPL strings in the dashboards and in
  `appserver/static/ai_drawer.js` with only minimal escaping.
