#!/usr/bin/env python
# coding=utf-8

import sys
import json
import time
import urllib.request
import urllib.error
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client


@Configuration()
class MCPAgentCommand(GeneratingCommand):
    """
    Autonomous Agent Command (mcpagent) - Pure English Version
    Executes a ReAct loop: Plan SPL -> Execute -> Observe -> Report.
    """
    prompt = Option(require=True)
    mcp_server = Option(require=False)
    provider = Option(require=False, default="Ollama")
    model = Option(require=False, default="qwen3:latest")
    max_steps = Option(require=False, default=3, validate=validators.Integer())
    api_url = Option(require=False, default="http://localhost:11434/v1/chat/completions")

    def run_splunk_search(self, spl_query):
        """
        The core tool for the LLM to execute native Splunk searches.
        """
        spl_query = spl_query.strip()
        if not spl_query.startswith("|") and not spl_query.startswith("search"):
            spl_query = "search " + spl_query

        kwargs_oneshot = {"output_mode": "json"}
        try:
            oneshotsearch_results = self.service.jobs.oneshot(spl_query, **kwargs_oneshot)
            reader = json.loads(oneshotsearch_results.read().decode('utf-8'))
            results = reader.get('results', [])

            # Limit results to top 10 to avoid token window overflow
            limited_results = results[:10]
            return json.dumps(limited_results, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"SPL Execution Failed: {str(e)}"})

    def generate(self):
        thought_process = []
        executed_queries = []
        final_report = ""

        # 1. Define Tool Schema (in English)
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "execute_splunk_search",
                    "description": "Executes a Splunk SPL query and returns the log results in JSON format. Use this tool to investigate events.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "spl_query": {
                                "type": "string",
                                "description": "The Splunk SPL query to execute. Example: 'search index=_audit action=search | head 5'"
                            },
                            "reasoning": {
                                "type": "string",
                                "description": "Your step-by-step reasoning on why you need to execute this specific search query."
                            }
                        },
                        "required": ["spl_query", "reasoning"]
                    }
                }
            }
        ]

        # 2. Initialize LLM Context (System prompt in English)
        messages = [
            {"role": "system",
             "content": "You are an elite Splunk Platform Security Auditor. You can autonomously use tools to execute SPL searches to investigate events. Always respond and write reports in English. Once you reach a solid conclusion based on the data, output the final investigation report directly without calling any further tools."},
            {"role": "user", "content": self.prompt}
        ]

        # 3. Agentic ReAct Loop
        for step in range(self.max_steps):
            payload = {
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "stream": False
            }

            try:
                req = urllib.request.Request(
                    self.api_url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers={"Content-Type": "application/json"}
                )

                with urllib.request.urlopen(req, timeout=120) as response:
                    response_data = json.loads(response.read().decode('utf-8'))

                message = response_data.get("choices", [{}])[0].get("message", {})
                messages.append(message)

                # Check if LLM invoked a Tool Call
                if message.get("tool_calls"):
                    for tool_call in message["tool_calls"]:
                        if tool_call["function"]["name"] == "execute_splunk_search":
                            args = json.loads(tool_call["function"]["arguments"])
                            spl_query = args.get("spl_query", "")
                            reasoning = args.get("reasoning", "Gathering more context.")

                            # Record logs in English
                            thought_process.append(f"[Step {step + 1} Thought] {reasoning}")
                            thought_process.append(f"[Step {step + 1} Action] Executing SPL query via MCP.")
                            executed_queries.append(f"{step + 1}. {spl_query}")

                            # Execute the search
                            search_result = self.run_splunk_search(spl_query)

                            # Record observation
                            thought_process.append(
                                f"[Step {step + 1} Observation] Successfully retrieved {len(json.loads(search_result))} related log events.")

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call["id"],
                                "name": "execute_splunk_search",
                                "content": search_result
                            })
                else:
                    # Final Report generated
                    final_report = message.get("content", "")
                    thought_process.append(f"[Completed] Investigation finished. Outputting final report.")
                    break

            except urllib.error.URLError as e:
                final_report = f"Agent API Request Failed: {str(e)}"
                break
            except Exception as e:
                final_report = f"Agent Runtime Error: {str(e)}"
                break

        # Fallback if max steps reached
        if not final_report:
            final_report = "Maximum thinking steps reached. Investigation forcibly terminated. Please review the executed queries and observations above."

        # 4. Yield results
        yield {
            "task": self.prompt,
            "agent_thought_process": "\n\n".join(thought_process) if thought_process else "No actions taken.",
            "executed_spl_queries": "\n\n".join(executed_queries) if executed_queries else "No queries executed.",
            "final_investigation_report": final_report
        }


dispatch(MCPAgentCommand, sys.argv, sys.stdin, sys.stdout, __name__)