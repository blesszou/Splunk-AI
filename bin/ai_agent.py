#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import json
import re
import urllib.request
import urllib.error
import configparser
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
import splunklib.client as client


@Configuration()
class AIAgentCommand(GeneratingCommand):
    prompt = Option(require=True)
    # Default provider is gemini, can be overridden in SPL via provider="ollama"
    provider = Option(require=False, default="gemini")

    def _get_config(self, provider_name):
        """Read configuration from agent_config.conf (handles default and local priority)."""
        app_name = self._metadata.searchinfo.app
        splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')

        config = configparser.ConfigParser()
        default_conf = os.path.join(splunk_home, 'etc', 'apps', app_name, 'default', 'agent_config.conf')
        local_conf = os.path.join(splunk_home, 'etc', 'apps', app_name, 'local', 'agent_config.conf')

        config.read([default_conf, local_conf])

        if provider_name in config.sections():
            return dict(config[provider_name])
        else:
            raise ValueError(f"Provider [{provider_name}] not found in agent_config.conf")

    def _clean_json(self, text):
        """Robust JSON extractor using Regex to prevent LLM chatty syndrome."""
        text = text.strip()
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            return match.group(0)
        return text

    def _call_llm(self, messages, system_prompt):
        """Router function to call the selected LLM provider based on config."""
        try:
            # 1. Fetch credentials from agent_config.conf
            conf = self._get_config(self.provider)
            base_url = conf.get("base_url", "")
            model_name = conf.get("model_name", "")
            api_key = conf.get("api_key", "")

            # 2. Route to Gemini Engine
            if self.provider.lower() == "gemini":
                url = f"{base_url}{model_name}:generateContent?key={api_key}"

                # Format standard messages to Gemini v1beta spec
                gemini_messages = []
                for msg in messages:
                    role = "model" if msg["role"] == "assistant" else "user"
                    gemini_messages.append({"role": role, "parts": [{"text": msg["content"]}]})

                payload = {
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": gemini_messages,
                    "generationConfig": {
                        "responseMimeType": "application/json",
                        "temperature": 0.1
                    }
                }

                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                             headers={'Content-Type': 'application/json'})
                response = urllib.request.urlopen(req, timeout=120)
                res_data = json.loads(response.read().decode('utf-8'))

                candidates = res_data.get("candidates", [])
                if not candidates:
                    return json.dumps({"Thought": "Error: Empty response.", "Action": "FINISH",
                                       "Final_Answer": "No candidates returned from Gemini."})
                return candidates[0].get("content", {}).get("parts", [])[0].get("text", "")

            # 3. Route to Ollama Engine
            elif self.provider.lower() == "ollama":
                ollama_messages = [{"role": "system", "content": system_prompt}] + messages
                payload = {
                    "model": model_name,
                    "messages": ollama_messages,
                    "stream": False
                }
                req = urllib.request.Request(base_url, data=json.dumps(payload).encode('utf-8'),
                                             headers={'Content-Type': 'application/json'})
                response = urllib.request.urlopen(req, timeout=120)
                res_data = json.loads(response.read().decode('utf-8'))
                return res_data.get("message", {}).get("content", "")

            else:
                return json.dumps({"Thought": f"Unknown provider: {self.provider}", "Action": "FINISH",
                                   "Final_Answer": "Check agent_config.conf"})

        except urllib.error.HTTPError as e:
            error_msg = e.read().decode('utf-8')
            return json.dumps({"Thought": f"API HTTP Error: {e.code}", "Action": "FINISH", "Final_Answer": error_msg})
        except Exception as e:
            return json.dumps({"Thought": f"System Error: {str(e)}", "Action": "FINISH",
                               "Final_Answer": "Failed to execute LLM request."})

    def _run_subsearch(self, spl_query, session_key):
        """Silently execute SPL in the background and return observations."""
        service = client.connect(token=session_key)

        if not spl_query.strip().startswith("| tstats") and "| head" not in spl_query:
            spl_query = f"{spl_query} | head 20"

        if not spl_query.startswith("search") and not spl_query.startswith("|"):
            spl_query = "search " + spl_query

        try:
            job = service.jobs.oneshot(spl_query, output_mode="json")
            results = json.loads(job.read().decode('utf-8'))
            records = results.get("results", [])

            if len(records) == 0:
                return "The query returned no results."
            return json.dumps(records[:10])
        except Exception as e:
            return f"Error executing SPL: {str(e)}"

    def generate(self):
        session_key = self._metadata.searchinfo.session_key

        # Dynamic model name extraction for UI Polish
        try:
            conf = self._get_config(self.provider)
            display_model = conf.get("model_name", self.provider)
        except Exception:
            display_model = self.provider

        system_prompt = """You are an autonomous Splunk Security Analyst Agent.
You operate in a "blind box" environment. You do not know what indexes, sourcetypes, or data exist.
Your task is to fulfill the user's request by iteratively searching the Splunk environment.

CRITICAL RULES:
1. EXPLORE FIRST: If you don't know the index, use `| tstats count where index=* by index, sourcetype`.
2. EFFICIENCY: Always append `| head 20` to raw searches.
3. STRICT FORMAT: You MUST ONLY output valid JSON. NO conversational text outside the JSON block.
4. JSON STRUCTURE:
{
  "Thought": "Your reasoning here.",
  "Action": "The SPL query to run, OR output 'FINISH' if you have the answer.",
  "Final_Answer": "If Action is 'FINISH', write the final report here. Otherwise, leave empty."
}"""

        messages = [
            {"role": "user", "content": f"Task: {self.prompt}"}
        ]

        max_iterations = 6

        for step in range(1, max_iterations + 1):
            # dynamically show the model name from config!
            yield {'_time': time.time(), 'step': step, 'type': '🔄 Thinking...',
                   'content': f'Waiting for {display_model} decision...'}

            llm_response = self._call_llm(messages, system_prompt)

            try:
                cleaned_response = self._clean_json(llm_response)
                parsed_res = json.loads(cleaned_response)
                thought = parsed_res.get("Thought", "No thought provided.")
                action = parsed_res.get("Action", "FINISH")
                final_answer = parsed_res.get("Final_Answer", "")
            except Exception as e:
                yield {'_time': time.time(), 'step': step, 'type': '⚠️ Format Recovered',
                       'content': "LLM dropped JSON format. Attempting to recover text as final report..."}
                thought = "The LLM output invalid JSON. Wrapping it as the final answer."
                action = "FINISH"
                final_answer = llm_response

            yield {'_time': time.time(), 'step': step, 'type': '🤔 Agent Reasoning', 'content': thought}

            if action.strip() == "FINISH":
                yield {'_time': time.time(), 'step': step, 'type': '✅ Final Report', 'content': final_answer}
                break

            yield {'_time': time.time(), 'step': step, 'type': '⚙️ Executing Query', 'content': action}
            observation = self._run_subsearch(action, session_key)
            yield {'_time': time.time(), 'step': step, 'type': '👀 Observation',
                   'content': f"Fetched {len(observation)} bytes of data results."}

            messages.append({"role": "assistant", "content": llm_response})
            messages.append(
                {"role": "user",
                 "content": f"Observation from your query: {observation}\nWhat is your next step? (REMEMBER: Output ONLY JSON)"}
            )

            if step == max_iterations:
                yield {'_time': time.time(), 'step': step, 'type': '⚠️ Forced Termination',
                       'content': 'Max iterations reached. Task aborted.'}


if __name__ == "__main__":
    dispatch(AIAgentCommand, sys.argv, sys.stdin, sys.stdout, __name__)