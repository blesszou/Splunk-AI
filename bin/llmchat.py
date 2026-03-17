#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
import urllib.parse
import time
import copy
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option


@Configuration()
class LLMDataChatCommand(StreamingCommand):
    """
    Usage: <your arbitrary SPL> | head 30 | llmchat session="xxx" prompt="analyze these logs"
    Purpose: Consumes search results from the pipeline and sends them along with the user's prompt to the LLM for analysis and summarization. Supports KV Store context memory.
    """

    prompt = Option(require=True, doc="The user's question regarding the current search results")
    session = Option(require=False, default="", doc="Session ID, used for KV Store context tracking")
    model = Option(default="llama3:latest", doc="Ollama model name")
    max_events = Option(default=50, doc="Maximum number of events to analyze, preventing context window overflow")

    OLLAMA_URL = "http://localhost:11434"

    # ================= KV Store Context Helpers =================
    def _get_searchinfo(self):
        if hasattr(self, 'searchinfo') and self.searchinfo is not None:
            return self.searchinfo
        elif hasattr(self, '_metadata') and self._metadata is not None:
            return self._metadata.searchinfo
        elif hasattr(self, 'metadata') and self.metadata is not None:
            return self.metadata.searchinfo
        raise RuntimeError("Fatal: Could not find searchinfo. Please ensure passauth = true is set in commands.conf")

    def _get_kvstore_url(self):
        info = self._get_searchinfo()
        return f"{info.splunkd_uri}/servicesNS/nobody/{info.app}/storage/collections/data/chat_sessions"

    def _get_headers(self):
        info = self._get_searchinfo()
        return {
            "Authorization": f"Splunk {info.session_key}",
            "Content-Type": "application/json"
        }

    def _load_history(self):
        url = self._get_kvstore_url()
        query = json.dumps({"session_id": self.session})
        req_url = f"{url}?query={urllib.parse.quote(query)}"

        try:
            r = requests.get(req_url, headers=self._get_headers(), verify=False, timeout=5)
            r.raise_for_status()
            records = r.json()
            if records and len(records) > 0:
                return records[0].get("_key"), json.loads(records[0].get("messages", "[]"))
        except Exception:
            pass

        default_messages = [
            {
                "role": "system",
                "content": "You are an expert Splunk data analyst and cybersecurity expert. You will analyze the provided Splunk logs and answer user questions accurately. Context from previous turns is provided to help you maintain conversation flow."
            }
        ]
        return None, default_messages

    def _save_history(self, record_key, messages):
        url = self._get_kvstore_url()
        payload = {"session_id": self.session, "messages": json.dumps(messages)}
        try:
            if record_key:
                requests.post(f"{url}/{record_key}", headers=self._get_headers(), json=payload, verify=False, timeout=5)
            else:
                requests.post(url, headers=self._get_headers(), json=payload, verify=False, timeout=5)
        except Exception:
            pass

    # ============================================================

    def stream(self, records):
        events = []

        # 1. Collect log data from the pipeline
        for record in records:
            if len(events) >= int(self.max_events):
                break
            clean_rec = {}
            for k, v in record.items():
                if not k.startswith('_') or k in ['_raw', '_time']:
                    clean_rec[k] = v
            events.append(clean_rec)

        if not events:
            return

        # 2. Restore memory: Fetch previous conversation from KV Store
        record_key = None
        if self.session:
            record_key, messages = self._load_history()
        else:
            messages = [
                {"role": "system", "content": "You are an expert Splunk data analyst. Analyze the following logs."}]

        # --- NEW: 提取并格式化历史对话，用于在前端折叠面板中展示 ---
        history_text = ""
        turn = 1
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            if role == "system":
                continue
            if role == "user":
                # 清洗掉之前附加在问题后面的隐藏提示词
                if "### User Question:\n" in content:
                    content = content.split("### User Question:\n")[-1]
                content = content.replace("\n(Note: Current round's raw log data was provided and analyzed.)",
                                          "").strip()
                history_text += f"--- Turn {turn} ---\n🧑‍💻 You: {content}\n"
            elif role == "assistant":
                history_text += f"🤖 AI: {content.strip()}\n\n"
                turn += 1

        if not history_text.strip():
            history_text = "No previous conversation history in this session."
        # -------------------------------------------------------------

        # 3. Assemble the current round's question and data
        user_content = f"### Current Log Data:\n{json.dumps(events, ensure_ascii=False)}\n\n### User Question:\n{self.prompt}"
        messages.append({"role": "user", "content": user_content})

        # 4. Send to local Ollama
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }
            r = requests.post(f"{self.OLLAMA_URL}/api/chat", json=payload, timeout=120)
            r.raise_for_status()
            answer = r.json().get("message", {}).get("content", "")

            # 5. Write the AI's response to memory and save
            messages.append({"role": "assistant", "content": answer})
            if self.session:
                # [Core Truncation Optimization]: To prevent raw data in history from blowing up the context window,
                # we strip the massive JSON log data when saving back to KV Store, keeping only the prompt.
                saved_messages = copy.deepcopy(messages)
                saved_messages[-2][
                    "content"] = f"### User Question:\n{self.prompt}\n(Note: Current round's raw log data was provided and analyzed.)"
                self._save_history(record_key, saved_messages)

        except Exception as e:
            answer = f"❌ LLM invocation failed: {str(e)}"

        # 6. Yield the unique analysis result record
        yield {
            "_time": events[0].get("_time") if events else time.time(),
            "user_prompt": self.prompt,
            "ai_response": answer,
            "analyzed_count": len(events),
            "chat_history": history_text.strip()  # <--- NEW: 将格式化好的历史记录传递给前端
        }


if __name__ == "__main__":
    dispatch(LLMDataChatCommand, sys.argv, sys.stdin, sys.stdout, __name__)