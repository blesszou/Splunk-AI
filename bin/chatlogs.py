#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
import urllib.parse
import time
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators


@Configuration()
class ChatLogsCommand(GeneratingCommand):
    """
    GeneratingCommand: 拥有 KV Store 长时记忆的 LLM 聊天后端
    用法: | chatlogs session="user_123" prompt="Failed logins today"
    """

    session = Option(require=True, doc="唯一的会话ID，用于追踪上下文")
    prompt = Option(require=True, doc="用户的自然语言输入")
    model = Option(default="llama3:latest", doc="Ollama 模型名称")

    OLLAMA_URL = "http://localhost:11434"

    def _get_searchinfo(self):
        """核心修复：全版本兼容提取 Splunk 上下文与 Session Key"""
        if hasattr(self, 'searchinfo') and self.searchinfo is not None:
            return self.searchinfo
        elif hasattr(self, '_metadata') and self._metadata is not None:
            return self._metadata.searchinfo
        elif hasattr(self, 'metadata') and self.metadata is not None:
            return self.metadata.searchinfo
        raise RuntimeError("Fatal: 无法在当前 SDK 中找到 searchinfo。请确保 commands.conf 中配置了 passauth = true")

    def _get_kvstore_url(self):
        """构造 KV Store 的内部 REST URL"""
        info = self._get_searchinfo()
        # info.splunkd_uri 通常是 https://127.0.0.1:8089
        return f"{info.splunkd_uri}/servicesNS/nobody/{info.app}/storage/collections/data/chat_sessions"

    def _get_headers(self):
        """使用当前用户的 Session Key 进行内部鉴权"""
        info = self._get_searchinfo()
        return {
            "Authorization": f"Splunk {info.session_key}",
            "Content-Type": "application/json"
        }

    def _load_history(self):
        """从 KV Store 读取历史记录"""
        url = self._get_kvstore_url()
        query = json.dumps({"session_id": self.session})
        req_url = f"{url}?query={urllib.parse.quote(query)}"

        try:
            r = requests.get(req_url, headers=self._get_headers(), verify=False, timeout=5)
            r.raise_for_status()
            records = r.json()

            if records and len(records) > 0:
                # 找到历史记录，返回其 _key 和 messages 列表
                return records[0].get("_key"), json.loads(records[0].get("messages", "[]"))

        except Exception as e:
            pass  # 如果表刚建好或者没数据，会走到下面

        # 如果没有历史记录，初始化系统提示词
        default_messages = [
            {
                "role": "system",
                "content": "You are a Splunk SPL expert. Translate user's natural language into Splunk SPL. Only output the SPL command, no explanations."
            }
        ]
        return None, default_messages

    def _save_history(self, record_key, messages):
        """将更新后的历史记录写回 KV Store"""
        url = self._get_kvstore_url()
        payload = {
            "session_id": self.session,
            "messages": json.dumps(messages)
        }

        try:
            if record_key:
                # 如果记录已存在，执行 POST 更新 (更新特定的 _key)
                update_url = f"{url}/{record_key}"
                requests.post(update_url, headers=self._get_headers(), json=payload, verify=False, timeout=5)
            else:
                # 如果是新会话，执行 POST 插入
                requests.post(url, headers=self._get_headers(), json=payload, verify=False, timeout=5)
        except Exception as e:
            pass  # 实际生产中可以记录 logging

    def generate(self):
        # 1. 恢复记忆：从 KV Store 拉取之前的对话
        record_key, messages = self._load_history()

        # 2. 加入新问题
        messages.append({"role": "user", "content": self.prompt})

        # 3. 带着所有记忆去问 Ollama
        try:
            llm_payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }
            llm_resp = requests.post(f"{self.OLLAMA_URL}/api/chat", json=llm_payload, timeout=60)
            llm_resp.raise_for_status()

            # 获取 LLM 的回答
            assistant_reply = llm_resp.json().get("message", {}).get("content", "")

            # 4. 将 AI 的回答写入记忆
            messages.append({"role": "assistant", "content": assistant_reply})

            # 5. 保存记忆到 KV Store
            self._save_history(record_key, messages)

        except Exception as e:
            assistant_reply = f"Error calling Ollama: {str(e)}"

        # 6. 输出结果到 Splunk 搜索界面
        yield {
            "_time": time.time(),  # 使用原生 Python 时间，避开 SDK 兼容性问题
            "session": self.session,
            "user_prompt": self.prompt,
            "ai_response": assistant_reply
        }


if __name__ == "__main__":
    dispatch(ChatLogsCommand, sys.argv, sys.stdin, sys.stdout, __name__)