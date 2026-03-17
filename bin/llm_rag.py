#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class LLMRAGCommand(StreamingCommand):
    """
    StreamingCommand: RAG + LLM (Zero-dependency Splunk-Native version)
    完全移除了 pymilvus 和 sentence_transformers 依赖。
    所有的外部交互全部通过 REST API 完成，并完美支持 Milvus 动态字段。
    """

    prompt = Option(require=True, doc="用户输入的提示词")
    provider = Option(require=True, doc="LLM 提供者，目前支持 Ollama", validate=validators.Match("provider", r"^ollama$"))
    model = Option(require=True, doc="模型名称，如 llama3:latest")
    collection_name = Option(default="security_incidents", doc="Milvus collection 名称")
    debug = Option(default=False, validate=validators.Boolean())
    max_records = Option(default=5, validate=validators.Integer())

    # Milvus 和 Ollama 的本地配置
    MILVUS_HOST = "127.0.0.1"
    MILVUS_PORT = "19530"
    OLLAMA_URL = "http://localhost:11434"
    EMBEDDING_MODEL = "all-minilm" 

    def stream(self, records):
        for record in records:
            event_value = record.get("event", "")

            # --- 1. RAG 检索上下文 (纯 REST API) ---
            context_records = self.retrieve_context(event_value, self.collection_name, debug=self.debug, limit=self.max_records)

            # --- 2. 构建 LLM Prompt ---
            if context_records:
                context_str = "\n".join([
                    f"[Record {i+1}]\n" + "\n".join([f"{k}: {v}" for k, v in r.items() if k != "score" and k != "vector"])
                    for i, r in enumerate(context_records)
                ])
                enhanced_prompt = (
                    "You are an experienced SOC analyst. "
                    "Based on the historical incidents below, determine which department or role is primarily responsible for handling this security event. "
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

            # --- 3. 调用 LLM (纯 REST API) ---
            response_text = self.call_llm(enhanced_prompt)

            # --- 4. 提取 top records 的 department/contact ---
            top_records = context_records[:2] if context_records else []
            department = ", ".join(set([str(r.get("department", "")) for r in top_records if r.get("department")]))
            contact = ", ".join(set([str(r.get("contact", "")) for r in top_records if r.get("contact")]))
            if not department: department = "N/A"
            if not contact: contact = "N/A"

            # --- 5. 输出，保留原始字段 + 新字段 ---
            output_record = dict(record)
            output_record.update({
                "answer": response_text,
                "department": department,
                "contact": contact,
                "matched_records": json.dumps(top_records, ensure_ascii=False)
            })

            yield output_record

    def retrieve_context(self, query, collection_name, debug=False, limit=5):
        try:
            # 1. 调用 Ollama 获取查询文本的 Embedding 向量
            query_embedding = self.get_embedding(query)
            if not query_embedding:
                if debug: print("[RAG] Failed to get embedding for query", file=sys.stderr)
                return []

            # 2. 调用 Milvus Describe API 动态获取 Schema
            describe_url = f"http://{self.MILVUS_HOST}:{self.MILVUS_PORT}/v2/vectordb/collections/describe"
            desc_resp = requests.post(describe_url, json={"collectionName": collection_name}, timeout=10)
            desc_resp.raise_for_status()
            desc_data = desc_resp.json()

            if desc_data.get("code") != 0:
                if debug: print(f"[Milvus Describe Error] {desc_data.get('message')}", file=sys.stderr)
                return []

            fields = desc_data.get("data", {}).get("fields", [])
            embedding_field = "vector" 
            available_fields = []

            for f in fields:
                field_type = str(f.get("type", "")).lower()
                field_data_type = str(f.get("dataType", "")).lower()
                if "vector" in field_type or "vector" in field_data_type:
                    embedding_field = f.get("name")
                else:
                    available_fields.append(f.get("name"))

            # --- 核心修复：强制添加动态字段，否则 Milvus 返回的数据里没有它们 ---
            expected_dynamic_fields = ["title", "description", "incident", "analyst", "department", "contact", "resolution"]
            for f in expected_dynamic_fields:
                if f not in available_fields:
                    available_fields.append(f)

            # 3. 调用 Milvus Search API 获取检索结果
            search_url = f"http://{self.MILVUS_HOST}:{self.MILVUS_PORT}/v2/vectordb/entities/search"
            search_payload = {
                "collectionName": collection_name,
                "data": [query_embedding],
                "annsField": embedding_field,
                "limit": limit,
                "outputFields": available_fields
            }

            search_resp = requests.post(search_url, json=search_payload, timeout=15)
            search_resp.raise_for_status()
            search_data = search_resp.json()

            if search_data.get("code") != 0:
                if debug: print(f"[Milvus Search Error] {search_data.get('message')}", file=sys.stderr)
                return []

            results = search_data.get("data", [])
            context_records = []
            
            for hit in results:
                record = {field: hit.get(field, "") for field in available_fields}
                record["score"] = float(hit.get("distance", 0.0))
                context_records.append(record)

            return context_records

        except Exception as e:
            if debug: print(f"[Milvus/Ollama System Error] {str(e)}", file=sys.stderr)
            return []

    def get_embedding(self, text):
        url = f"{self.OLLAMA_URL}/api/embeddings"
        payload = {
            "model": self.EMBEDDING_MODEL,
            "prompt": text
        }
        try:
            r = requests.post(url, json=payload, timeout=30)
            r.raise_for_status()
            data = r.json()
            return data.get("embedding", [])
        except Exception as e:
            if self.debug: print(f"Ollama Embedding Error: {str(e)}", file=sys.stderr)
            return []

    def call_llm(self, prompt_text):
        url = f"{self.OLLAMA_URL}/api/chat"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt_text}],
            "stream": False,
            "format": "json" 
        }
        try:
            r = requests.post(url, json=payload, timeout=60)
            r.raise_for_status()
            data = r.json()
            return data.get("message", {}).get("content", "")
        except Exception as e:
            return f"{{\"error\": \"LLM 调用失败: {str(e)}\"}}"

if __name__ == "__main__":
    dispatch(LLMRAGCommand, sys.argv, sys.stdin, sys.stdout, __name__)
