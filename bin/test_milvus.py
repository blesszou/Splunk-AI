#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys

# ---------------- 配置 ----------------
MILVUS_HOST = "127.0.0.1"
MILVUS_PORT = "19530"
COLLECTION_NAME = "security_incidents"
BASE_URL = f"http://{MILVUS_HOST}:{MILVUS_PORT}/v2/vectordb"

OLLAMA_URL = "http://localhost:11434"
EMBEDDING_MODEL = "all-minilm"

def get_embedding(text):
    """调用 Ollama 获取向量 (替代 sentence_transformers)"""
    url = f"{OLLAMA_URL}/api/embeddings"
    try:
        resp = requests.post(url, json={"model": EMBEDDING_MODEL, "prompt": text}, timeout=30)
        resp.raise_for_status()
        return resp.json().get("embedding", [])
    except Exception as e:
        print(f"❌ Ollama Embedding Error: {e}")
        sys.exit(1)

def main():
    # ---------------- 1. 加载 Collection ----------------
    print(f"Loading collection '{COLLECTION_NAME}'...")
    requests.post(f"{BASE_URL}/collections/load", json={"collectionName": COLLECTION_NAME})

    # ---------------- 2. 获取并打印 Schema 信息 ----------------
    print("\nDescribing collection...")
    resp = requests.post(f"{BASE_URL}/collections/describe", json={"collectionName": COLLECTION_NAME})
    desc_data = resp.json()
    
    if desc_data.get("code") != 0:
        print(f"❌ Failed to describe collection: {desc_data.get('message')}")
        sys.exit(1)

    fields = desc_data.get("data", {}).get("fields", [])
    
    vector_field = None
    dim = "Unknown"
    scalar_fields = []
    
    print(f"Collection name: {COLLECTION_NAME}")
    print("Strict Schema fields:")
    for f in fields:
        name = f.get("name")
        dtype = f.get("type", f.get("dataType", "Unknown"))
        print(f"  - name: {name}, dtype: {dtype}")
        
        # 判断是否为向量字段
        if "vector" in str(dtype).lower():
            vector_field = name
            # 提取维度信息
            dim = f.get("typeParams", {}).get("dim", f.get("dimension", "Unknown"))
        else:
            scalar_fields.append(name)

    print(f"\nCollection embedding dimension: {dim}")

    if not vector_field:
        raise ValueError("No vector field found in collection!")

    # --- 修复：强制添加已知的动态字段 (Dynamic Fields) ---
    # 因为 Describe API 不会返回动态写入的字段，我们需要显式声明它们以便 Fetch
    expected_dynamic_fields = ["title", "description", "incident", "analyst", "department", "contact", "resolution"]
    for f in expected_dynamic_fields:
        if f not in scalar_fields:
            scalar_fields.append(f)

    # ---------------- 3. 打印 sample 数据 ----------------
    print("\nSample entities (first 3):")
    # REST API query 必须带 filter，这里假设 ID 都是 >= 0 的正数
    query_payload = {
        "collectionName": COLLECTION_NAME,
        "filter": "id >= 0", 
        "limit": 3,
        "outputFields": scalar_fields
    }
    q_resp = requests.post(f"{BASE_URL}/entities/query", json=query_payload).json()
    for i, entity in enumerate(q_resp.get("data", [])):
        print(f"{i+1}: {entity}")

    # ---------------- 4. 交互式用户查询 ----------------
    while True:
        try:
            query_text = input("\nEnter query text (or Ctrl+C to quit): ")
            if not query_text.strip():
                continue
                
            query_embedding = get_embedding(query_text)
            print(f"Query embedding length: {len(query_embedding)}")

            # ---------------- 5. 搜索 ----------------
            search_payload = {
                "collectionName": COLLECTION_NAME,
                "data": [query_embedding],
                "annsField": vector_field,
                "limit": 5,
                "outputFields": scalar_fields
            }
            s_resp = requests.post(f"{BASE_URL}/entities/search", json=search_payload).json()

            # ---------------- 6. 打印搜索结果 ----------------
            print("\nSearch results:")
            results = s_resp.get("data", [])
            if not results:
                print("  No hits found")
                
            for hit in results:
                # 兼容数据结构里的 incident 和 description 字段
                ident = hit.get("id", "N/A")
                score = hit.get("distance", hit.get("score", "N/A"))
                incident = hit.get("incident", hit.get("title", ""))
                desc = hit.get("description", "")
                print(f"  id: {ident}, score: {score:.4f}, incident: {incident}")
                print(f"    └ description: {desc[:100]}...") # 截断太长的描述
                
        except KeyboardInterrupt:
            print("\nExiting test program.")
            break

if __name__ == "__main__":
    main()
