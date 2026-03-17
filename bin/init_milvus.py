#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import sys
import csv
import os

# === 配置区 ===
MILVUS_HOST = "localhost"
MILVUS_PORT = "19530"
COLLECTION_NAME = "security_incidents"
BASE_URL = f"http://{MILVUS_HOST}:{MILVUS_PORT}/v2/vectordb"

OLLAMA_URL = "http://localhost:11434"
EMBEDDING_MODEL = "all-minilm" # 确保在 Ollama 中已下载: ollama pull all-minilm

CSV_FILE = "./incident_history.csv"

def get_embedding(text):
    """使用 Ollama REST API 获取向量表示 (替代 sentence_transformers)"""
    url = f"{OLLAMA_URL}/api/embeddings"
    payload = {"model": EMBEDDING_MODEL, "prompt": text}
    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json().get("embedding", [])
    except Exception as e:
        print(f"❌ Ollama Embedding Error: {e}")
        sys.exit(1)

def setup_collection():
    """使用 REST API 重置并创建 Collection"""
    # 1. 尝试删除现有的 Collection (等同于 old_col.drop())
    requests.post(f"{BASE_URL}/collections/drop", json={"collectionName": COLLECTION_NAME})
    
    # 2. 创建全新的 Collection
    print(f"Creating collection '{COLLECTION_NAME}'...")
    payload = {
        "collectionName": COLLECTION_NAME,
        "dimension": 384, # all-minilm 的输出维度
        "metricType": "IP",
        "primaryField": "id",
        "vectorField": "vector" # 强制使用 Milvus 默认的 vector 字段名以防兼容性报错
        # 注意：REST API v2 默认开启 dynamic_field，
        # 所以传入的其他字段(title, analyst等)会自动作为动态标量保存，无需像 pymilvus 那样冗长地定义 Schema。
    }
    
    response = requests.post(f"{BASE_URL}/collections/create", json=payload, timeout=10)
    data = response.json()
    if data.get("code") == 0:
        print("✅ Collection created successfully.")
    else:
        print(f"❌ Failed to create collection: {data.get('message')}")
        sys.exit(1)

def insert_data():
    """使用内置 csv 模块替代 pandas 解析文件，并获取向量写入 Milvus"""
    if not os.path.exists(CSV_FILE):
        print(f"❌ Error: CSV file '{CSV_FILE}' not found!")
        sys.exit(1)

    print(f"Parsing {CSV_FILE} and generating embeddings via Ollama...")
    
    data_to_insert = []
    with open(CSV_FILE, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 7:
                continue
            
            # 跳过表头 (如果你的 CSV 包含 id,title,description... 这样的表头)
            if str(row[0]).lower() == 'id':
                continue
                
            record_id = int(row[0])
            title = row[1]
            description = row[2]
            analyst = row[3]
            department = row[4]
            contact = row[5]
            resolution = row[6]
            
            # 严格按照你测试脚本的逻辑：只对 description 字段做 embedding
            emb = get_embedding(description)
            
            # 将实体组装成 JSON 对象插入
            data_to_insert.append({
                "id": record_id,
                "title": title,
                "description": description,
                "analyst": analyst,
                "department": department,
                "contact": contact,
                "resolution": resolution,
                "vector": emb # 字段名从 'embedding' 改为 'vector'，完美匹配 Milvus REST 默认规范
            })
            print(f"  Generated embedding for ID {record_id}...")

    print(f"Inserting {len(data_to_insert)} incidents into collection '{COLLECTION_NAME}'...")
    payload = {
        "collectionName": COLLECTION_NAME,
        "data": data_to_insert
    }
    
    response = requests.post(f"{BASE_URL}/entities/insert", json=payload, timeout=30)
    data = response.json()
    if data.get("code") == 0:
        print("✅ Data inserted successfully.")
    else:
        print(f"❌ Failed to insert data: {data.get('message')}")
        sys.exit(1)

def create_index():
    """使用 REST API 创建向量索引 (等同于 collection.create_index)"""
    url = f"{BASE_URL}/indexes/create"
    
    # 按照你代码中的 IVF_FLAT 索引参数
    payload = {
        "collectionName": COLLECTION_NAME,
        "indexParams": [
            {
                "fieldName": "vector", # 索引名对应修改为 vector
                "indexName": "vector_ivf_flat_index",
                "metricType": "IP",
                "indexType": "IVF_FLAT",
                "params": {"nlist": 128}
            }
        ]
    }

    print(f"Creating vector index for 'vector' field...")
    try:
        response = requests.post(url, json=payload, timeout=10)
        data = response.json()
        
        if data.get("code") == 0:
            print("✅ Index created successfully.")
        else:
            print(f"⚠️ Index creation skipped or failed: {data.get('message')}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to Milvus REST API: {e}")
        sys.exit(1)

def load_collection():
    """使用 REST API 将 Collection 加载到内存"""
    url = f"{BASE_URL}/collections/load"
    payload = {"collectionName": COLLECTION_NAME}

    print(f"Loading collection '{COLLECTION_NAME}' into memory...")
    try:
        response = requests.post(url, json=payload, timeout=10)
        data = response.json()
        
        if data.get("code") == 0:
            print("✅ Collection loaded into memory, ready for search.")
        else:
            print(f"❌ Failed to load collection: {data.get('message')}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to Milvus REST API: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("--- Milvus Initialization Started (Pure REST API) ---")
    setup_collection()
    insert_data()
    create_index()
    load_collection()
    print("--- Initialization Complete! ---")
