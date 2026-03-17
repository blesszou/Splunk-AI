# Splunk AI Toolkit Showcase 🤖🔍

Welcome to the **Splunk AI Toolkit Showcase**. This application is a comprehensive gallery designed to demonstrate the powerful integration of Generative AI (LLMs) with Splunk Enterprise. Watch and learn from advanced AI examples using real datasets. 

## ✨ Showcase Gallery (Use Cases)

This application includes five bespoke dashboards, each demonstrating a unique architectural approach to interacting with AI models inside Splunk:

* **Case 1: LLM-enhanced analysis**
  Demonstrates LLM-enhanced security event analysis and automated Indicator of Compromise (IOC) extraction from raw, unstructured log data.

* **Case 2: Multi-model collaboration**
  Highlights a multi-model collaborative workflow. Watch different AI models hand off tasks to perform complex threat hunting and enrich security context.

* **Case 3: Vector search in LLM (RAG Pipeline)**
  Features a Retrieval-Augmented Generation (RAG) pipeline utilizing vector search (powered by Milvus) for internal knowledge base lookups directly within the Splunk ecosystem.

* **Case 4: Autonomous Auditing via Splunk MCP**
  Showcases Autonomous Platform Auditing to monitor and report on platform health and compliance.

* **🏆 Case 5: Talk to Your Logs (AI Chat)**
  The crown jewel of this app: a multi-turn, conversational AI interface that reasons over your *actual* log payload. 

## ⚙️ Prerequisites

1. **Splunk Enterprise** (Tested on 9.x / 10.x).
2. **Ollama**: Installed and running locally.
3. **Milvus** (Required for **Case 3** only): A running instance of Milvus vector database for the RAG pipeline.
4. **Python 3**: Splunk's built-in Python 3 environment.

## 🚀 Installation & Configuration
The app requires several specific local models to demonstrate multi-model collaboration and specific security tasks. Run the following commands in your terminal to pull them via Ollama:
  ollama pull hf.co/DevQuasar/fdtn-ai.Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
  ollama pull aya:8b-23
  ollama pull llama3:latest
  ollama pull qwen3:latest
  ollama pull all-minilm:latest
