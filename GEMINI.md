# 🧠 GEMINI.md — Antigravity Model Execution Rules

## 1. PURPOSE
This file dictates the execution standards, constraints, and baseline performance metrics that all Gemini/Antigravity Agents must adhere to while operating on the SecureMailScope codebase.

## 2. CODE STANDARDS & PATTERNS
- **Language Stack:** Python 3.12+ (Backend, ML, Parsing), TypeScript/React (Frontend Dashboard).
- **Strict Typing:** All Python code must utilize type hints. Leverage `Pydantic v2` for all data modeling, input validation, and settings management.
- **Concurrency & Asynchrony:** Network and I/O-bound operations should use `asyncio`. Use `FastAPI` for REST endpoints.
- **Zero-Copy & Memory Efficiency:** When processing multi-gigabyte `.pcap` files, prefer zero-copy memory techniques (e.g., memory mapping, efficient DPKT usage, DuckDB embeddings). 

## 3. PERFORMANCE BASELINES
- **Memory Constraint:** The core processing engine must consume `<150 MB RAM` under standard operating load. Memory leaks or unbounded queues are unacceptable.
- **CPU Constraint:** The baseline protocol sifting must execute with `<1% CPU` overhead when passively listening, bursting only during active chunk processing.
- **Execution Speed:** Complete parsing, analysis, scoring, and output generation of standard evaluation `.pcap` files must resolve in **under 7 seconds**.

## 4. MULTI-FILE SYNTHESIS
- When making modifications, ensure that corresponding components (e.g., API schemas in Backend and API clients in Frontend) remain synchronized.
- Generate unit tests simultaneously with logic implementation.

## 5. SECURITY IMPERATIVES
- Code generated must NOT include external telemetry.
- Fail-closed security architecture: Any parsing failure must result in secure degradation, logging the error without exposing stack traces to the API response.
