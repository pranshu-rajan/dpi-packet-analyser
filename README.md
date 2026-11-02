# 🛡️ Deep Packet Inspection (DPI) & Streaming AI Copilot Platform

<div align="center">

[![Live Demo](https://img.shields.io/badge/🌐_Live_Demo-dpi--packet--analyser.vercel.app-00E5FF?style=for-the-badge&logo=vercel&logoColor=black)](https://dpi-packet-analyser.vercel.app/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17%20Multi--Threaded-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16%20App%20Router-000000?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%20Supabase-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Docker](https://img.shields.io/badge/Docker-Multi--Container-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

<p align="center">
  <strong>A high-throughput, multi-threaded Deep Packet Inspection (DPI) engine coupled with a Wireshark-grade browser dissector, persistent PostgreSQL telemetry, dynamic firewall ACL containment, and an interactive streaming AI Security Copilot (NetCopilot).</strong>
</p>

[**Explore Live Demo »**](https://dpi-packet-analyser.vercel.app/) · [Report Bug](https://github.com/pranshu-rajan/dpi-packet-analyser/issues) · [Request Feature](https://github.com/pranshu-rajan/dpi-packet-analyser/issues)

</div>

---

## 📑 Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. The Core Problem: Why DPI is Hard](#2-the-core-problem-why-dpi-is-hard)
- [3. Prior Work & Academic Landscape](#3-prior-work--academic-landscape)
- [4. What I Have Solved & Key Innovations](#4-what-i-have-solved--key-innovations)
- [5. System Architecture & Packet Flow](#5-system-architecture--packet-flow)
- [6. Deep Dive: C++ Multi-Threaded Engine Internals](#6-deep-dive-c-multi-threaded-engine-internals)
- [7. Key Platform Capabilities](#7-key-platform-capabilities)
- [8. Technology Stack: What Was Built With What](#8-technology-stack-what-was-built-with-what)
- [9. REST & Streaming API Reference](#9-rest--streaming-api-reference)
- [10. Quickstart & Installation Guide](#10-quickstart--installation-guide)
- [11. Environment Configuration](#11-environment-configuration)
- [12. Verification & Testing Suite](#12-verification--testing-suite)
- [13. License](#13-license)

---

## 1. Executive Summary

In contemporary computer networks, over **90% of all traffic is encrypted** using TLS/HTTPS. Traditional firewalls and packet sniffers operate at Layer 3 (IP) and Layer 4 (Port numbers). When malicious traffic, data exfiltration, or unauthorized services tunnel through standard port 443 (HTTPS) or port 80 (HTTP), traditional firewalls are blind.

This project delivers a complete, production-grade **3-Tier Deep Packet Inspection (DPI) & Threat Intelligence Platform**:
1. **Core Processing Tier**: A native **C++17 multi-threaded DPI engine** that leverages a **Load Balancer $\to$ Fast Path consistent-hashing pipeline** to dissect wire-level PCAPs at gigabit line speeds without lock contention.
2. **Application Tier**: A modern **FastAPI (Python 3.11)** asynchronous microservice handling PCAP file ingestion, byte-level dissection trees, dynamic Access Control List (ACL) orchestration, and Server-Sent Events (SSE) AI streaming.
3. **Telemetry & Dissection Tier**: A **Next.js 16 (React 19) + Tailwind CSS v4** interactive dashboard featuring a browser-based **Wireshark packet dissector**, a synchronized hexadecimal byte dump explorer, live bandwidth telemetry, and **NetCopilot** — an AI Copilot that analyzes live capture telemetry, detects vulnerabilities, and outputs 1-click executable firewall rules.

> [!NOTE]
> **Try the Live Deployment**: You can interact with the live platform directly at [https://dpi-packet-analyser.vercel.app/](https://dpi-packet-analyser.vercel.app/) without compiling anything locally.

---

## 2. The Core Problem: Why DPI is Hard

### The Evolution of Packet Filtering

```
┌────────────────────────────────────────────────────────────────────────┐
│  Shallow Packet Inspection (SPI) / Packet Filtering (L3 / L4)          │
│  - Inspects only IP addresses and Port numbers                         │
│  - CANNOT distinguish between Google Search and YouTube over Port 443  │
│  - BLIND to modern CDNs (Cloudflare, Akamai share single IPs)          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Deep Packet Inspection (DPI) (Layer 7 Application Layer)              │
│  - Inspects inside packet payload (byte-by-byte)                       │
│  - Extracts TLS SNI, HTTP Host, DNS queries, application signatures    │
│  - CHALLENGE: Must be blazingly fast; cannot introduce latency!        │
└────────────────────────────────────────────────────────────────────────┘
```

1. **The Encryption Conundrum**: Modern traffic is encrypted end-to-end. Decrypting traffic on an enterprise perimeter requires invasive SSL/TLS interception (installing custom Root CA certificates on all client machines), which breaks certificate pinning, violates user privacy, and incurs massive compute overhead.
2. **Shared Content Delivery Networks (CDNs)**: Thousands of distinct websites share identical public IP addresses behind Cloudflare, AWS CloudFront, or Fastly. Blocking an offending site by IP address results in massive collateral damage by blacklisting innocent services.
3. **High-Throughput Packet Processing Bottlenecks**: Network interfaces receive millions of packets per second. A naive single-threaded or mutex-heavy multi-threaded parser causes severe CPU lock contention, cache invalidation, and packet drops.
4. **Tool Fragmentation**: Network administrators frequently oscillate between CLI tools (`tcpdump`), desktop software (`Wireshark`), monolithic signature engines (`Snort`), and isolated firewall GUIs. There is no unified, modern web-native platform that combines inspection, real-time filtering, hex inspection, persistent telemetry, and AI remediation in one single pane of glass.

---

## 3. Prior Work & Academic Landscape

To understand the contribution of this platform, we compare it against established industry and academic paradigms:

| Solution / Framework | Strengths | Limitations & Gaps | How This Project Solves It |
| :--- | :--- | :--- | :--- |
| **Wireshark / tshark** | Industry gold standard for offline packet dissection and protocol analysis. | Heavy desktop-only GUI (Qt/C); cannot actively filter/drop packets inline into a sanitized PCAP; no web access; no built-in AI triage. | Offers a **web-based Wireshark dissector** with synchronized hex dumps and protocol trees, running in any modern browser with instant zero-install access. |
| **Snort & Suricata** | Powerful rule-based Network Intrusion Detection/Prevention Systems (NIDS/NIPS). | Monolithic C codebase; steep learning curve; complex rule languages; high operational overhead; lack modern UI & API. | Provides an intuitive **FastAPI REST API**, dynamic JSON-based ACLs, and automatic filtered PCAP re-generation. |
| **Linux iptables / nftables** | In-kernel line-rate Layer 3/4 filtering. | Blind to Layer 7 TLS SNI payloads unless paired with complex userspace daemons or custom eBPF programs. | Parses **Layer 7 TLS Client Hello SNI** extensions in userspace, allowing domain-based and app-based policy enforcement without kernel modifications. |
| **ML-based Flow Classifiers** (Academic Research) | Identifies traffic types based on packet size/inter-arrival timing statistics. | High false positive rates; computationally expensive; vulnerable to concept drift and traffic padding; "black box" decisions. | Utilizes **deterministic, zero-false-positive RFC-compliant binary parsing** of TLS SNI and HTTP headers, backed by an explainable AI Copilot. |

---

## 4. What I Have Solved & Key Innovations

### 1. Zero-Decryption Layer 7 SNI Extraction
During an HTTPS connection handshake, the client sends a `TLS Client Hello` message **in plaintext** before any symmetric session keys are negotiated. This platform implements a high-performance binary parser following RFC 6066 specifications:
- Navigates through variable-length record headers, cipher suite lists, and compression vectors.
- Locates Extension `0x0000` (Server Name Indication) and extracts the exact target hostname (e.g., `www.youtube.com`, `discord.com`).
- Classifies traffic into application categories (`YOUTUBE`, `DISCORD`, `TIKTOK`, `NETFLIX`, `SPOTIFY`, etc.) with **100% precision without breaking cryptography**.

### 2. Lockless Multi-Threaded Consistent Hashing Pipeline
To scale packet parsing across multi-core CPUs without synchronization locks:
- Packets are hashed based on their **5-Tuple**:
  $$\text{Hash} = \text{hash}(\text{Src IP}, \text{Dst IP}, \text{Src Port}, \text{Dst Port}, \text{Protocol}) \pmod N$$
- All packets belonging to the same bidirectional conversation stream are guaranteed to land on the **same Fast Path (FP) worker thread**.
- Eliminates mutex contention for connection flow tables, enabling thread-local state tracking at near-hardware speeds.

### 3. Dynamic Firewall Containment & Filtered PCAP Regeneration
Unlike static sniffers that merely observe, this engine acts as an active security checkpoint:
- Supports multi-vector Access Control Lists: **IP blocking**, **Application-level blocking**, and **Domain substring blocking**.
- Dynamically re-runs the native engine upon rule changes to produce a **sanitized output PCAP** (`filtered_<id>.pcap`) with unauthorized traffic purged, ready for forensic archival or edge firewall deployment.

### 4. Telemetry-Grounded AI Security Copilot (`NetCopilot`)
- Integrates Large Language Models (Groq LPU Llama-3, Google Gemini, OpenAI) with a Server-Sent Events (SSE) streaming transport.
- The AI does not hallucinate arbitrary networking facts: it receives the live capture's active telemetry, detected domains, threat scores, and protocol ratios directly in its system context.
- **Actionable Remediation**: When the Copilot detects a risk (e.g., plaintext credentials or unauthorized social media), it emits interactive `[SUGGEST_RULE:...]` tokens that render as **1-click rule creation cards** in the UI.

### 5. Wireshark-Grade Browser Dissector & Hexadecimal Inspector
- Hierarchical expandable protocol tree: `Frame` $\to$ `Ethernet II` $\to$ `IPv4` $\to$ `TCP/UDP` $\to$ `TLS/HTTP/DNS`.
- Synchronized Hex Viewer displaying memory offsets (`0000`, `0010`), raw hexadecimal bytes, and decoded printable ASCII characters.

---

## 5. System Architecture & Packet Flow

The system is built as a modular, decoupled 3-tier architecture:

```mermaid
flowchart TD
    subgraph Client["Tier 1: Client Browser (Next.js 16 + React 19)"]
        UI["Modern Web Dashboard"]
        Cards["Metric Cards & Telemetry"]
        Diss["Wireshark Packet Dissector & Hex Dump"]
        RulesUI["Firewall ACL Manager"]
        Copilot["NetCopilot AI Drawer (SSE Streaming)"]
    end

    subgraph Backend["Tier 2: Backend Microservice (FastAPI + Python 3.11)"]
        API["REST & SSE Endpoints"]
        Inspector["Packet Inspector & Dissector Service"]
        Runner["DPI Subprocess Orchestrator"]
        AIService["AI Agent Service (Groq / Gemini / OpenAI)"]
        ThreatCalc["Heuristic 0-100 Threat Scoring Engine"]
    end

    subgraph Engine["Tier 3: Core C++ Multi-Threaded Engine"]
        PcapReader["PCAP Binary Reader"]
        LB["Load Balancers (Consistent Hashing)"]
        FP["Fast Path Workers (Thread-Local State)"]
        SNI["TLS SNI & Protocol Extractor"]
        ACL["Rule Matching & Packet Filter"]
        PcapWriter["Sanitized PCAP Writer"]
    end

    subgraph DB["Tier 4: Persistence Store"]
        Postgres[("PostgreSQL 16 / Supabase\n(Captures, Rules, Threat Logs, Chat)")]
        SQLite[("Local SQLite Fallback")]
    end

    UI -->|REST API / JSON| API
    Copilot -->|SSE Streaming /api/chat/stream| AIService
    API --> Inspector
    API --> Runner
    API --> ThreatCalc
    API -->|SQLAlchemy 2.0 ORM| Postgres
    Postgres -.->|Offline Dev| SQLite
    Runner -->|Spawn Subprocess CLI| PcapReader
    PcapReader --> LB
    LB --> FP
    FP --> SNI
    FP --> ACL
    ACL -->|Forwarded Packets| PcapWriter
    PcapWriter -->|filtered.pcap + telemetry.json| Runner
    Runner -->|Structured Telemetry| API
```

---

## 6. Deep Dive: C++ Multi-Threaded Engine Internals

The core packet processing engine (`Packet_analyzer/`) is written in modern **C++17** for raw execution speed and predictable memory access.

### 1. The Multi-Threaded Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant R as Reader Thread
    participant Q1 as LB Input Queue
    participant LB as Load Balancers (LB0, LB1)
    participant Q2 as FP Input Queue
    participant FP as Fast Path Workers (FP0..FP3)
    participant OQ as Output Queue
    participant W as PCAP Writer Thread

    R->>R: Read 16-byte PCAP packet header + raw bytes
    R->>R: Extract 5-Tuple (Src IP, Dst IP, Ports, Protocol)
    R->>Q1: Push Packet to LB queue based on hash(5-tuple) % Num_LBs
    Q1->>LB: Pop Packet
    LB->>Q2: Distribute to FP queue based on hash(5-tuple) % Num_FPs
    Q2->>FP: Pop Packet
    FP->>FP: Lookup flow in thread-local FlowTable (Lockless)
    FP->>FP: If TLS Client Hello -> Extract SNI hostname
    FP->>FP: Evaluate active IP / App / Domain ACLs
    alt Packet Allowed
        FP->>OQ: Push to Output Queue
        OQ->>W: Pop and write packet to filtered.pcap
    else Packet Blocked
        FP->>FP: Increment dropped counter (Do not write)
    end
```

### 2. TLS Client Hello SNI Extraction Walkthrough

To inspect encrypted connections without keys, the engine parses the binary TLS handshake format:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TLS Record Layer Header (5 bytes)                                      │
│ - Byte 0: Content Type = 0x16 (Handshake)                              │
│ - Bytes 1-2: Version = 0x0301 (TLS 1.0) / 0x0303 (TLS 1.2)             │
│ - Bytes 3-4: Length = N bytes                                          │
├────────────────────────────────────────────────────────────────────────┤
│ Handshake Protocol (4 bytes)                                           │
│ - Byte 5: Handshake Type = 0x01 (Client Hello)                         │
│ - Bytes 6-8: Handshake Length                                          │
├────────────────────────────────────────────────────────────────────────┤
│ Client Hello Body                                                      │
│ - Client Version (2 bytes) + Random Vector (32 bytes)                  │
│ - Session ID Length (1 byte) + Session ID [Variable]                   │
│ - Cipher Suites Length (2 bytes) + Cipher Suites Array [Variable]      │
│ - Compression Methods Length (1 byte) + Compression List [Variable]    │
│ - Extensions Length (2 bytes)                                          │
│   ├── Extension Type: 0x0000 (Server Name Indication)                  │
│   ├── Extension Length: M bytes                                        │
│   └── Server Name List:                                                │
│       ├── Name Type: 0x00 (Host Name)                                  │
│       ├── Name Length: L bytes                                         │
│       └── Value: "www.youtube.com" <--- EXTRACTED TARGET!              │
└────────────────────────────────────────────────────────────────────────┘
```

### 3. Thread-Safe Queue Implementation
Communication between threads is mediated via a templated condition-variable queue (`thread_safe_queue.h`):
```cpp
template<typename T>
class ThreadSafeQueue {
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_not_empty_;
    std::condition_variable cv_not_full_;
    const size_t max_size_;
public:
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_not_full_.wait(lock, [this]() { return queue_.size() < max_size_; });
        queue_.push(std::move(item));
        cv_not_empty_.notify_one();
    }
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_not_empty_.wait(lock, [this]() { return !queue_.empty() || finished_; });
        if (queue_.empty()) return false;
        item = std::move(queue_.front());
        queue_.pop();
        cv_not_full_.notify_one();
        return true;
    }
};
```

---

## 7. Key Platform Capabilities

### 🔍 1. Interactive Wireshark-Style Dissector
- **Protocol Layer Parsing**: Decodes Ethernet II (MACs), IPv4 (TTL, flags, IPs), TCP (sequence numbers, ACK, SYN/FIN/RST flags), UDP, TLS, HTTP, and DNS.
- **Synchronized Hex Explorer**: Inspect raw byte streams side-by-side with offset indicators and decoded ASCII text.
- **Search & Quick Filters**: Filter live packets by protocol (`TCP`, `UDP`, `DNS`, `HTTPS`, `HTTP`), status (`FORWARDED`, `DROPPED`), or freeform keyword search.

### 🛡️ 2. Dynamic Firewall ACL Containment
- **IP Blacklisting**: Block malicious endpoints by exact IPv4 address (e.g. `192.168.1.50`).
- **Application Signatures**: Block bandwidth-heavy or unauthorized apps (e.g. `YouTube`, `TikTok`, `Netflix`, `Discord`, `Telegram`, `Spotify`).
- **Domain Wildcards & Substrings**: Intercept tracking or malicious domains (e.g. `doubleclick.net`, `analytics`).
- **1-Click PCAP Re-filtering**: Trigger instant re-execution of the C++ engine to sanitize captures and export clean PCAP files.

### 🤖 3. NetCopilot AI Streaming Assistant
- **Server-Sent Events (SSE)**: Streams tokens in real time to the browser with zero UI freeze.
- **Context-Aware Prompts**: Ingests active capture metadata, threat indicators, top talkers, and protocol distributions directly into LLM prompts.
- **Provider Agnostic**:
  - **Groq LPU**: Blazing-fast inference (500+ tokens/sec) via `llama-3.3-70b-versatile` or `llama-3.1-8b-instant`.
  - **Google Gemini**: Deep security reasoning via `gemini-1.5-flash` or `gemini-1.5-pro`.
  - **OpenAI**: Structured threat analysis via `gpt-4o-mini`.
  - **Offline Heuristic Mode**: Fallback expert cybersecurity reasoning with zero API keys required.
- **Actionable Remediation**: Clickable `[SUGGEST_RULE:...]` cards apply firewall rules directly into the live capture with a single click.

### ⚡ 4. Heuristic Threat Radar & Risk Scoring
- **Plaintext Data Leak Detection**: Alerts on unencrypted HTTP sessions transmitting sensitive headers.
- **Elevated Anomaly Detection**: Highlights suspicious tunneling or unclassified traffic ratios exceeding baseline thresholds.
- **Normalized 0–100 Threat Score**: Visual gauge providing instant situational awareness of network health.

### 🗄️ 5. PostgreSQL & Supabase Telemetry Persistence
- **ACID-Compliant Flow History**: Preserves historical PCAP analyses, throughput metrics, and top-talker statistics in PostgreSQL (via SQLAlchemy 2.0).
- **Persistent ACL Storage**: User-defined firewall rules persist permanently across browser sessions and system reboots.
- **Zero-Config SQLite Fallback**: Automatically creates a local `dpi.db` SQLite database if external PostgreSQL credentials are not supplied.

---

## 8. Technology Stack: What Was Built With What

| Subsystem | Technology | Version | Purpose in Project |
| :--- | :--- | :--- | :--- |
| **Core DPI Engine** | **C++** | C++17 | High-performance wire-level binary PCAP reader, TLS SNI parser, 5-tuple flow tracking, multi-threaded load balancer. |
| **Compiler / Build** | **GCC / g++ / CMake** | 13+ / MinGW | Multi-platform compilation with `-O2` optimization flags for gigabit throughput. |
| **Backend Framework** | **FastAPI** | 0.115+ | High-throughput asynchronous REST microservice, CORS handling, API key protection. |
| **Runtime & Language** | **Python** | 3.11+ | Subprocess orchestration, binary byte parsing, streaming async generators. |
| **Database & ORM** | **PostgreSQL / SQLAlchemy** | 16 / 2.0+ | Relational schema persistence for capture records, firewall ACLs, threat events, and chat logs. |
| **Cloud Database** | **Supabase** | Cloud | Managed PostgreSQL host with automated schema initialization and connection pooling. |
| **Frontend Framework** | **Next.js (App Router)** | 16.3.4 | Server and client component rendering, zero-config SSR, streaming consumption. |
| **UI Library** | **React** | 19.2.8 | Declarative reactive UI state management, hooks, and component lifecycles. |
| **Styling & Icons** | **Tailwind CSS & Lucide** | v4 / 1.45+ | Cyberpunk-inspired dark/light theme, high-density telemetry cards, terminal styling. |
| **Markdown & Formatting** | **React-Markdown / GFM** | 10.1+ | Renders technical AI analysis tables and bulleted incident summaries. |
| **AI LLM Inference** | **Groq / Gemini / OpenAI** | Cloud APIs | Token-by-token streaming AI security recommendations with actionable rule suggestions. |
| **Containerization** | **Docker & Compose** | 24+ / 3.8 | Multi-stage container builds compiling C++ within Linux and orchestrating microservices. |
| **Edge Hosting** | **Vercel** | Cloud | Global CDN deployment for the Next.js frontend with fast edge response times. |

---

## 9. REST & Streaming API Reference

The FastAPI backend exposes fully documented endpoints with Swagger UI available at `/docs`:

### Analysis & Telemetry
| Method | Endpoint | Description | Payload / Parameters |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze/sample` | Runs DPI engine on built-in sample PCAP with active rules. | `rules_json` (optional Form body) |
| `POST` | `/api/analyze/upload` | Uploads a custom `.pcap` or `.pcapng` file for analysis. | `multipart/form-data` (`file`, `rules_json`) |
| `POST` | `/api/analyze/refilter` | Re-runs engine on an existing capture with modified ACLs. | `RefilterRequest` (`analysis_id`, `rules`) |
| `GET` | `/api/analyze/history` | Fetches historical capture sessions stored in database. | Query: `limit`, `offset` |
| `GET` | `/api/analyze/session/{id}`| Retrieves complete telemetry metrics for a historical session. | Path: `session_id` |
| `GET` | `/api/analyze/download/{fn}`| Downloads the sanitized output PCAP file. | Path: `filename` |
| `GET` | `/api/analyze/status` | Reports C++ engine binary status and file system paths. | None |

### Packet Dissection & Hex Dumps
| Method | Endpoint | Description | Payload / Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/packets` | Lists dissected packets with pagination and protocol filters. | `analysis_id`, `limit`, `offset`, `protocol`, `search` |
| `GET` | `/api/packets/{id}` | Returns hierarchical protocol tree & synchronized hex dump lines. | Path: `packet_id`, Query: `analysis_id` |

### Persistent Firewall Rules (ACL)
| Method | Endpoint | Description | Payload / Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/rules` | Retrieves all persistent firewall rules from PostgreSQL. | None |
| `POST` | `/api/rules` | Creates a new persistent firewall rule. | `FilterRuleCreate` (`type`, `value`, `action`, `enabled`) |
| `POST` | `/api/rules/bulk` | Synchronizes active rule set to database in bulk. | `List[FilterRuleCreate]` |
| `PATCH` | `/api/rules/{id}/toggle` | Enables or disables an individual firewall rule. | Path: `rule_id` |
| `DELETE`| `/api/rules/{id}` | Deletes a firewall rule from database. | Path: `rule_id` |
| `GET` | `/api/rules/presets` | Returns factory-default security presets (e.g. Block Social, Block Ads). | None |

### AI Security Copilot
| Method | Endpoint | Description | Payload / Parameters |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/chat/stream` | Server-Sent Events (SSE) stream delivering real-time tokens. | `ChatStreamRequest` (`messages`, `analysis_id`) |

---

## 10. Quickstart & Installation Guide

You can launch the complete platform locally using either Docker Compose or direct native execution:

### Option A: 1-Click Launch with Docker Compose (Recommended)

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running:

```bash
# 1. Clone the repository
git clone https://github.com/pranshu-rajan/dpi-packet-analyser.git
cd dpi-packet-analyser

# 2. Build and launch all services (Database, Backend with C++ Engine, and Frontend)
docker compose up --build
```

- **Frontend Application**: [http://localhost:3000](http://localhost:3000)
- **FastAPI Backend & Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **PostgreSQL Database**: Port `5432`

---

### Option B: Native Host Execution

#### Step 1: Compile the C++17 DPI Engine

Ensure you have `g++` (GCC 9+ or MinGW on Windows) installed:

```bash
cd Packet_analyzer

# On Windows (PowerShell / MinGW):
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

# On Linux / macOS:
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

# Verify compilation
./dpi_engine --help  # (or .\dpi_engine.exe on Windows)
cd ..
```

#### Step 2: Configure and Start the FastAPI Backend

```bash
cd backend

# Create Python virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Copy environment template
cp .env.example .env

# Start FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Step 3: Configure and Start the Next.js Frontend

```bash
cd ../frontend

# Install Node dependencies
npm install

# Run development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser to begin analyzing network traffic!

---

## 11. Environment Configuration

### Backend Environment (`backend/.env`)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8000` | Port for the FastAPI server. |
| `HOST` | `0.0.0.0` | Bind host interface. |
| `DATABASE_URL` | `sqlite:///./dpi.db` | PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/db`). Defaults to SQLite if left empty. |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated list of allowed web origins. |
| `DPI_API_KEY` | *(Empty)* | Optional shared secret required in `X-API-Key` headers for production security. |
| `GROQ_API_KEY` | *(Optional)* | API key for ultra-fast LPU inference via Groq (`llama-3.3-70b-versatile`). |
| `GEMINI_API_KEY` | *(Optional)* | API key for Google Gemini model fallback. |
| `OPENAI_API_KEY` | *(Optional)* | API key for OpenAI model fallback. |
| `DPI_ENGINE_PATH`| *(Auto-detected)* | Path to the compiled C++ executable binary. |

### Frontend Environment (`frontend/.env.local`)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Public URL pointing to the FastAPI backend API. |

---

## 12. Verification & Testing Suite

The repository includes automated end-to-end and unit test suites:

```bash
cd backend

# Run comprehensive 7-stage end-to-end verification suite
python test_e2e_verification.py
```

### Verification Coverage:
1. **Database Table Initialization**: Confirms SQLAlchemy creates `captures`, `firewall_rules`, `threat_events`, and `chat_messages` tables and seeds default ACL policies.
2. **Health & Subprocess Readiness**: Validates `/health` and verifies that the compiled C++ engine is discoverable and executable.
3. **Firewall Rules CRUD**: Tests creating, toggling, deleting, and fetching database rules.
4. **C++ Engine Execution & Telemetry**: Feeds `test_dpi.pcap` through the C++ engine with active rules, verifying drop counts and generated JSON telemetry.
5. **Wireshark Dissection & Hex Dump**: Validates protocol hierarchy dissection, Ethernet/IP/TCP headers, and ASCII/Hex dump alignments.
6. **Filtered PCAP Export**: Confirms sanitized output PCAP exists and is downloadable.
7. **AI Copilot Streaming**: Verifies Server-Sent Events (SSE) streaming output and structured markdown responses.

---

## 13. License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<div align="center">
  <sub>Built with ❤️ for network security researchers, systems developers, and cybersecurity analysts.</sub>
</div>
