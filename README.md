# Deep Packet Inspection (DPI) & Streaming AI Copilot Platform

<div align="center">

![C++17](https://img.shields.io/badge/C%2B%2B-17%20Multi--Threaded-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-16%20App%20Router-000000?style=for-the-badge&logo=next.js&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Tailwind-v4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Vercel](https://img.shields.io/badge/Vercel-Deployable-black?style=for-the-badge&logo=vercel&logoColor=white)

An industry-grade, full-stack cybersecurity platform orchestrating a high-performance **C++ multi-threaded Deep Packet Inspection engine** with an interactive **Wireshark-style packet dissector**, **dynamic firewall rule containment**, and a **streaming AI Network Security Copilot** (`NetCopilot`).

</div>

---

## 🌟 Architecture Overview

The platform preserves the high-performance C++ packet inspection core while wrapping it in modern cloud services:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           USER BROWSER (CLIENT)                          │
│  Next.js 16 (App Router) + TypeScript + Tailwind CSS v4 + Lucide Icons   │
│  - Live Telemetry & Metric Cards (Packets, Bytes, Forwarded vs Dropped)  │
│  - Wireshark-Style Deep Packet Dissector (Frame, IPv4, TCP/UDP, TLS SNI) │
│  - Synchronized Byte & Hex Dump Inspector (Offset, Hex Bytes, ASCII)     │
│  - Dynamic Firewall Policy Orchestrator (Block IP, App, Domain substring)│
│  - NetCopilot AI Streaming Chatbot (SSE real-time streaming)             │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │ REST & SSE Streaming
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         FASTAPI BACKEND (PYTHON 3.11)                    │
│  - /api/analyze/upload & /sample (PCAP ingestion & multi-threaded exec)  │
│  - /api/analyze/refilter (Dynamic firewall policy re-execution)          │
│  - /api/packets & /api/packets/{id} (Protocol layer tree & hex dump)     │
│  - /api/analyze/download/{filename} (Filtered PCAP export)               │
│  - /api/chat/stream (SSE Streaming: Gemini / OpenAI / Offline Fallback)  │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │ Subprocess Execution / IPC
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              CORE C++ DPI ENGINE (MULTI-THREADED, PRESERVED)             │
│  - Packet Reader (Ethernet, IPv4, TCP, UDP protocol dissection)          │
│  - TLS Server Name Indication (SNI) & HTTP Host Extractor                │
│  - 5-Tuple Connection Tracking (FiveTupleHash, Fast Path queues)         │
│  - Multi-Core Worker Pool: 2 Load Balancers (LB) + 4 Fast Paths (FP)     │
│  - Firewall Filtering: Forwarding allowed packets / Dropping blocked     │
│  - Produces Filtered PCAP Output + JSON Telemetry Report                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Unique Features

### 1. 🔍 Wireshark-Grade Deep Packet Dissector
- **Hierarchical Protocol Dissection**: Frame $\to$ Ethernet II (MAC addresses, EtherType) $\to$ IPv4 (Src/Dst IP, TTL, Protocol) $\to$ TCP/UDP (Ports, Flags, Seq/Ack) $\to$ TLS / Application.
- **Synchronized Hex Dump Viewer**: View byte offsets (`0000`, `0010`), raw hexadecimal bytes, and decoded ASCII representations.
- **Instant Filtering**: Filter by protocol (`TCP`, `UDP`, `DNS`, `HTTPS`, `HTTP`), status (`FORWARDED`, `DROPPED`), or search query.

### 2. 🛡️ Dynamic Firewall Rule Containment
- **Multi-Vector Blocking**:
  - **IP Containment**: Block specific source or destination IPs (e.g. `192.168.1.50`).
  - **Application Signatures**: Block specific apps (e.g. `YouTube`, `TikTok`, `Netflix`, `Discord`, `Telegram`, `Spotify`).
  - **Domain / SNI Wildcards**: Block domains by substring (e.g. `doubleclick.net`, `adservice`).
- **1-Click PCAP Re-Filtering**: Immediately re-executes the C++ engine, updates the drop count, and generates an updated sanitized PCAP file.
- **Filtered PCAP Download**: Download the sanitized capture with blocked packets stripped out for forensic storage or router deployment.

### 3. 🤖 NetCopilot AI Streaming Assistant
- **Real-Time Streaming**: Server-Sent Events (SSE) stream responses token-by-token.
- **Telemetry-Grounded System Context**: The AI receives live packet statistics, detected SNIs, application breakdowns, and threat findings in its prompt context.
- **Multi-Provider Support**:
  - Google Gemini (`GEMINI_API_KEY`) via `google-generativeai`.
  - OpenAI (`OPENAI_API_KEY`).
  - **Intelligent Offline Fallback**: Functions out-of-the-box offline with zero configuration or API keys!
- **Actionable Suggestions**: When the AI recommends a firewall rule, it renders an interactive card with a **"Click to Apply Rule"** button.

### 4. ⚡ Heuristic Cyber Threat Radar
- **Plaintext Leak Detection**: Detects unencrypted HTTP traffic carrying credentials or session IDs.
- **High-Risk Application Flagging**: Highlights bandwidth hogs or unauthorized social media in enterprise networks.
- **0-100 Threat Risk Index**: Continuous scoring based on active traffic composition.

---

## 🛠️ Quickstart Guide

### Option 1: Docker Compose (Single Command)
```bash
docker compose up --build
```
- Frontend: [http://localhost:3000](http://localhost:3000)
- Backend & Swagger Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option 2: Native Local Execution

#### 1. Compile the Core C++ DPI Engine
```bash
# Windows (MinGW g++)
cd Packet_analyzer
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

# Linux / macOS
cd Packet_analyzer
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

#### 2. Launch FastAPI Backend
```bash
cd ../backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

#### 3. Launch Next.js Frontend
```bash
cd ../frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🌐 Production Deployment

See [DEPLOYMENT.md](file:///c:/Users/pranshu/Desktop/PROJECTS/Deep-packet-inspection/DEPLOYMENT.md) for full step-by-step instructions:
- **Frontend**: Deploy with 1-click to **Vercel** (`NEXT_PUBLIC_API_URL` pointing to backend).
- **Backend**: Deploy container to **Render**, **Railway**, **Fly.io**, or any cloud VM via `backend/Dockerfile`.

---

## 📁 Repository Structure

```
Deep-packet-inspection/
├── Packet_analyzer/                # Core C++ Multi-Threaded Engine (Preserved)
│   ├── include/                    # Header files (pcap_reader, packet_parser, sni_extractor, etc.)
│   ├── src/                        # C++ implementations (dpi_mt.cpp, etc.)
│   ├── test_dpi.pcap               # Built-in sample capture with 18 SNI domains
│   └── CMakeLists.txt
│
├── backend/                        # FastAPI Python Service
│   ├── app/
│   │   ├── api/                    # analyze, packets, rules, chat (SSE)
│   │   ├── services/               # dpi_runner, packet_inspector, ai_agent
│   │   ├── models/                 # Pydantic schemas
│   │   ├── config.py
│   │   └── main.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/                       # Next.js 16 + Tailwind CSS v4 Frontend
│   ├── src/
│   │   ├── app/                    # App Router (page.tsx, layout.tsx, globals.css)
│   │   ├── components/             # Navbar, MetricCards, TrafficAnalytics, PacketDissector, RuleManagerModal, AICopilotDrawer
│   │   ├── lib/                    # api.ts (Fetch + SSE stream client)
│   │   └── types/                  # TypeScript definitions
│   ├── Dockerfile
│   └── package.json
│
├── docker-compose.yml              # Local & VM multi-container orchestration
├── DEPLOYMENT.md                   # Comprehensive deployment guide
└── .github/workflows/ci.yml        # Automated CI/CD pipeline
```

---

## 📄 License
This project is licensed under the MIT License.
