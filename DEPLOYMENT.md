# Deployment Guide - Deep Packet Inspection (DPI) Platform

This guide walks you through deploying the full-stack DPI Engine and NetCopilot AI platform to production.

---

## Architecture Summary

| Component | Technology | Recommended Host | Notes |
| :--- | :--- | :--- | :--- |
| **Frontend** | Next.js 16 (App Router), Tailwind CSS v4, TypeScript | **Vercel** | Edge CDN, zero-config SSR, telemetry UI |
| **Backend** | FastAPI, Python 3.11, Uvicorn, SSE Streaming | **Render / Railway / Fly.io / Docker** | Compiles C++ DPI engine via GCC |
| **Database** | PostgreSQL 16 (SQLAlchemy 2.0 ORM) | **Supabase / Render Postgres / Docker** | Stores PCAP telemetry, ACL rules, threat logs |
| **DPI Engine** | C++17 (Multi-threaded with Load Balancers & Fast Path) | Included in Backend container | Ultra-fast native packet parsing |

---

## 1. Setting up Database (PostgreSQL / Supabase)

### Option A: Supabase (Recommended - Free Cloud PostgreSQL)
1. Go to [supabase.com](https://supabase.com) and create a free account.
2. Click **New Project** and choose your region and database password.
3. Under **Project Settings** -> **Database** -> **Connection string**, select **URI**.
4. Copy the connection string (format: `postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres`).
5. Set this string as `DATABASE_URL` in your backend environment variables (FastAPI automatically migrates tables and seeds default firewall rules on startup).

### Option B: Render PostgreSQL
1. In the [Render Dashboard](https://dashboard.render.com), click **New +** -> **PostgreSQL**.
2. Give it a name (e.g. `dpi-postgres`) and select the Free tier.
3. Copy the **Internal Database URL** and set it as `DATABASE_URL` in your Backend Web Service.

---

## 2. Deploying Frontend to Vercel (Recommended)

1. Push your repository to **GitHub**.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Import your GitHub repository.
4. Set the **Root Directory** to `frontend` and enable **Include files outside the root directory** only if your deployment needs repository-level files.
   - The repository-level `vercel.json` expects this setting and runs `npm ci` and `npm run build` directly inside `frontend`.
5. Under **Environment Variables**, add:
   ```env
   NEXT_PUBLIC_API_URL=https://your-backend-service.onrender.com
   CORS_ORIGINS=https://your-frontend.vercel.app
   ```
   *(Replace with your live FastAPI backend URL from Step 3)*.
6. Click **Deploy**. Vercel will automatically build and assign a production URL (e.g. `https://deep-packet-inspection.vercel.app`).

---

## 3. Deploying Backend to Render / Railway / Fly.io

### Option A: Render (Easiest Container Web Service)
1. In [Render Dashboard](https://dashboard.render.com), click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Configure the service:
   - **Environment**: `Docker`
   - **Dockerfile Path**: `backend/Dockerfile`
   - **Docker Context**: `.` (Root directory so it can access `Packet_analyzer/`)
   - **Instance Type**: Starter (or free tier)
4. Under **Environment Variables**, set:
   ```env
   PORT=8000
   DATABASE_URL=postgresql://postgres:password@your-db-host:5432/dbname
   CORS_ORIGINS=https://your-frontend.vercel.app,http://localhost:3000
   GROQ_API_KEY=your_groq_key_here
   GEMINI_API_KEY=your_optional_gemini_key_here
   OPENAI_API_KEY=your_optional_openai_key_here
   ```
5. Click **Create Web Service**. Render builds the C++ binary and launches FastAPI with the PostgreSQL connection pool.

### Option B: Railway
1. Go to [railway.app](https://railway.app) -> **New Project** -> **Deploy from GitHub repo**.
2. Set root directory to `.` and specify Dockerfile `backend/Dockerfile`.
3. Add a PostgreSQL plugin service in Railway and connect `DATABASE_URL`.
4. Add port variable `PORT=8000`.

---

## 4. Deploying via Docker Compose (Any Cloud VM / VPS / DigitalOcean / AWS EC2)

To deploy both Frontend and Backend on any Ubuntu/Debian Linux server with a single command:

1. Clone the repo on your server:
   ```bash
   git clone https://github.com/your-username/Deep-packet-inspection.git
   cd Deep-packet-inspection
   ```
2. (Optional) Configure environment variables:
   ```bash
   cp backend/.env.example backend/.env
   ```
3. Run with Docker Compose:
   ```bash
   docker compose up --build -d
   ```
4. Access the web app at `http://<your-server-ip>:3000` and API docs at `http://<your-server-ip>:8000/docs`.

---

## 4. Local Development Run

### Terminal 1: Compile & Launch FastAPI Backend
```bash
# Windows (MinGW g++)
cd Packet_analyzer
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
cd ../backend
python -m uvicorn app.main:app --reload --port 8000

# Linux / macOS
cd Packet_analyzer
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
cd ../backend
python3 -m uvicorn app.main:app --reload --port 8000
```

### Terminal 2: Launch Next.js Frontend
```bash
cd frontend
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.
