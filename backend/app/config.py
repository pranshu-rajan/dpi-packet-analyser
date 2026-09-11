import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR.parent

PACKET_ANALYZER_DIR = WORKSPACE_DIR / "Packet_analyzer"
SAMPLE_PCAP_PATH = PACKET_ANALYZER_DIR / "test_dpi.pcap"

UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUTS_DIR = BASE_DIR / "outputs"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# Determine DPI engine executable path
env_engine_path = os.getenv("DPI_ENGINE_PATH")
if env_engine_path and Path(env_engine_path).exists():
    DPI_ENGINE_PATH = Path(env_engine_path)
else:
    exe_candidate = PACKET_ANALYZER_DIR / ("dpi_engine.exe" if os.name == "nt" else "dpi_engine")
    if not exe_candidate.exists():
        # fallback to looking in base dir
        exe_candidate = BASE_DIR / ("dpi_engine.exe" if os.name == "nt" else "dpi_engine")
    DPI_ENGINE_PATH = exe_candidate

PORT = int(os.getenv("PORT", 8000))
HOST = os.getenv("HOST", "0.0.0.0")

raw_cors = os.getenv("CORS_ORIGINS", "*")
if raw_cors == "*":
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
    CORS_ORIGIN_REGEX = None
else:
    configured_origins = [orig.strip() for orig in raw_cors.split(",") if orig.strip()]
    CORS_ORIGINS = [origin for origin in configured_origins if "*" not in origin]
    wildcard_origins = [re.escape(origin).replace(r"\*", ".*") for origin in configured_origins if "*" in origin]
    CORS_ORIGIN_REGEX = f"^({'|'.join(wildcard_origins)})$" if wildcard_origins else None

DPI_API_KEY = os.getenv("DPI_API_KEY", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
