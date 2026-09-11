from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.config import CORS_ORIGINS, CORS_ORIGIN_REGEX, DPI_API_KEY, DPI_ENGINE_PATH, UPLOADS_DIR, OUTPUTS_DIR
from app.api import analyze, packets, rules, chat

@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title="Deep Packet Inspection (DPI) & AI Copilot Platform",
    description="Full-stack DPI system orchestrating high-performance C++ engine with real-time streaming AI Copilot.",
    version="2.0.0",
    lifespan=lifespan
)

@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if DPI_API_KEY and request.method != "OPTIONS" and request.url.path.startswith("/api/"):
        if request.headers.get("x-api-key") != DPI_API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API key"})
    return await call_next(request)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# Mount API routers
app.include_router(analyze.router)
app.include_router(packets.router)
app.include_router(rules.router)
app.include_router(chat.router)

@app.get("/")
def root():
    return {
        "service": "Deep Packet Inspection (DPI) Platform",
        "version": "2.0.0",
        "status": "online",
        "engine_ready": DPI_ENGINE_PATH.exists(),
        "docs_url": "/docs"
    }

@app.get("/health")
def health_check():
    engine_ready = DPI_ENGINE_PATH.exists()
    return {
        "status": "healthy" if engine_ready else "degraded",
        "engine_ready": engine_ready,
        "engine_path": str(DPI_ENGINE_PATH)
    }

if __name__ == "__main__":
    import uvicorn
    from app.config import HOST, PORT
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
