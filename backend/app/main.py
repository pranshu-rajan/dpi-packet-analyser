from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import CORS_ORIGINS, DPI_ENGINE_PATH, UPLOADS_DIR, OUTPUTS_DIR
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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    return {
        "status": "healthy",
        "engine_ready": DPI_ENGINE_PATH.exists(),
        "engine_path": str(DPI_ENGINE_PATH)
    }

if __name__ == "__main__":
    import uvicorn
    from app.config import HOST, PORT
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
