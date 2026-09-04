"""SharkAI - AI-Powered Network Forensics & CTF Analyzer"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.ai_routes import router as ai_router
from app.api.analysis import router as analysis_router
from app.api.captures import router as captures_router
from app.core.config import get_settings
from app.database.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="SharkAI",
    description="AI-Powered Network Forensics & CTF Analyzer",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(captures_router)
app.include_router(analysis_router)
app.include_router(ai_router)


@app.get("/api/health")
async def health():
    from app.services.analysis_service import analysis_service
    return {
        "status": "ok",
        "service": "SharkAI",
        "tshark_available": analysis_service.tshark_available,
    }


@app.get("/")
async def root():
    return {
        "name": "SharkAI",
        "tagline": "Your AI-Powered Network Traffic Analyst",
        "docs": "/docs",
    }
