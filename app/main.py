"""FastAPI entry point for ScamShield."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analyzer import analyze_message
from .database import initialize_database, recent_scans, save_scan

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="ScamShield API",
    description="Explainable scam-risk analysis for emails, messages, and job listings.",
    version="1.0.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class ScanRequest(BaseModel):
    content: str = Field(min_length=20, max_length=25_000)


@app.get("/", include_in_schema=False)
async def home() -> FileResponse:
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/scans")
async def list_scans() -> dict:
    return {"scans": recent_scans()}


@app.post("/api/scans", status_code=201)
async def create_scan(payload: ScanRequest) -> dict:
    content = payload.content.strip()
    if len(content) < 20:
        raise HTTPException(status_code=400, detail="Paste at least 20 characters to run a useful check.")
    return {"scan": save_scan(content, analyze_message(content))}
