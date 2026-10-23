"""TRIAD /scan FastAPI service.

Run:  uvicorn server:app --reload
Env:  DEMO_MODE=1|0   (default 1 -> instant fixture-backed demo, zero network)
      TRIAD_TIMEOUT=8  (per-request HTTP timeout for live web scans)
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel, Field

import triad_scanner
from triad_scanner import TRIAD_Scanner

app = FastAPI(
    title="TRIAD Scan Service",
    version="1.0.0",
    description="Agentic AI vulnerability intelligence - INGEST stage. "
                "One input: GitHub repo URL or live website URL.",
)

DEMO_MODE = os.getenv("DEMO_MODE", "1") != "0"      # demo-safe by default
scanner = TRIAD_Scanner(timeout=float(os.getenv("TRIAD_TIMEOUT", "8")))


class ScanRequest(BaseModel):
    target: str = Field(..., description="GitHub repo URL or live website URL")
    demo: bool | None = Field(None, description="Override server DEMO_MODE for this call")


class ScanResponse(BaseModel):
    target: str
    routed_as: str
    demo_mode: bool
    scan_id: str
    started_at: str
    duration_ms: int
    finding_count: int
    findings: list[dict]


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "demo_mode": DEMO_MODE,
        "index_provenance": scanner.deps.provenance.get("fetched_at"),
        "advisories": scanner.deps.provenance.get("advisory_count"),
        "templates": [t.get("id") for t in scanner.templates],
    }


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> dict:
    demo = req.demo if req.demo is not None else DEMO_MODE
    report = scanner.scan(req.target, demo=demo)
    return report


if __name__ == "__main__":  # pragma: no cover
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
