"""
FastAPI app for KQL Detective.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .game_data import KEYWORDS, TABLE_SCHEMAS
from .validator import get_public_game_state, validate_submission


BASE_DIR = Path(__file__).resolve().parent.parent
app = FastAPI(title="KQL Detective", version="0.1.0")


class Submission(BaseModel):
    mission_id: str = Field(min_length=2)
    query: str = Field(min_length=3)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (BASE_DIR / "web" / "index.html").read_text(encoding="utf-8")


@app.get("/api/game")
def game() -> Dict[str, Any]:
    state = get_public_game_state()
    state["editor"] = {
        "keywords": KEYWORDS,
        "tables": TABLE_SCHEMAS,
    }
    return state


@app.post("/api/submit")
def submit(payload: Submission) -> Dict[str, Any]:
    try:
        return validate_submission(payload.mission_id, payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
