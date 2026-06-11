"""
Validation logic for KQL Detective mission submissions.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .game_data import SCENARIO


def get_public_game_state() -> Dict[str, Any]:
    missions = []
    for mission in SCENARIO["missions"]:
        missions.append(
            {
                "id": mission["id"],
                "title": mission["title"],
                "goal": mission["goal"],
                "narrative": mission["narrative"],
                "illustration": mission["illustration"],
                "allowed_tables": mission["allowed_tables"],
                "concepts": mission["concepts"],
                "starting_query": mission["starting_query"],
                "hint": mission["hint"],
            }
        )

    return {
        "title": SCENARIO["title"],
        "subtitle": SCENARIO["subtitle"],
        "briefing": SCENARIO["briefing"],
        "stakes": SCENARIO["stakes"],
        "missions": missions,
    }


def validate_submission(mission_id: str, query: str) -> Dict[str, Any]:
    mission = next((item for item in SCENARIO["missions"] if item["id"] == mission_id), None)
    if mission is None:
        raise ValueError("Unknown mission.")

    normalized = normalize_query(query)
    failures: List[str] = []

    for check in mission["checks"]:
        check_type = check["type"]
        if check_type == "contains":
            if check["value"] not in normalized:
                failures.append(check["message"])
        elif check_type == "any":
            if not any(candidate in normalized for candidate in check["values"]):
                failures.append(check["message"])

    if failures:
        return {
            "status": "incorrect",
            "message": failures[0],
            "hint": mission["hint"],
            "result_rows": [],
            "answer": None,
        }

    score = score_query(normalized)
    return {
        "status": "correct",
        "message": mission["success_message"],
        "hint": None,
        "result_rows": mission["success_rows"],
        "answer": mission["success_answer"],
        "score_delta": score,
    }


def normalize_query(query: str) -> str:
    compact = " ".join(query.lower().split())
    return compact.replace("'", "\"")


def score_query(query: str) -> int:
    bonus = 100
    if "project" in query:
        bonus += 5
    if "distinct" in query or "summarize" in query:
        bonus += 5
    if "order by" in query or "| top " in query:
        bonus += 5
    return bonus
