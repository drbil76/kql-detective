# KQL Detective

An interactive blue-team training game where the player solves a realistic incident by writing KQL queries step by step.

## Concept

The player is a junior SOC analyst investigating a malicious attachment chain. Each mission requires a KQL query to uncover the next pivot:
- identify the compromised device
- trace the parent process
- pivot to network activity
- confirm persistence
- scope the affected user

Progress only unlocks when the submitted query matches the mission logic.

## Current Features

- story-driven investigation with 5 sequential missions
- Defender-like KQL tables and fields
- browser-based query editor powered by Monaco
- KQL-style syntax highlighting and autocomplete for tables, columns, and common operators
- success and failure feedback with animated state changes
- result preview for successful queries
- local progress persistence through browser storage
- FastAPI backend for game state and answer validation

## Run

```bash
pip install -r requirements.txt
uvicorn src.app:app --reload
```

Open `http://127.0.0.1:8000`.

## Notes

This MVP does not execute real KQL against Microsoft Defender. It simulates Defender-style telemetry and validates the query structure required for each mission.

That is deliberate:
- the product is usable without Microsoft licenses
- the gameplay is controlled and predictable
- the scope stays realistic for a portfolio project

## Next Steps

- stronger parser-based validation instead of token checks
- multiple scenarios and difficulty levels
- scoring rubric and post-mission explanations
- optional Azure Data Explorer integration for real KQL execution
- later support for SPL and other blue-team query languages
