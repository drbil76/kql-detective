# KQL Detective

> Learn KQL by investigating a realistic cyber incident step by step in an interactive SOC-style game.

## 🚧 Work In Progress

`KQL Detective` is currently under active development.  
The current version is a playable MVP focused on the core gameplay loop:

- read the mission
- write a KQL query
- validate your answer
- unlock the next step of the investigation

The goal is to turn this into a polished training experience for junior SOC analysts who want a more realistic way to practice KQL.

## 🎯 Concept

You play as a **junior SOC analyst** investigating a suspicious attachment chain.

Each mission pushes the story forward through KQL:

- identify the compromised device
- trace the parent process
- pivot to network activity
- confirm persistence
- scope the affected user

You only progress when the query logic is correct, so the investigation unfolds like a real blue-team puzzle instead of a static tutorial.

## ✨ Current MVP Features

- story-driven investigation with 5 sequential missions
- Defender-like KQL tables and fields
- browser-based query editor powered by `Monaco`
- KQL-style syntax highlighting
- autocomplete for tables, fields, and common operators
- animated success and failure feedback
- result preview for successful queries
- local progress persistence in the browser
- `FastAPI` backend for game state and answer validation

## 🧠 Why This Project Exists

One of the biggest problems for junior analysts is simple:  
it is hard to find a place to **practice KQL in a realistic investigation flow** without needing enterprise tooling, licenses, or a full SOC lab.

`KQL Detective` is meant to fill that gap with something more interactive, more visual, and more scenario-driven than a list of syntax exercises.

## 🛠️ Run Locally

```bash
pip install -r requirements.txt
uvicorn src.app:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

## 📌 Important Note

This MVP does **not** execute real KQL against Microsoft Defender.

Right now, it:

- simulates Defender-style telemetry
- checks the structure and logic expected for each mission
- keeps the experience lightweight and usable without paid Microsoft products

That tradeoff is intentional for the current phase of the project.

## 🗺️ Planned Improvements

- stronger parser-based validation instead of simple token checks
- multiple incidents and difficulty levels
- mission scoring and post-challenge explanations
- better progression UX and scenario map
- optional Azure Data Explorer integration for more realistic execution
- later support for other analyst query languages such as `SPL`

## 🧪 Current Status

This repo should be seen as:

- a **playable concept**
- a **portfolio project in progress**
- the foundation for a more complete blue-team query training platform

If you open it today, expect an MVP, not a finished product.
