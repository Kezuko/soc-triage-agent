"""Loads the synthetic lab data the read-only tools query.

Everything in data/ is fabricated for this demo; swap these loaders for real
SIEM/EDR/TIP API clients to point the agent at a real environment.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@cache
def load(name: str) -> dict:
    with open(DATA_DIR / f"{name}.json", encoding="utf-8") as fh:
        return json.load(fh)


def intel() -> dict:
    return load("intel")


def assets() -> dict:
    return load("assets")


def logs() -> dict:
    return load("logs")


def tenants() -> dict:
    return load("tenants")
