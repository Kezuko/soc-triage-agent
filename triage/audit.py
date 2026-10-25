"""Append-only JSONL audit trail: every model turn, tool call, guardrail and
approval decision is recorded so a reviewer can reconstruct why a verdict was
reached."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []

    def write(self, kind: str, **fields: Any) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, **fields}
        self.records.append(record)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
