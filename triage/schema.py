"""Structured output contract for triage verdicts.

The model must return JSON matching VERDICT_JSON_SCHEMA (enforced by the
Responses API with strict json_schema output), and the result is validated
again here with Pydantic before anything downstream uses it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["true_positive", "false_positive", "needs_review"]
ActionType = Literal["block_ip", "block_domain", "isolate_host", "create_ticket"]


class Evidence(BaseModel):
    source: str = Field(description="Tool or alert field the evidence came from")
    detail: str = Field(description="What was observed")


class ProposedAction(BaseModel):
    action: ActionType
    target: str
    reason: str


class TriageVerdict(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: list[Evidence]
    mitre_techniques: list[str] = Field(description="ATT&CK IDs supported by evidence, e.g. T1059.001")
    proposed_actions: list[ProposedAction]


def _strict(schema: dict) -> dict:
    """Make a Pydantic JSON schema compatible with strict structured outputs:
    every object closed (additionalProperties false) and every property required."""
    if schema.get("type") == "object" and "properties" in schema:
        schema["additionalProperties"] = False
        schema["required"] = list(schema["properties"].keys())
    for value in schema.values():
        if isinstance(value, dict):
            _strict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _strict(item)
    return schema


def verdict_json_schema() -> dict:
    schema = TriageVerdict.model_json_schema()
    # Strict mode does not accept numeric bounds or titles everywhere; keep it lean.
    def clean(node):
        if isinstance(node, dict):
            for key in ("title", "minimum", "maximum", "default"):
                node.pop(key, None)
            for v in node.values():
                clean(v)
        elif isinstance(node, list):
            for v in node:
                clean(v)
    clean(schema)
    return _strict(schema)
