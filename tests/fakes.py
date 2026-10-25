"""Offline stand-in for the OpenAI client so tests and CI need no API key."""

from __future__ import annotations

import json

from openai.types.responses import ResponseFunctionToolCall


class FakeResponse:
    def __init__(self, output=None, output_text=""):
        self.output = output or []
        self.output_text = output_text


def tool_call(name: str, call_id: str = "call_1", **args) -> FakeResponse:
    return FakeResponse(output=[ResponseFunctionToolCall(
        type="function_call", name=name, call_id=call_id, arguments=json.dumps(args),
    )])


def final(**verdict) -> FakeResponse:
    base = {"verdict": "needs_review", "confidence": 0.5, "summary": "s", "evidence": [],
            "mitre_techniques": [], "proposed_actions": []}
    base.update(verdict)
    return FakeResponse(output_text=json.dumps(base))


class FakeClient:
    """Returns scripted responses in order and records every request."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.responses = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        if not self.script:
            raise AssertionError("FakeClient ran out of scripted responses")
        nxt = self.script.pop(0)
        return nxt(kwargs) if callable(nxt) else nxt
