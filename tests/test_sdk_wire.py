"""Runs the agent through the real OpenAI SDK against a mocked HTTP transport,
checking the exact request bodies sent to /v1/responses and that real SDK
response objects are parsed correctly. No network or API key needed."""

import json

from openai import OpenAI

try:  # newer SDKs ship on httpx2, older ones on httpx
    import httpx2 as httpx
except ImportError:  # pragma: no cover
    import httpx

from evals.run_eval import load_rows
from triage.agent import triage

ALERT = {row["alert"]["id"]: row["alert"] for row in load_rows()}["ALT-012"]


def response_json(output):
    return {
        "id": "resp_test", "object": "response", "created_at": 0, "model": "test-model",
        "status": "completed", "output": output, "parallel_tool_calls": True,
        "tool_choice": "auto", "tools": [],
    }


def test_wire_format_with_real_sdk():
    bodies = []
    verdict = {
        "verdict": "true_positive", "confidence": 0.93, "summary": "Beacon to tracked C2.",
        "evidence": [{"source": "lookup_indicator", "detail": "45.155.205.233 malicious (C2 tracker)"}],
        "mitre_techniques": ["T1071.001"],
        "proposed_actions": [{"action": "block_ip", "target": "45.155.205.233", "reason": "C2"}],
    }
    replies = [
        response_json([{
            "type": "function_call", "id": "fc_1", "call_id": "call_1", "status": "completed",
            "name": "lookup_indicator", "arguments": json.dumps({"indicator_type": "ip", "value": "45.155.205.233"}),
        }]),
        response_json([{
            "type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": json.dumps(verdict), "annotations": []}],
        }]),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/responses")
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=replies[len(bodies) - 1])

    client = OpenAI(api_key="test", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    res = triage(ALERT, client, model="test-model")

    assert res.verdict.verdict == "true_positive" and res.tool_calls == 1
    first, second = bodies
    assert first["text"]["format"]["type"] == "json_schema" and first["text"]["format"]["strict"] is True
    assert {t["name"] for t in first["tools"]} == {"lookup_indicator", "get_asset_context", "query_host_events"}
    types = [i.get("type") for i in second["input"]]
    assert "function_call" in types and "function_call_output" in types
    fc = next(i for i in second["input"] if i.get("type") == "function_call")
    assert set(fc) <= {"type", "id", "call_id", "name", "arguments", "status"}
