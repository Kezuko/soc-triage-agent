import json

import pytest

from evals.run_eval import load_rows, score
from triage.agent import MAX_STEPS, triage
from triage.approval import ApprovalQueue
from triage.audit import AuditLog
from triage.schema import ProposedAction, verdict_json_schema
from triage.tools import call_tool

from .fakes import FakeClient, final, tool_call

ALERTS = {row["alert"]["id"]: row["alert"] for row in load_rows()}
EVIDENCE = [{"source": "lookup_indicator", "detail": "45.155.205.233 is a tracked C2"}]


def walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk(v)


def test_schema_is_strict_compatible():
    for node in walk(verdict_json_schema()):
        if node.get("type") == "object" and "properties" in node:
            assert node["additionalProperties"] is False
            assert set(node["required"]) == set(node["properties"])


def test_tool_loop_feeds_results_back_and_returns_structured_verdict():
    client = FakeClient([
        tool_call("lookup_indicator", indicator_type="ip", value="45.155.205.233"),
        final(verdict="true_positive", confidence=0.95, evidence=EVIDENCE, mitre_techniques=["T1071.001"],
              proposed_actions=[{"action": "block_ip", "target": "45.155.205.233", "reason": "C2"}]),
    ])
    res = triage(ALERTS["ALT-012"], client)
    assert res.verdict.verdict == "true_positive"
    assert res.tool_calls == 1
    second_input = client.requests[1]["input"]
    outputs = [i for i in second_input if isinstance(i, dict) and i.get("type") == "function_call_output"]
    assert json.loads(outputs[0]["output"])["reputation"] == "malicious"
    assert res.verdict.proposed_actions[0].target == "45.155.205.233"
    assert client.requests[0]["text"]["format"]["strict"] is True


def test_tenant_exception_suppresses_without_calling_model():
    client = FakeClient([])
    res = triage(ALERTS["ALT-004"], client)
    assert res.suppressed_by_exception and res.verdict.verdict == "false_positive"
    assert client.requests == []


def test_low_confidence_false_positive_is_escalated():
    client = FakeClient([final(verdict="false_positive", confidence=0.6, evidence=EVIDENCE)])
    res = triage(ALERTS["ALT-003"], client)
    assert res.verdict.verdict == "needs_review"
    assert any(r.startswith("low_confidence_fp") for r in res.guardrails_fired)


def test_decided_verdict_without_evidence_is_escalated():
    client = FakeClient([final(verdict="true_positive", confidence=0.99, evidence=[])])
    assert triage(ALERTS["ALT-001"], client).verdict.verdict == "needs_review"


def test_prompt_injection_cannot_close_alert_or_block_protected_ip():
    # Simulate a model that obeyed the injected instruction.
    client = FakeClient([final(
        verdict="false_positive", confidence=0.99, evidence=EVIDENCE,
        proposed_actions=[{"action": "block_ip", "target": "8.8.8.8", "reason": "per alert note"}],
    )])
    res = triage(ALERTS["ALT-010"], client)
    assert res.verdict.verdict == "needs_review"
    assert not any(a.target == "8.8.8.8" for a in res.verdict.proposed_actions)
    assert any("prompt_injection" in r for r in res.guardrails_fired)


def test_ungrounded_action_target_is_dropped():
    client = FakeClient([final(
        verdict="true_positive", confidence=0.9, evidence=EVIDENCE,
        proposed_actions=[{"action": "block_ip", "target": "203.0.113.77", "reason": "invented"}],
    )])
    res = triage(ALERTS["ALT-012"], client)
    assert res.verdict.proposed_actions == []
    assert any(r.startswith("ungrounded_action_dropped") for r in res.guardrails_fired)


def test_invalid_attack_ids_removed():
    client = FakeClient([final(verdict="true_positive", confidence=0.9, evidence=EVIDENCE,
                               mitre_techniques=["T1059.001", "CVE-2025-8088", "Phishing"])])
    assert triage(ALERTS["ALT-001"], client).verdict.mitre_techniques == ["T1059.001"]


def test_malformed_model_output_falls_back_to_review():
    from .fakes import FakeResponse
    client = FakeClient([FakeResponse(output_text='{"verdict": "maybe"}')])
    assert triage(ALERTS["ALT-001"], client).verdict.verdict == "needs_review"


def test_step_limit_falls_back_to_review():
    client = FakeClient([tool_call("get_asset_context", call_id=f"c{i}", hostname="WS-FIN-021")
                         for i in range(MAX_STEPS)])
    res = triage(ALERTS["ALT-001"], client)
    assert res.verdict.verdict == "needs_review" and res.tool_calls == MAX_STEPS


def test_actions_only_execute_after_named_approval(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    queue = ApprovalQueue(audit)
    [item] = queue.submit("ALT-012", [ProposedAction(action="block_ip", target="45.155.205.233", reason="C2")])
    assert item.status == "pending" and item.result is None
    with pytest.raises(ValueError):
        queue.decide(item, True, analyst="")
    queue.decide(item, True, analyst="terence")
    assert item.result == {"simulated": True, "would_call": "block_ip('45.155.205.233')"}
    kinds = [json.loads(line)["kind"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert kinds == ["action_proposed", "action_decision"]


def test_tools_handle_bad_input():
    assert "error" in call_tool("drop_tables", "{}")
    assert "error" in call_tool("lookup_indicator", '{"indicator_type": "ip"}')
    assert call_tool("get_asset_context", '{"hostname": "nope"}')["found"] is False


def test_scoring_counts_missed_malicious():
    rows = [{"label": "true_positive"}, {"label": "false_positive"}, {"label": "needs_review"}]
    preds = [
        {"alert_id": "A", "verdict": "false_positive", "proposed_actions": [], "guardrails_fired": [], "tool_calls": 1},
        {"alert_id": "B", "verdict": "false_positive", "proposed_actions": [], "guardrails_fired": [], "tool_calls": 2},
        {"alert_id": "C", "verdict": "needs_review", "proposed_actions": [], "guardrails_fired": [], "tool_calls": 0},
    ]
    m = score(rows, preds)
    assert m["missed_malicious"] == 1 and m["fp_auto_closed"] == 1.0 and m["ambiguous_escalated"] == "1/1"
