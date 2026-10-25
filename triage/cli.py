"""Triage one alert from the eval set and walk through the approval gate.

    python -m triage.cli ALT-001
    python -m triage.cli ALT-001 --analyst terence --auto-reject
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent import DEFAULT_MODEL, triage
from .approval import ApprovalQueue
from .audit import AuditLog

ALERTS = Path(__file__).resolve().parent.parent / "evals" / "alerts.jsonl"


def load_alert(alert_id: str) -> dict:
    with open(ALERTS, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if row["alert"]["id"] == alert_id:
                return row["alert"]
    raise SystemExit(f"alert {alert_id} not found in {ALERTS}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alert_id")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--analyst", default="")
    parser.add_argument("--auto-reject", action="store_true", help="reject every proposed action")
    parser.add_argument("--audit", default="runs/audit.jsonl")
    args = parser.parse_args()

    from openai import OpenAI

    audit = AuditLog(args.audit)
    result = triage(load_alert(args.alert_id), OpenAI(), model=args.model, audit=audit)
    v = result.verdict
    print(f"\n{result.alert_id}: {v.verdict} (confidence {v.confidence:.2f}, {result.tool_calls} tool calls)")
    print(v.summary)
    for e in v.evidence:
        print(f"  - [{e.source}] {e.detail}")
    if v.mitre_techniques:
        print("ATT&CK:", ", ".join(v.mitre_techniques))
    for rule in result.guardrails_fired:
        print("guardrail:", rule)

    queue = ApprovalQueue(audit)
    for item in queue.submit(result.alert_id, v.proposed_actions):
        prompt = f"\nApprove {item.action.action} {item.action.target}? ({item.action.reason}) [y/N] "
        approve = False if args.auto_reject else input(prompt).strip().lower() == "y"
        analyst = args.analyst or input("Your name: ").strip()
        queue.decide(item, approve, analyst)
        print(f"  -> {item.status}", item.result or "")
    print(f"\nAudit trail: {args.audit}")


if __name__ == "__main__":
    main()
