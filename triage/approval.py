"""Human approval gate for containment actions.

Nothing proposed by the model executes until a named analyst approves it.
Execution here is simulated (it returns what *would* be sent to the
firewall/EDR/ticketing API) so the demo is safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .audit import AuditLog
from .schema import ProposedAction


@dataclass
class PendingAction:
    alert_id: str
    action: ProposedAction
    status: str = "pending"  # pending | approved | rejected
    decided_by: str | None = None
    result: dict | None = None


@dataclass
class ApprovalQueue:
    audit: AuditLog
    items: list[PendingAction] = field(default_factory=list)

    def submit(self, alert_id: str, actions: list[ProposedAction]) -> list[PendingAction]:
        new = [PendingAction(alert_id=alert_id, action=a) for a in actions]
        self.items.extend(new)
        for p in new:
            self.audit.write("action_proposed", alert_id=alert_id, **p.action.model_dump())
        return new

    def decide(self, item: PendingAction, approve: bool, analyst: str) -> PendingAction:
        if item.status != "pending":
            raise ValueError("already decided")
        if not analyst:
            raise ValueError("an approving analyst must be named")
        item.status = "approved" if approve else "rejected"
        item.decided_by = analyst
        if approve:
            item.result = execute(item.action)
        self.audit.write(
            "action_decision", alert_id=item.alert_id, status=item.status, analyst=analyst,
            action=item.action.action, target=item.action.target, result=item.result,
        )
        return item


def execute(action: ProposedAction) -> dict:
    """Simulated connector call. Replace with real firewall/EDR/ticketing APIs."""
    return {"simulated": True, "would_call": f"{action.action}({action.target!r})"}
