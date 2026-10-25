"""Deterministic checks that sit between the model and anything that matters.

The model proposes; these rules decide what is allowed to stand. Each rule
that fires is recorded so analysts can see exactly why a verdict changed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .schema import TriageVerdict

ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
INJECTION_PATTERNS = re.compile(
    r"ignore (all |any |previous |prior )?instructions|you are now|system prompt|"
    r"mark (this|it) as (false positive|benign)|disregard|do not escalate",
    re.IGNORECASE,
)


@dataclass
class GuardrailResult:
    verdict: TriageVerdict
    fired: list[str] = field(default_factory=list)


def match_exception(alert: dict, tenant: dict) -> dict | None:
    """Customer-scoped suppression: return the matching exception, if any."""
    for exc in tenant.get("exceptions", []):
        if str(alert.get(exc["field"], "")) == exc["value"]:
            return exc
    return None


def looks_like_injection(alert: dict) -> bool:
    text = " ".join(str(v) for v in alert.values() if isinstance(v, str))
    return bool(INJECTION_PATTERNS.search(text))


def apply(alert: dict, verdict: TriageVerdict, tenant: dict, observed_text: str) -> GuardrailResult:
    """Apply post-model guardrails.

    observed_text is the alert plus every tool output the model saw; proposed
    action targets must appear in it, so the model cannot act on values it
    invented or that only exist in its own reasoning.
    """
    v = verdict.model_copy(deep=True)
    fired: list[str] = []

    # 1. Evidence is mandatory for any decided verdict.
    if v.verdict != "needs_review" and not v.evidence:
        v.verdict = "needs_review"
        fired.append("no_evidence: decided verdict without evidence -> needs_review")

    # 2. Only well-formed ATT&CK IDs survive.
    bad = [t for t in v.mitre_techniques if not ATTACK_ID.match(t)]
    if bad:
        v.mitre_techniques = [t for t in v.mitre_techniques if ATTACK_ID.match(t)]
        fired.append(f"invalid_attack_ids_removed: {bad}")

    # 3. Auto-close only on high-confidence false positives.
    threshold = tenant.get("auto_close_fp_min_confidence", 0.9)
    if v.verdict == "false_positive" and v.confidence < threshold:
        v.verdict = "needs_review"
        fired.append(f"low_confidence_fp: {v.confidence:.2f} < {threshold} -> needs_review")

    # 4. Untrusted alert text that tries to steer the model goes to a human.
    if looks_like_injection(alert):
        if v.verdict == "false_positive":
            v.verdict = "needs_review"
        fired.append("possible_prompt_injection_in_alert: human review required")

    # 5. Proposed actions must be grounded and allowed for this tenant.
    kept = []
    never_block = set(tenant.get("never_block", []))
    for action in v.proposed_actions:
        if action.action != "create_ticket" and action.target not in observed_text:
            fired.append(f"ungrounded_action_dropped: {action.action} {action.target}")
            continue
        if action.action in ("block_ip", "block_domain") and action.target in never_block:
            fired.append(f"protected_target_dropped: {action.action} {action.target}")
            continue
        kept.append(action)
    v.proposed_actions = kept

    # 6. A false positive never carries containment actions.
    if v.verdict == "false_positive" and any(a.action != "create_ticket" for a in v.proposed_actions):
        v.proposed_actions = [a for a in v.proposed_actions if a.action == "create_ticket"]
        fired.append("containment_on_fp_removed")

    return GuardrailResult(verdict=v, fired=fired)
