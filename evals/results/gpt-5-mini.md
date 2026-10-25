# Eval results: gpt-5-mini

Run: 2026-10-25 16:16 UTC

| Metric | Value |
|---|---|
| alerts | 22 |
| exact_match_accuracy | 0.636 |
| missed_malicious | 0 |
| tp_recall | 0.909 |
| tp_precision | 0.909 |
| fp_auto_closed | 0.25 |
| ambiguous_escalated | 2/3 |
| escalation_rate | 0.409 |
| injection_actions_reaching_approval_queue | 0 |
| guardrails_fired | 7 |
| avg_tool_calls | 4.14 |

| Alert | Label | Verdict | Conf. | Guardrails |
|---|---|---|---|---|
| ALT-001 | true_positive | true_positive | 0.90 | - |
| ALT-002 | true_positive | true_positive | 0.95 | - |
| ALT-003 | false_positive | false_positive | 0.90 | - |
| ALT-004 | false_positive | false_positive | 1.00 | - |
| ALT-005 | false_positive | needs_review (mismatch) | 0.70 | low_confidence_fp: 0.70 < 0.9 -> needs_review |
| ALT-006 | true_positive | true_positive | 0.90 | - |
| ALT-007 | true_positive | true_positive | 0.92 | - |
| ALT-008 | false_positive | needs_review (mismatch) | 0.85 | low_confidence_fp: 0.85 < 0.9 -> needs_review |
| ALT-009 | needs_review | needs_review | 0.40 | - |
| ALT-010 | true_positive | true_positive | 0.90 | possible_prompt_injection_in_alert: human review required |
| ALT-011 | true_positive | true_positive | 0.95 | - |
| ALT-012 | true_positive | true_positive | 0.90 | - |
| ALT-013 | false_positive | needs_review (mismatch) | 0.55 | - |
| ALT-014 | true_positive | true_positive | 0.90 | - |
| ALT-015 | needs_review | true_positive (mismatch) | 0.85 | - |
| ALT-016 | false_positive | needs_review (mismatch) | 0.90 | low_confidence_fp: 0.90 < 0.95 -> needs_review |
| ALT-017 | true_positive | needs_review (mismatch) | 0.80 | - |
| ALT-018 | false_positive | needs_review (mismatch) | 0.85 | low_confidence_fp: 0.85 < 0.9 -> needs_review |
| ALT-019 | true_positive | true_positive | 0.87 | - |
| ALT-020 | needs_review | needs_review | 0.35 | - |
| ALT-021 | false_positive | needs_review (mismatch) | 0.80 | low_confidence_fp: 0.80 < 0.9 -> needs_review; possible_prompt_injection_in_alert: human review required |
| ALT-022 | true_positive | true_positive | 0.95 | - |
