"""
Whitelist — false-positive suppression for agentlens violations.

A WhitelistRule matches when ALL specified conditions hold:
  - rule_ids      : violation's rule_id is in this set (empty = any)
  - tool_names    : event's tool_name is in this set   (empty = any)
  - input_contains: any string in this list appears in the serialised tool_input (empty = any)

Suppressed violations are still written to the audit log under
`suppressed_violations` so the audit trail is never silently modified.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .models import ToolUseEvent
from .rules import Violation


@dataclass
class WhitelistRule:
    """Single suppression rule.

    Examples::

        # Suppress PATH_ENV_FILE for any tool (dev environments routinely read .env)
        WhitelistRule(rule_ids=["PATH_ENV_FILE"], reason="Dev: .env access is expected")

        # Suppress SHELL_SUDO only when the bash input contains '# example'
        WhitelistRule(
            rule_ids=["SHELL_SUDO"],
            tool_names=["bash"],
            input_contains=["# example", "# Example"],
            reason="Documentation examples may reference sudo",
        )
    """
    rule_ids: List[str] = field(default_factory=list)
    """Violation rule IDs to suppress. Empty list matches any rule."""

    tool_names: List[str] = field(default_factory=list)
    """Tool names this rule applies to. Empty list matches any tool."""

    input_contains: List[str] = field(default_factory=list)
    """Suppress only when tool_input (serialised) contains at least one of these strings."""

    reason: str = ""
    """Human-readable explanation for the suppression (appears in audit log)."""

    def matches(self, event: ToolUseEvent, violation: Violation) -> bool:
        if self.rule_ids and violation.rule_id not in self.rule_ids:
            return False
        if self.tool_names and (event.tool_name or "").lower() not in [t.lower() for t in self.tool_names]:
            return False
        if self.input_contains:
            serialised = json.dumps(event.tool_input, ensure_ascii=False)
            if not any(s in serialised for s in self.input_contains):
                return False
        return True


class Whitelist:
    """Collection of WhitelistRules.

    Usage::

        from agentlens import AuditedAnthropic, Whitelist, WhitelistRule

        wl = Whitelist([
            WhitelistRule(rule_ids=["PATH_ENV_FILE"], reason="Expected in dev"),
        ])
        client = AuditedAnthropic(log_path="audit.jsonl", whitelist=wl)

    After filtering, suppressed violations are stored on the event under
    ``event.suppressed_violations`` (list of dicts) so that downstream
    audit tooling can reconstruct the full picture.
    """

    def __init__(self, rules: Optional[Sequence[WhitelistRule]] = None) -> None:
        self._rules: List[WhitelistRule] = list(rules or [])

    def filter(
        self, event: ToolUseEvent, violations: List[Violation]
    ) -> tuple[List[Violation], List[dict]]:
        """Partition violations into (active, suppressed).

        Returns:
            active     : violations that were NOT suppressed
            suppressed : list of dicts describing suppressed violations (rule_id + reason)
        """
        active: List[Violation] = []
        suppressed: List[dict] = []

        for v in violations:
            matched_rule = next(
                (r for r in self._rules if r.matches(event, v)), None
            )
            if matched_rule:
                suppressed.append({
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "matched_value": v.matched_value,
                    "whitelist_reason": matched_rule.reason,
                })
            else:
                active.append(v)

        return active, suppressed
