"""Authority enforcement (Layer B, step 2).

v0.10 *recorded* provenance.authority — the scopes an agent was granted at run
time. This module turns that record into *enforcement*: a tool call whose
required scopes are not fully covered by the granted authority produces a
critical :class:`~agentlens.rules.Violation`, which the existing pre-execution
gate blocks (``block_on_critical=True``). Record → enforce.

Design notes (kept deliberately small — agentlens does not impose an identity
system):

* Enforcement is **opt-in**. No policy → behaviour is byte-for-byte identical
  to v0.10 (pure recording).
* A tool is allowed **iff every scope in its requirement is present** in the
  event's ``provenance.authority`` (AND semantics — list a single scope for the
  common case; the rule stays unambiguous).
* Authority checks reuse the ``Violation`` type and the same gate as the danger
  rules, so nothing new is needed downstream (CLI, hash chain, callbacks all
  already understand Violations).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import ToolUseEvent
from .rules import Violation

AUTHORITY_RULE_ID = "AUTHORITY_OUT_OF_SCOPE"


@dataclass
class AuthorityPolicy:
    """Enforce that a tool call stays within an agent's granted authority.

    Attributes:
        requirements:
            ``tool_name -> [scope, ...]``. Every listed scope must be present
            in the event's ``provenance.authority`` for the tool to be allowed.
        default_required:
            Scopes required for any tool **not** listed in ``requirements``.
            ``None`` (default) or ``[]`` allows unmapped tools — start by
            restricting only the tools you care about, then tighten with a
            deny-by-default policy (e.g. ``default_required=["*"]``) once your
            scope map is complete.
        severity:
            Severity of an out-of-scope violation. Defaults to ``"critical"``
            so it trips ``block_on_critical`` like the built-in danger rules.
    """

    requirements: Dict[str, List[str]] = field(default_factory=dict)
    default_required: Optional[List[str]] = None
    severity: str = "critical"

    def required_scopes(self, tool_name: str) -> Optional[List[str]]:
        """Scopes required to call ``tool_name`` (``None`` = unrestricted)."""
        if tool_name in self.requirements:
            return self.requirements[tool_name]
        return self.default_required

    def check(self, event: ToolUseEvent) -> List[Violation]:
        """Return a (possibly empty) list of authority violations for one event."""
        required = self.required_scopes(event.tool_name)
        if not required:  # None or [] → no restriction on this tool
            return []

        granted = set((event.provenance or {}).get("authority", []) or [])
        # "*" in the *granted* authority is a wildcard super-scope (grants everything).
        # On the *required* side, "*" is an ordinary scope name (use it as a
        # default_required to get deny-by-default: only agents granted "*" pass).
        if "*" in granted:
            return []

        missing = [s for s in required if s not in granted]
        if not missing:
            return []

        granted_list = sorted(granted)
        return [
            Violation(
                rule_id=AUTHORITY_RULE_ID,
                severity=self.severity,
                description=(
                    f"Tool '{event.tool_name}' requires authority {list(required)}; "
                    f"granted={granted_list or '[]'}; missing {missing}"
                ),
                matched_value=",".join(missing),
            )
        ]
