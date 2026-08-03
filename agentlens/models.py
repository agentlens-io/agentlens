from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, List
import json
import os
import re
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Provenance:
    """Who ran the agent, and under what authority (Layer B — provenance).

    Attached to every audit event so the log can answer not just *what*
    happened, but *who* caused it and *with what granted authority*.

    Fields:
        agent_id      : stable identifier of the agent (e.g. "deploy-bot")
        principal     : the human/service on whose behalf it runs (e.g. "alice@corp")
        authority     : granted scopes/roles recorded at run time (e.g. ["repo:read"])
        run_id        : unique id for this run/process (auto-generated if omitted)
        parent_run_id : run_id of the agent that spawned this one (lineage)
        metadata      : free-form provenance context (region, ticket, etc.)

    Recording only — agentlens does not grant or enforce authority here; it
    captures the declared identity so a later reader can prove provenance.
    """
    agent_id: str = ""
    principal: Optional[str] = None
    authority: List[str] = field(default_factory=list)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_run_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "Provenance":
        """Build provenance from environment variables.

        Hosted/CI agents usually receive their identity from the orchestration
        platform via env, so this is the common wiring path:
            AGENTLENS_AGENT_ID, AGENTLENS_PRINCIPAL,
            AGENTLENS_AUTHORITY (comma/space separated),
            AGENTLENS_RUN_ID, AGENTLENS_PARENT_RUN_ID
        """
        e = env if env is not None else os.environ
        authority = [a for a in re.split(r"[,\s]+", e.get("AGENTLENS_AUTHORITY", "")) if a]
        kwargs: dict = {
            "agent_id":      e.get("AGENTLENS_AGENT_ID", ""),
            "principal":     e.get("AGENTLENS_PRINCIPAL") or None,
            "authority":     authority,
            "parent_run_id": e.get("AGENTLENS_PARENT_RUN_ID") or None,
        }
        run_id = e.get("AGENTLENS_RUN_ID")
        if run_id:
            kwargs["run_id"] = run_id
        return cls(**kwargs)


def normalize_provenance(prov: Any) -> dict:
    """Accept a Provenance, a plain dict, or None → always return a dict.

    Kept permissive so callers can pass either the dataclass or a raw dict
    without agentlens dictating their identity model.
    """
    if prov is None:
        return {}
    if isinstance(prov, Provenance):
        return prov.as_dict()
    if isinstance(prov, dict):
        return dict(prov)
    raise TypeError(f"provenance must be Provenance, dict, or None (got {type(prov).__name__})")


class PreExecutionBlockedError(Exception):
    """Raised when a pre-execution hook blocks a tool call before it reaches the caller.

    Attributes:
        event      : ToolUseEvent that was blocked (already written to the audit log)
        violations : list of Violation that triggered the block
    """
    def __init__(self, event: "ToolUseEvent", violations: list) -> None:
        self.event = event
        self.violations = violations
        rule_ids = ", ".join(getattr(v, "rule_id", str(v)) for v in violations)
        super().__init__(
            f"[agentlens] Tool '{event.tool_name}' blocked before execution: {rule_ids}"
        )


@dataclass
class ToolUseEvent:
    """Emitted when Claude decides to call a tool."""
    event_type: str = "tool_use"
    tool_use_id: str = ""
    tool_name: str = ""
    tool_input: dict = field(default_factory=dict)
    model: str = ""
    timestamp: str = field(default_factory=_now)
    session_id: Optional[str] = None
    violations: List[dict] = field(default_factory=list)           # active violations (after whitelist)
    suppressed_violations: List[dict] = field(default_factory=list) # whitelist-suppressed violations
    provenance: dict = field(default_factory=dict)                  # who/what authority (Layer B)
    entry_hash: str = ""  # SHA-256 hash chain (set by FileWriter)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    def to_json_without_hash(self) -> str:
        d = asdict(self)
        d.pop("entry_hash", None)
        return json.dumps(d, ensure_ascii=False)


@dataclass
class ToolResultEvent:
    """Emitted when a tool result is returned to Claude."""
    event_type: str = "tool_result"
    tool_use_id: str = ""
    result_content: Any = None
    is_error: bool = False
    timestamp: str = field(default_factory=_now)
    session_id: Optional[str] = None
    provenance: dict = field(default_factory=dict)                  # who/what authority (Layer B)
    entry_hash: str = ""  # SHA-256 hash chain (set by FileWriter)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    def to_json_without_hash(self) -> str:
        d = asdict(self)
        d.pop("entry_hash", None)
        return json.dumps(d, ensure_ascii=False)
