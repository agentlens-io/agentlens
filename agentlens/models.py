from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, List
import json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    entry_hash: str = ""  # SHA-256 hash chain (set by FileWriter)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    def to_json_without_hash(self) -> str:
        d = asdict(self)
        d.pop("entry_hash", None)
        return json.dumps(d, ensure_ascii=False)
