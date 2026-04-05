from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, List
import json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    violations: List[dict] = field(default_factory=list)  # populated by rules.check()

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


@dataclass
class ToolResultEvent:
    """Emitted when a tool result is returned to Claude."""
    event_type: str = "tool_result"
    tool_use_id: str = ""
    result_content: Any = None
    is_error: bool = False
    timestamp: str = field(default_factory=_now)
    session_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)
