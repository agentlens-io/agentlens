import uuid
from dataclasses import asdict
from typing import Any, Callable, List, Optional

import anthropic

from .models import ToolUseEvent, ToolResultEvent
from .rules import check, Violation
from .writers.base import BaseWriter
from .writers.file import FileWriter

OnViolation = Callable[[ToolUseEvent, List[Violation]], None]


def _default_on_violation(event: ToolUseEvent, violations: List[Violation]) -> None:
    for v in violations:
        print(
            f"[agentlens] {v.severity.upper()} {v.rule_id}: {v.description} "
            f"(tool={event.tool_name}, matched='{v.matched_value}')"
        )


class AuditedMessages:
    """Wraps anthropic.resources.Messages.
    Intercepts every create() call to capture:
      - tool_use blocks in the response  (what Claude decided to do)
      - tool_result blocks in the input  (what actually came back)
    The original request/response is never modified.
    """

    def __init__(
        self,
        client: anthropic.Anthropic,
        writer: BaseWriter,
        session_id: str,
        on_violation: OnViolation,
    ):
        self._client = client
        self._writer = writer
        self._session_id = session_id
        self._on_violation = on_violation

    def create(self, **kwargs) -> Any:
        # --- Capture tool_result blocks from inbound messages ---
        for msg in kwargs.get("messages", []):
            if msg.get("role") != "user":
                continue
            content = msg.get("content", [])
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    self._writer.write(ToolResultEvent(
                        tool_use_id=block.get("tool_use_id", ""),
                        result_content=block.get("content"),
                        is_error=block.get("is_error", False),
                        session_id=self._session_id,
                    ))

        # --- Forward to Anthropic API (read-only, no modification) ---
        response = self._client.messages.create(**kwargs)

        # --- Capture tool_use blocks from response ---
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                event = ToolUseEvent(
                    tool_use_id=block.id,
                    tool_name=block.name,
                    tool_input=block.input,
                    model=response.model,
                    session_id=self._session_id,
                )
                violations = check(event)
                if violations:
                    event.violations = [asdict(v) for v in violations]
                    self._on_violation(event, violations)
                self._writer.write(event)

        return response


class AuditedAnthropic:
    """Drop-in replacement for anthropic.Anthropic that adds audit logging.

    Usage:
        from agentlens import AuditedAnthropic

        client = AuditedAnthropic(log_path="./audit.jsonl")
        # Use exactly like anthropic.Anthropic()

    Design principles:
        - Read-only interception: requests/responses are never altered
        - Append-only writes: log entries cannot be edited after creation
        - Logger is deterministic code, not an LLM
        - Data stays local by default (FileWriter)
    """

    def __init__(
        self,
        writer: Optional[BaseWriter] = None,
        log_path: str = "./agentlens_audit.jsonl",
        session_id: Optional[str] = None,
        on_violation: Optional[OnViolation] = None,
        **anthropic_kwargs,
    ):
        self._client = anthropic.Anthropic(**anthropic_kwargs)
        self._writer = writer or FileWriter(log_path)
        self._session_id = session_id or str(uuid.uuid4())
        self._on_violation = on_violation or _default_on_violation
        self.messages = AuditedMessages(
            self._client, self._writer, self._session_id, self._on_violation
        )
