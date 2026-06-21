import uuid
from dataclasses import asdict
from typing import Any, Callable, List, Optional, Tuple

import anthropic

from .models import ToolUseEvent, ToolResultEvent, PreExecutionBlockedError
from .rules import check, Violation
from .whitelist import Whitelist, WhitelistRule
from .writers.base import BaseWriter
from .writers.file import FileWriter

OnViolation    = Callable[[ToolUseEvent, List[Violation]], None]
OnPreExecution = Callable[[ToolUseEvent, List[Violation]], None]


def _default_on_violation(event: ToolUseEvent, violations: List[Violation]) -> None:
    for v in violations:
        print(
            f"[agentlens] {v.severity.upper()} {v.rule_id}: {v.description} "
            f"(tool={event.tool_name}, matched='{v.matched_value}')"
        )


def _make_pre_execution_hook(block_on_critical: bool) -> OnPreExecution:
    """Returns a pre-execution hook that raises PreExecutionBlockedError on critical violations."""
    def hook(event: ToolUseEvent, violations: List[Violation]) -> None:
        if block_on_critical and any(v.severity == "critical" for v in violations):
            raise PreExecutionBlockedError(event, violations)
    return hook


class AuditedMessages:
    """Wraps anthropic.resources.Messages.
    Intercepts every create() call to:
      1. Capture tool_result blocks in inbound messages (post-execution facts)
      2. Capture tool_use blocks in the response (what Claude decided to do)
      3. Run danger rules — emit violations via on_violation
      4. Run pre-execution hook — can raise PreExecutionBlockedError to stop execution

    The original request/response is never modified.
    If PreExecutionBlockedError is raised, the event is written to the log first,
    then the exception propagates to the caller — response is withheld.
    """

    def __init__(
        self,
        client: anthropic.Anthropic,
        writer: BaseWriter,
        session_id: str,
        on_violation: OnViolation,
        on_pre_execution: OnPreExecution,
        whitelist: Optional[Whitelist] = None,
    ):
        self._client = client
        self._writer = writer
        self._session_id = session_id
        self._on_violation = on_violation
        self._on_pre_execution = on_pre_execution
        self._whitelist = whitelist

    def create(self, **kwargs) -> Any:
        # ── 1. Capture tool_result blocks from inbound messages ──
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

        # ── 2. Forward to Anthropic API (read-only) ──
        response = self._client.messages.create(**kwargs)

        # ── 3 & 4. Capture tool_use → check rules → pre-execution gate ──
        block_to_raise: Optional[Tuple[PreExecutionBlockedError]] = None

        for block in response.content:
            if getattr(block, "type", None) != "tool_use":
                continue

            event = ToolUseEvent(
                tool_use_id=block.id,
                tool_name=block.name,
                tool_input=block.input,
                model=response.model,
                session_id=self._session_id,
            )
            all_violations = check(event)

            # Apply whitelist: partition into active vs suppressed
            if self._whitelist and all_violations:
                active_violations, suppressed = self._whitelist.filter(event, all_violations)
                if suppressed:
                    event.suppressed_violations = suppressed
            else:
                active_violations = all_violations

            violations = active_violations
            if violations:
                event.violations = [asdict(v) for v in violations]
                self._on_violation(event, violations)

            # Always write to audit log first (forensic completeness)
            self._writer.write(event)

            # Pre-execution gate: run hook; if it raises, capture for re-raise after full loop
            if violations and block_to_raise is None:
                try:
                    self._on_pre_execution(event, violations)
                except PreExecutionBlockedError as exc:
                    block_to_raise = exc

        # Raise after all events are logged so the audit trail is complete
        if block_to_raise is not None:
            raise block_to_raise

        return response


class AuditedAnthropic:
    """Drop-in replacement for anthropic.Anthropic that adds audit logging.

    Usage — basic:
        from agentlens import AuditedAnthropic

        client = AuditedAnthropic(log_path="./audit.jsonl")
        # Use exactly like anthropic.Anthropic()

    Usage — block critical violations before execution:
        client = AuditedAnthropic(
            log_path="./audit.jsonl",
            block_on_critical=True,
        )
        # Raises PreExecutionBlockedError when Claude attempts rm -rf /, key exfiltration, etc.

    Usage — custom pre-execution hook:
        def my_hook(event, violations):
            send_slack_alert(violations)
            if any(v.severity == "critical" for v in violations):
                raise PreExecutionBlockedError(event, violations)

        client = AuditedAnthropic(on_pre_execution=my_hook)

    Design principles:
        - Read-only interception: requests/responses are never altered
        - Append-only writes: log entries cannot be edited after creation
        - Logger is deterministic code, not an LLM
        - Data stays local by default (FileWriter)
        - Pre-execution blocking is opt-in (block_on_critical=False by default)
    """

    def __init__(
        self,
        writer: Optional[BaseWriter] = None,
        log_path: str = "./agentlens_audit.jsonl",
        session_id: Optional[str] = None,
        on_violation: Optional[OnViolation] = None,
        on_pre_execution: Optional[OnPreExecution] = None,
        block_on_critical: bool = False,
        whitelist: Optional[Whitelist] = None,
        **anthropic_kwargs,
    ):
        self._client = anthropic.Anthropic(**anthropic_kwargs)
        self._writer = writer or FileWriter(log_path)
        self._session_id = session_id or str(uuid.uuid4())
        self._on_violation = on_violation or _default_on_violation

        # on_pre_execution priority: explicit hook > block_on_critical flag > no-op
        if on_pre_execution is not None:
            self._on_pre_execution = on_pre_execution
        else:
            self._on_pre_execution = _make_pre_execution_hook(block_on_critical)

        self.messages = AuditedMessages(
            self._client,
            self._writer,
            self._session_id,
            self._on_violation,
            self._on_pre_execution,
            whitelist=whitelist,
        )
