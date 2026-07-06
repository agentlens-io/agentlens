import uuid
from dataclasses import asdict
from typing import Any, Callable, List, Optional

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


class _AuditCore:
    """Shared interception logic for the sync and async Messages wrappers.

    The network call (messages.create) differs between sync/async, but the
    capture → rule-check → whitelist → write → pre-execution-gate logic is
    identical. That logic lives here so both wrappers stay byte-for-byte
    consistent. Subclasses implement create()/async create() only.
    """

    def __init__(
        self,
        client: Any,
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

    def _capture_tool_results(self, kwargs: dict) -> None:
        """Capture tool_result blocks from inbound messages (post-execution facts)."""
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

    def _process_response(self, response: Any) -> None:
        """Capture tool_use blocks → check rules → whitelist → write → pre-execution gate.

        The original response is never modified. If a pre-execution hook raises,
        every event is written to the log first, then the exception propagates.
        """
        block_to_raise: Optional[PreExecutionBlockedError] = None

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


class AuditedMessages(_AuditCore):
    """Wraps anthropic.resources.Messages (synchronous).

    Intercepts every create() call to capture tool_result / tool_use events,
    run danger rules, and gate execution via the pre-execution hook.
    The original request/response is never modified.
    """

    def create(self, **kwargs) -> Any:
        self._capture_tool_results(kwargs)
        response = self._client.messages.create(**kwargs)   # read-only forward
        self._process_response(response)
        return response


class AsyncAuditedMessages(_AuditCore):
    """Wraps anthropic.resources.AsyncMessages (asynchronous).

    Identical interception to AuditedMessages; only the API call is awaited.
    Audit writes remain synchronous (fast append-only I/O), preserving the
    "logger is deterministic code" principle.
    """

    async def create(self, **kwargs) -> Any:
        self._capture_tool_results(kwargs)
        response = await self._client.messages.create(**kwargs)   # read-only forward
        self._process_response(response)
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


class AsyncAuditedAnthropic:
    """Drop-in replacement for anthropic.AsyncAnthropic that adds audit logging.

    Async counterpart of AuditedAnthropic — same audit/blocking behavior, for
    codebases built on the asynchronous Anthropic client.

    Usage:
        from agentlens import AsyncAuditedAnthropic

        client = AsyncAuditedAnthropic(log_path="./audit.jsonl", block_on_critical=True)
        resp = await client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": "..."}],
        )
        # Raises PreExecutionBlockedError when Claude attempts a critical action.

    Design principles are identical to AuditedAnthropic (read-only interception,
    append-only writes, deterministic logger). Audit writes are synchronous;
    swap in an async-capable writer if the write path ever becomes a bottleneck.
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
        self._client = anthropic.AsyncAnthropic(**anthropic_kwargs)
        self._writer = writer or FileWriter(log_path)
        self._session_id = session_id or str(uuid.uuid4())
        self._on_violation = on_violation or _default_on_violation

        # on_pre_execution priority: explicit hook > block_on_critical flag > no-op
        if on_pre_execution is not None:
            self._on_pre_execution = on_pre_execution
        else:
            self._on_pre_execution = _make_pre_execution_hook(block_on_critical)

        self.messages = AsyncAuditedMessages(
            self._client,
            self._writer,
            self._session_id,
            self._on_violation,
            self._on_pre_execution,
            whitelist=whitelist,
        )
