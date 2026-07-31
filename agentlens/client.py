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


class AuditedMessageStream:
    """Read-only wrapper around a live anthropic MessageStream.

    Text/event iteration is forwarded untouched — the byte stream the caller
    sees is identical to the unwrapped SDK. The audit + pre-execution gate run
    exactly once, when the *complete* message is available (get_final_message),
    or when the `with` block ends if the caller only consumed text. Because
    tool execution happens in the caller's code *after* it reads tool_use from
    the finished message, gating here is still "before execution".
    """

    def __init__(self, stream: Any, core: "_AuditCore"):
        self._stream = stream
        self._core = core
        self._processed = False

    # ── read-only passthrough of the live stream ──────────────────────────
    def __iter__(self):
        return self._stream.__iter__()

    def __next__(self):
        return self._stream.__next__()

    @property
    def text_stream(self):
        return self._stream.text_stream

    def get_final_text(self):
        return self._stream.get_final_text()

    def until_done(self):
        self._stream.until_done()

    def close(self):
        self._stream.close()

    def __getattr__(self, name):
        # Anything we don't override (response, request_id, current_message_snapshot, …)
        return getattr(self._stream, name)

    # ── audit + gate (runs once) ──────────────────────────────────────────
    def _process_once(self) -> Any:
        message = self._stream.get_final_message()
        if not self._processed:
            self._processed = True
            self._core._process_response(message)   # may raise PreExecutionBlockedError
        return message

    def get_final_message(self) -> Any:
        # Audit + gate happen here, before the caller can act on tool_use.
        return self._process_once()


class AuditedMessageStreamManager:
    """Wraps the context manager returned by messages.stream().

    On enter, yields an AuditedMessageStream. On a clean exit, ensures the
    audit + gate ran even if the caller only iterated text and never asked for
    the final message — so streaming callers cannot silently skip the log.
    """

    def __init__(self, manager: Any, core: "_AuditCore"):
        self._manager = manager
        self._core = core
        self._stream: Optional[AuditedMessageStream] = None

    def __enter__(self) -> AuditedMessageStream:
        raw = self._manager.__enter__()
        self._stream = AuditedMessageStream(raw, self._core)
        return self._stream

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None and self._stream is not None:
                self._stream._process_once()   # gate may raise; finally still closes
        finally:
            self._manager.__exit__(exc_type, exc, tb)


class AsyncAuditedMessageStream:
    """Async counterpart of AuditedMessageStream. Same guarantees, awaited."""

    def __init__(self, stream: Any, core: "_AuditCore"):
        self._stream = stream
        self._core = core
        self._processed = False

    def __aiter__(self):
        return self._stream.__aiter__()

    async def __anext__(self):
        return await self._stream.__anext__()

    @property
    def text_stream(self):
        return self._stream.text_stream

    async def get_final_text(self):
        return await self._stream.get_final_text()

    async def until_done(self):
        await self._stream.until_done()

    async def close(self):
        await self._stream.close()

    def __getattr__(self, name):
        return getattr(self._stream, name)

    async def _process_once(self) -> Any:
        message = await self._stream.get_final_message()
        if not self._processed:
            self._processed = True
            self._core._process_response(message)   # sync, deterministic
        return message

    async def get_final_message(self) -> Any:
        return await self._process_once()


class AsyncAuditedMessageStreamManager:
    """Async counterpart of AuditedMessageStreamManager."""

    def __init__(self, manager: Any, core: "_AuditCore"):
        self._manager = manager
        self._core = core
        self._stream: Optional[AsyncAuditedMessageStream] = None

    async def __aenter__(self) -> AsyncAuditedMessageStream:
        raw = await self._manager.__aenter__()
        self._stream = AsyncAuditedMessageStream(raw, self._core)
        return self._stream

    async def __aexit__(self, exc_type, exc, tb):
        try:
            if exc_type is None and self._stream is not None:
                await self._stream._process_once()
        finally:
            await self._manager.__aexit__(exc_type, exc, tb)


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

    def stream(self, **kwargs) -> AuditedMessageStreamManager:
        self._capture_tool_results(kwargs)
        manager = self._client.messages.stream(**kwargs)   # read-only forward
        return AuditedMessageStreamManager(manager, self)


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

    def stream(self, **kwargs) -> AsyncAuditedMessageStreamManager:
        self._capture_tool_results(kwargs)
        manager = self._client.messages.stream(**kwargs)   # read-only forward
        return AsyncAuditedMessageStreamManager(manager, self)


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

    Usage — streaming (audit + gate fire when the message completes):
        with client.messages.stream(
            model="claude-opus-4-6", max_tokens=1024,
            messages=[{"role": "user", "content": "..."}],
        ) as stream:
            for text in stream.text_stream:
                print(text, end="")
            message = stream.get_final_message()  # tool_use audited + gated here
        # Text passes through untouched; PreExecutionBlockedError raises before
        # the caller can act on any critical tool_use.

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
