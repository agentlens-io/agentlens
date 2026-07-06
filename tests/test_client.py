"""Unit tests — no real API calls needed."""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agentlens import AuditedAnthropic, AsyncAuditedAnthropic, PreExecutionBlockedError
from agentlens.writers.base import BaseWriter
from agentlens.models import ToolUseEvent, ToolResultEvent


class MemoryWriter(BaseWriter):
    """Captures events in memory for assertions."""
    def __init__(self):
        self.events = []

    def write(self, event) -> None:
        self.events.append(event)


def make_tool_use_block(name="bash", input=None, id="toolu_test01"):
    block = MagicMock()
    block.type = "tool_use"
    block.id = id
    block.name = name
    block.input = input or {"command": "echo hello"}
    return block


def make_response(blocks, model="claude-opus-4-6"):
    resp = MagicMock()
    resp.content = blocks
    resp.model = model
    return resp


@patch("agentlens.client.anthropic.Anthropic")
def test_tool_use_is_logged(mock_anthropic_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "ls -la"})
    ])

    client = AuditedAnthropic(writer=writer, session_id="test-session")
    client.messages.create(
        model="claude-opus-4-6",
        max_tokens=100,
        messages=[{"role": "user", "content": "List files"}],
    )

    assert len(writer.events) == 1
    event = writer.events[0]
    assert isinstance(event, ToolUseEvent)
    assert event.tool_name == "bash"
    assert event.tool_input == {"command": "ls -la"}
    assert event.session_id == "test-session"


@patch("agentlens.client.anthropic.Anthropic")
def test_tool_result_is_logged(mock_anthropic_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([])

    client = AuditedAnthropic(writer=writer, session_id="test-session")
    client.messages.create(
        model="claude-opus-4-6",
        max_tokens=100,
        messages=[
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_xyz", "content": "file1.txt", "is_error": False}
            ]}
        ],
    )

    assert len(writer.events) == 1
    event = writer.events[0]
    assert isinstance(event, ToolResultEvent)
    assert event.tool_use_id == "toolu_xyz"
    assert event.is_error is False


@patch("agentlens.client.anthropic.Anthropic")
def test_response_is_not_modified(mock_anthropic_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    original_response = make_response([make_tool_use_block()])
    mock_client.messages.create.return_value = original_response

    client = AuditedAnthropic(writer=writer)
    result = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=100,
        messages=[{"role": "user", "content": "hi"}],
    )

    assert result is original_response


# ── Pre-execution hook tests ───────────────────────────────────────────────

@patch("agentlens.client.anthropic.Anthropic")
def test_block_on_critical_raises(mock_anthropic_cls):
    """block_on_critical=True raises PreExecutionBlockedError for rm -rf /"""
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "rm -rf /"})
    ])

    client = AuditedAnthropic(writer=writer, block_on_critical=True)

    with pytest.raises(PreExecutionBlockedError) as exc_info:
        client.messages.create(
            model="claude-opus-4-6",
            max_tokens=100,
            messages=[{"role": "user", "content": "clean up"}],
        )

    assert "bash" in str(exc_info.value)
    # Audit log must still be written even when blocked
    assert len(writer.events) == 1
    assert writer.events[0].tool_name == "bash"
    assert len(writer.events[0].violations) > 0


@patch("agentlens.client.anthropic.Anthropic")
def test_block_on_critical_false_does_not_raise(mock_anthropic_cls):
    """block_on_critical=False (default) logs violation but does NOT raise."""
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    original_response = make_response([
        make_tool_use_block(name="bash", input={"command": "rm -rf /"})
    ])
    mock_client.messages.create.return_value = original_response

    client = AuditedAnthropic(writer=writer, block_on_critical=False)
    result = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=100,
        messages=[{"role": "user", "content": "clean up"}],
    )

    assert result is original_response
    assert len(writer.events) == 1
    assert len(writer.events[0].violations) > 0


@patch("agentlens.client.anthropic.Anthropic")
def test_custom_pre_execution_hook_can_block(mock_anthropic_cls):
    """Custom on_pre_execution hook that raises PreExecutionBlockedError blocks execution."""
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "rm -rf /"})
    ])

    def strict_hook(event, violations):
        raise PreExecutionBlockedError(event, violations)

    client = AuditedAnthropic(writer=writer, on_pre_execution=strict_hook)

    with pytest.raises(PreExecutionBlockedError):
        client.messages.create(
            model="claude-opus-4-6",
            max_tokens=100,
            messages=[{"role": "user", "content": "clean up"}],
        )
    assert len(writer.events) == 1  # logged before raise


@patch("agentlens.client.anthropic.Anthropic")
def test_pre_execution_hook_safe_tool_not_blocked(mock_anthropic_cls):
    """Safe tool calls are not blocked even with block_on_critical=True."""
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    original_response = make_response([
        make_tool_use_block(name="bash", input={"command": "ls -la"})
    ])
    mock_client.messages.create.return_value = original_response

    client = AuditedAnthropic(writer=writer, block_on_critical=True)
    result = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=100,
        messages=[{"role": "user", "content": "list files"}],
    )

    assert result is original_response
    assert len(writer.events) == 1
    assert writer.events[0].violations == []


@patch("agentlens.client.anthropic.Anthropic")
def test_blocked_event_has_violation_details(mock_anthropic_cls):
    """PreExecutionBlockedError carries the event and violations."""
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_anthropic_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "rm -rf /"})
    ])

    client = AuditedAnthropic(writer=writer, block_on_critical=True)

    with pytest.raises(PreExecutionBlockedError) as exc_info:
        client.messages.create(
            model="claude-opus-4-6",
            max_tokens=100,
            messages=[{"role": "user", "content": "clean up"}],
        )

    err = exc_info.value
    assert err.event.tool_name == "bash"
    assert len(err.violations) > 0


# ── Async client tests (AsyncAuditedAnthropic) ─────────────────────────────
# asyncio.run keeps these plugin-free (no pytest-asyncio dependency).

def _make_async_client(mock_cls, response, **kwargs):
    """Wire an AsyncAuditedAnthropic whose underlying AsyncAnthropic.messages.create
    returns `response` as an awaitable."""
    mock_client = MagicMock()
    mock_client.messages.create = AsyncMock(return_value=response)
    mock_cls.return_value = mock_client
    return AsyncAuditedAnthropic(**kwargs)


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_tool_use_is_logged(mock_async_cls):
    writer = MemoryWriter()
    client = _make_async_client(
        mock_async_cls,
        make_response([make_tool_use_block(name="bash", input={"command": "ls -la"})]),
        writer=writer, session_id="test-async",
    )

    asyncio.run(client.messages.create(
        model="claude-opus-4-6", max_tokens=100,
        messages=[{"role": "user", "content": "List files"}],
    ))

    assert len(writer.events) == 1
    event = writer.events[0]
    assert isinstance(event, ToolUseEvent)
    assert event.tool_name == "bash"
    assert event.tool_input == {"command": "ls -la"}
    assert event.session_id == "test-async"


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_tool_result_is_logged(mock_async_cls):
    writer = MemoryWriter()
    client = _make_async_client(
        mock_async_cls, make_response([]), writer=writer, session_id="test-async",
    )

    asyncio.run(client.messages.create(
        model="claude-opus-4-6", max_tokens=100,
        messages=[{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_xyz", "content": "file1.txt", "is_error": False}
        ]}],
    ))

    assert len(writer.events) == 1
    assert isinstance(writer.events[0], ToolResultEvent)
    assert writer.events[0].tool_use_id == "toolu_xyz"


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_response_is_not_modified(mock_async_cls):
    writer = MemoryWriter()
    original = make_response([make_tool_use_block()])
    client = _make_async_client(mock_async_cls, original, writer=writer)

    result = asyncio.run(client.messages.create(
        model="claude-opus-4-6", max_tokens=100,
        messages=[{"role": "user", "content": "hi"}],
    ))

    assert result is original


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_block_on_critical_raises(mock_async_cls):
    writer = MemoryWriter()
    client = _make_async_client(
        mock_async_cls,
        make_response([make_tool_use_block(name="bash", input={"command": "rm -rf /"})]),
        writer=writer, block_on_critical=True,
    )

    with pytest.raises(PreExecutionBlockedError):
        asyncio.run(client.messages.create(
            model="claude-opus-4-6", max_tokens=100,
            messages=[{"role": "user", "content": "clean up"}],
        ))

    # Audit log must still be written even when blocked
    assert len(writer.events) == 1
    assert writer.events[0].tool_name == "bash"
    assert len(writer.events[0].violations) > 0


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_safe_tool_not_blocked(mock_async_cls):
    writer = MemoryWriter()
    original = make_response([make_tool_use_block(name="bash", input={"command": "ls -la"})])
    client = _make_async_client(mock_async_cls, original, writer=writer, block_on_critical=True)

    result = asyncio.run(client.messages.create(
        model="claude-opus-4-6", max_tokens=100,
        messages=[{"role": "user", "content": "list files"}],
    ))

    assert result is original
    assert len(writer.events) == 1
    assert writer.events[0].violations == []
