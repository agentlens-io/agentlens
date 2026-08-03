"""Tests for Layer B — provenance (who ran the agent, under what authority)."""
import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentlens import AuditedAnthropic, AsyncAuditedAnthropic, Provenance, FileWriter
from agentlens.models import ToolUseEvent, ToolResultEvent, normalize_provenance
from agentlens.writers.base import BaseWriter


class MemoryWriter(BaseWriter):
    def __init__(self):
        self.events = []

    def write(self, event) -> None:
        self.events.append(event)


def make_tool_use_block(name="bash", input=None, id="toolu_test01"):
    block = MagicMock()
    block.type = "tool_use"
    block.id = id
    block.name = name
    block.input = input or {"command": "echo hi"}
    return block


def make_response(blocks, model="claude-opus-4-6"):
    resp = MagicMock()
    resp.content = blocks
    resp.model = model
    return resp


# ── Provenance dataclass ────────────────────────────────────────────────────

def test_provenance_defaults_generate_run_id():
    p = Provenance(agent_id="deploy-bot")
    assert p.agent_id == "deploy-bot"
    assert p.principal is None
    assert p.authority == []
    # run_id auto-generated and unique
    assert p.run_id
    assert Provenance().run_id != p.run_id


def test_provenance_as_dict_roundtrip():
    p = Provenance(agent_id="a", principal="alice@corp", authority=["repo:read"], run_id="r1")
    d = p.as_dict()
    assert d == {
        "agent_id": "a", "principal": "alice@corp", "authority": ["repo:read"],
        "run_id": "r1", "parent_run_id": None, "metadata": {},
    }


def test_from_env_parses_all_fields():
    env = {
        "AGENTLENS_AGENT_ID": "research-agent",
        "AGENTLENS_PRINCIPAL": "bob@corp",
        "AGENTLENS_AUTHORITY": "repo:read, web:fetch shell:none",
        "AGENTLENS_RUN_ID": "run-123",
        "AGENTLENS_PARENT_RUN_ID": "run-000",
    }
    p = Provenance.from_env(env)
    assert p.agent_id == "research-agent"
    assert p.principal == "bob@corp"
    assert p.authority == ["repo:read", "web:fetch", "shell:none"]  # comma+space split
    assert p.run_id == "run-123"
    assert p.parent_run_id == "run-000"


def test_from_env_empty_generates_run_id_and_blank_fields():
    p = Provenance.from_env({})
    assert p.agent_id == ""
    assert p.principal is None
    assert p.authority == []
    assert p.parent_run_id is None
    uuid.UUID(p.run_id)  # valid uuid string


# ── normalize_provenance ────────────────────────────────────────────────────

def test_normalize_accepts_dataclass_dict_none():
    assert normalize_provenance(None) == {}
    assert normalize_provenance({"agent_id": "x"}) == {"agent_id": "x"}
    p = Provenance(agent_id="y", run_id="r")
    assert normalize_provenance(p)["agent_id"] == "y"


def test_normalize_rejects_bad_type():
    with pytest.raises(TypeError):
        normalize_provenance(12345)


# ── provenance attached to events ───────────────────────────────────────────

@patch("agentlens.client.anthropic.Anthropic")
def test_tool_use_event_carries_provenance(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "ls"})
    ])

    prov = Provenance(agent_id="deploy-bot", principal="alice@corp",
                      authority=["repo:read"], run_id="run-xyz")
    client = AuditedAnthropic(writer=writer, provenance=prov)
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
                           messages=[{"role": "user", "content": "hi"}])

    assert len(writer.events) == 1
    ev = writer.events[0]
    assert isinstance(ev, ToolUseEvent)
    assert ev.provenance["agent_id"] == "deploy-bot"
    assert ev.provenance["principal"] == "alice@corp"
    assert ev.provenance["authority"] == ["repo:read"]
    assert ev.provenance["run_id"] == "run-xyz"


@patch("agentlens.client.anthropic.Anthropic")
def test_tool_result_event_carries_provenance(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([])

    client = AuditedAnthropic(writer=writer, provenance={"agent_id": "svc"})
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
        messages=[{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok", "is_error": False}
        ]}])

    assert len(writer.events) == 1
    ev = writer.events[0]
    assert isinstance(ev, ToolResultEvent)
    assert ev.provenance == {"agent_id": "svc"}


@patch("agentlens.client.anthropic.Anthropic")
def test_no_provenance_defaults_to_empty_dict(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([make_tool_use_block()])

    client = AuditedAnthropic(writer=writer)  # no provenance
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
                           messages=[{"role": "user", "content": "hi"}])

    assert writer.events[0].provenance == {}


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_tool_use_carries_provenance(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_client.messages.create = AsyncMock(
        return_value=make_response([make_tool_use_block(name="bash")])
    )
    mock_cls.return_value = mock_client

    client = AsyncAuditedAnthropic(writer=writer, provenance=Provenance(agent_id="async-bot"))
    asyncio.run(client.messages.create(model="claude-opus-4-6", max_tokens=10,
                                       messages=[{"role": "user", "content": "hi"}]))

    assert writer.events[0].provenance["agent_id"] == "async-bot"


# ── provenance is tamper-evident (hash chain) ───────────────────────────────

@patch("agentlens.client.anthropic.Anthropic")
def test_provenance_is_in_hash_chain_and_verifies(mock_cls, tmp_path):
    log = tmp_path / "audit.jsonl"
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([make_tool_use_block()])

    client = AuditedAnthropic(writer=FileWriter(str(log)),
                              provenance=Provenance(agent_id="deploy-bot", run_id="r1"))
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
                           messages=[{"role": "user", "content": "hi"}])

    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry["provenance"]["agent_id"] == "deploy-bot"
    assert entry["entry_hash"]  # chained

    # verify passes with provenance present
    from agentlens.cli import cmd_verify
    cmd_verify(log)  # should not sys.exit

    # tampering with provenance breaks the chain: the stored hash no longer
    # matches a recomputation over the (tampered) content.
    from agentlens.writers.file import _sha256, _GENESIS
    tampered = dict(entry)
    tampered["provenance"] = {"agent_id": "attacker"}
    content = {k: v for k, v in tampered.items() if k != "entry_hash"}
    expected = _sha256(_sha256(_GENESIS) + json.dumps(content, ensure_ascii=False))
    assert tampered["entry_hash"] != expected


# ── CLI formatter ───────────────────────────────────────────────────────────

def test_format_provenance():
    from agentlens.cli import _format_provenance
    out = _format_provenance({"agent_id": "deploy-bot", "principal": "alice@corp",
                              "authority": ["repo:read", "web:fetch"], "run_id": "abcdef123456"})
    assert "agent=deploy-bot" in out
    assert "principal=alice@corp" in out
    assert "auth=[repo:read,web:fetch]" in out
    assert "run=abcdef12" in out  # truncated to 8
    assert _format_provenance({}) == ""
