"""Tests for Layer B, step 2 — authority enforcement (record → enforce)."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentlens import AuditedAnthropic, AsyncAuditedAnthropic, AuthorityPolicy, Provenance
from agentlens.authority import AUTHORITY_RULE_ID
from agentlens.models import ToolUseEvent, PreExecutionBlockedError
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


def _event(tool_name, authority):
    return ToolUseEvent(tool_name=tool_name, provenance={"authority": authority})


# ── AuthorityPolicy.check (unit) ────────────────────────────────────────────

def test_allowed_when_granted_covers_required():
    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    assert policy.check(_event("bash", ["shell:exec"])) == []


def test_blocked_when_scope_missing():
    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    vios = policy.check(_event("bash", ["repo:read"]))
    assert len(vios) == 1
    v = vios[0]
    assert v.rule_id == AUTHORITY_RULE_ID
    assert v.severity == "critical"
    assert "shell:exec" in v.matched_value


def test_and_semantics_requires_all_scopes():
    policy = AuthorityPolicy(requirements={"deploy": ["repo:write", "prod:deploy"]})
    # only one of two granted → still blocked, missing lists the absent one
    vios = policy.check(_event("deploy", ["repo:write"]))
    assert vios and vios[0].matched_value == "prod:deploy"
    # both granted → allowed
    assert policy.check(_event("deploy", ["repo:write", "prod:deploy"])) == []


def test_unmapped_tool_allowed_by_default():
    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    assert policy.check(_event("read_file", [])) == []


def test_default_required_denies_unmapped_tool():
    # deny-by-default: everything needs the "*" scope unless overridden
    policy = AuthorityPolicy(requirements={"read_file": []}, default_required=["*"])
    # read_file explicitly unrestricted (empty list) → allowed
    assert policy.check(_event("read_file", [])) == []
    # unmapped tool needs "*" which is not granted → blocked
    assert policy.check(_event("bash", ["repo:read"]))


def test_wildcard_grant_allows_everything():
    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]}, default_required=["prod:deploy"])
    assert policy.check(_event("bash", ["*"])) == []
    assert policy.check(_event("anything", ["*"])) == []


def test_empty_authority_blocks_restricted_tool():
    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    vios = policy.check(ToolUseEvent(tool_name="bash", provenance={}))
    assert vios and "shell:exec" in vios[0].matched_value


# ── enforcement through AuditedAnthropic (integration) ──────────────────────

@patch("agentlens.client.anthropic.Anthropic")
def test_out_of_scope_tool_is_blocked(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "ls"})
    ])

    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    client = AuditedAnthropic(
        writer=writer,
        block_on_critical=True,
        provenance=Provenance(agent_id="deploy-bot", authority=["repo:read"]),
        authority_policy=policy,
    )

    with pytest.raises(PreExecutionBlockedError) as exc:
        client.messages.create(model="claude-opus-4-6", max_tokens=10,
                               messages=[{"role": "user", "content": "hi"}])

    # event still written (forensic completeness) with the authority violation
    assert len(writer.events) == 1
    ev = writer.events[0]
    assert any(v["rule_id"] == AUTHORITY_RULE_ID for v in ev.violations)
    assert any(v.rule_id == AUTHORITY_RULE_ID for v in exc.value.violations)


@patch("agentlens.client.anthropic.Anthropic")
def test_in_scope_tool_passes(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "ls"})
    ])

    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    client = AuditedAnthropic(
        writer=writer,
        block_on_critical=True,
        provenance=Provenance(agent_id="ci", authority=["shell:exec"]),
        authority_policy=policy,
    )

    # no raise; event recorded without authority violation
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
                           messages=[{"role": "user", "content": "hi"}])
    ev = writer.events[0]
    assert not any(v["rule_id"] == AUTHORITY_RULE_ID for v in ev.violations)


@patch("agentlens.client.anthropic.Anthropic")
def test_records_violation_without_blocking_when_gate_off(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "ls"})
    ])

    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    client = AuditedAnthropic(  # block_on_critical defaults to False
        writer=writer,
        provenance=Provenance(agent_id="x", authority=[]),
        authority_policy=policy,
    )
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
                           messages=[{"role": "user", "content": "hi"}])
    ev = writer.events[0]
    assert any(v["rule_id"] == AUTHORITY_RULE_ID for v in ev.violations)


@patch("agentlens.client.anthropic.Anthropic")
def test_no_policy_is_backward_compatible(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_cls.return_value = mock_client
    mock_client.messages.create.return_value = make_response([
        make_tool_use_block(name="bash", input={"command": "ls"})
    ])

    client = AuditedAnthropic(  # no authority_policy
        writer=writer, block_on_critical=True,
        provenance=Provenance(agent_id="x", authority=[]),
    )
    client.messages.create(model="claude-opus-4-6", max_tokens=10,
                           messages=[{"role": "user", "content": "hi"}])
    ev = writer.events[0]
    assert not any(v["rule_id"] == AUTHORITY_RULE_ID for v in ev.violations)


@patch("agentlens.client.anthropic.AsyncAnthropic")
def test_async_out_of_scope_tool_is_blocked(mock_cls):
    writer = MemoryWriter()
    mock_client = MagicMock()
    mock_client.messages.create = AsyncMock(
        return_value=make_response([make_tool_use_block(name="bash")])
    )
    mock_cls.return_value = mock_client

    policy = AuthorityPolicy(requirements={"bash": ["shell:exec"]})
    client = AsyncAuditedAnthropic(
        writer=writer, block_on_critical=True,
        provenance=Provenance(agent_id="async-bot", authority=["repo:read"]),
        authority_policy=policy,
    )
    with pytest.raises(PreExecutionBlockedError):
        asyncio.run(client.messages.create(model="claude-opus-4-6", max_tokens=10,
                                           messages=[{"role": "user", "content": "hi"}]))
    assert any(v["rule_id"] == AUTHORITY_RULE_ID for v in writer.events[0].violations)
