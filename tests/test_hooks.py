"""Tests for the Claude Code hooks integration (agentlens/hooks.py)."""
import json

import pytest

from agentlens.hooks import handle_pre, handle_post, load_whitelist, _fallback_tool_use_id
from agentlens.whitelist import Whitelist, WhitelistRule
from agentlens.writers.file import FileWriter


def _read_log(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _pre_payload(command="ls -la", tool="Bash"):
    return {
        "session_id": "sess_test",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


class TestHandlePre:
    def test_benign_call_logged_and_allowed(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        decision = handle_pre(_pre_payload("ls -la"), FileWriter(str(log)))
        assert decision is None
        events = _read_log(log)
        assert len(events) == 1
        assert events[0]["event_type"] == "tool_use"
        assert events[0]["tool_name"] == "Bash"
        assert events[0]["violations"] == []
        assert events[0]["entry_hash"]

    def test_critical_violation_blocked(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        decision = handle_pre(_pre_payload("rm -rf /"), FileWriter(str(log)), block_level="critical")
        assert decision is not None
        hso = decision["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert "SHELL_RM_ROOT" in hso["permissionDecisionReason"]
        assert decision["decision"] == "block"
        # blocked call is still in the audit log
        events = _read_log(log)
        assert events[0]["violations"][0]["rule_id"] == "SHELL_RM_ROOT"

    def test_high_not_blocked_at_critical_level(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        decision = handle_pre(_pre_payload("sudo apt install jq"), FileWriter(str(log)), block_level="critical")
        assert decision is None  # logged but not blocked
        events = _read_log(log)
        assert any(v["rule_id"] == "SHELL_SUDO" for v in events[0]["violations"])

    def test_high_blocked_at_high_level(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        decision = handle_pre(_pre_payload("sudo rm x"), FileWriter(str(log)), block_level="high")
        assert decision is not None

    def test_block_off_never_blocks(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        decision = handle_pre(_pre_payload("rm -rf /"), FileWriter(str(log)), block_level="off")
        assert decision is None

    def test_whitelist_suppresses_block(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        wl = Whitelist([WhitelistRule(rule_ids=["SHELL_RM_ROOT"], reason="test suppression")])
        decision = handle_pre(_pre_payload("rm -rf /"), FileWriter(str(log)), whitelist=wl)
        assert decision is None
        events = _read_log(log)
        assert events[0]["violations"] == []
        assert events[0]["suppressed_violations"][0]["rule_id"] == "SHELL_RM_ROOT"


class TestHandlePost:
    def test_result_only_by_default(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        payload = {
            "session_id": "sess_test",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"output": "file1\nfile2"},
        }
        handle_post(payload, FileWriter(str(log)))
        events = _read_log(log)
        assert len(events) == 1
        assert events[0]["event_type"] == "tool_result"

    def test_standalone_logs_both(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        payload = {
            "session_id": "sess_test",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"output": "ok"},
        }
        handle_post(payload, FileWriter(str(log)), standalone=True)
        events = _read_log(log)
        assert [e["event_type"] for e in events] == ["tool_use", "tool_result"]
        assert events[0]["tool_use_id"] == events[1]["tool_use_id"]

    def test_is_error_detected(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        payload = {"tool_name": "Bash", "tool_input": {}, "tool_response": {"is_error": True}}
        handle_post(payload, FileWriter(str(log)))
        assert _read_log(log)[0]["is_error"] is True


class TestHashChainAcrossHooks:
    def test_chain_verifies_after_pre_and_post(self, tmp_path, capsys):
        from agentlens.cli import cmd_verify
        log = tmp_path / "audit.jsonl"
        handle_pre(_pre_payload("ls"), FileWriter(str(log)))
        handle_post(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"output": "ok"}},
            FileWriter(str(log)),
        )
        cmd_verify(log)
        assert "OK" in capsys.readouterr().out

    def test_tamper_detected_output(self, tmp_path, capsys):
        from agentlens.cli import cmd_verify
        log = tmp_path / "audit.jsonl"
        handle_pre(_pre_payload("ls"), FileWriter(str(log)))
        handle_pre(_pre_payload("pwd"), FileWriter(str(log)))
        lines = log.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["tool_input"] = {"command": "changed"}
        lines[0] = json.dumps(first, ensure_ascii=False)
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            cmd_verify(log)
        except SystemExit:
            pass
        assert "改ざん検知" in capsys.readouterr().out


class TestLoadWhitelist:
    def test_missing_file_returns_empty(self):
        wl = load_whitelist("/nonexistent/path.json")
        assert isinstance(wl, Whitelist)

    def test_loads_rules(self, tmp_path):
        p = tmp_path / "wl.json"
        p.write_text(json.dumps([{"rule_ids": ["PATH_ENV_FILE"], "reason": "dev"}]), encoding="utf-8")
        wl = load_whitelist(str(p))
        decision_input = {"tool_name": "Read", "tool_input": {"file_path": "/app/.env"}}
        # apply through handle_pre to check suppression end-to-end
        log = tmp_path / "a.jsonl"
        d = handle_pre(decision_input, FileWriter(str(log)), whitelist=wl, block_level="high")
        assert d is None
        events = _read_log(log)
        assert events[0]["suppressed_violations"][0]["rule_id"] == "PATH_ENV_FILE"


class TestFallbackId:
    def test_deterministic(self):
        p = {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}}
        assert _fallback_tool_use_id(p) == _fallback_tool_use_id(dict(p))
        assert _fallback_tool_use_id(p).startswith("hook_")
