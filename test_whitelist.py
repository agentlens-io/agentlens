"""Tests for Whitelist / WhitelistRule."""
import pytest
from agentlens.whitelist import Whitelist, WhitelistRule
from agentlens.rules import Violation
from agentlens.models import ToolUseEvent


def _event(tool_name: str, tool_input: dict) -> ToolUseEvent:
    return ToolUseEvent(tool_name=tool_name, tool_input=tool_input)


def _violation(rule_id: str, severity: str = "critical") -> Violation:
    return Violation(rule_id=rule_id, severity=severity,
                     description="test", matched_value="x")


# ── WhitelistRule.matches ─────────────────────────────────────────────────

class TestWhitelistRuleMatches:
    def test_empty_rule_matches_anything(self):
        rule = WhitelistRule()
        assert rule.matches(_event("bash", {}), _violation("SHELL_SUDO"))

    def test_rule_id_filter(self):
        rule = WhitelistRule(rule_ids=["PATH_ENV_FILE"])
        assert rule.matches(_event("read", {}), _violation("PATH_ENV_FILE"))
        assert not rule.matches(_event("read", {}), _violation("SHELL_SUDO"))

    def test_tool_name_filter(self):
        rule = WhitelistRule(rule_ids=["SHELL_SUDO"], tool_names=["bash"])
        assert rule.matches(_event("bash", {}), _violation("SHELL_SUDO"))
        assert not rule.matches(_event("python", {}), _violation("SHELL_SUDO"))

    def test_tool_name_case_insensitive(self):
        rule = WhitelistRule(tool_names=["Bash"])
        assert rule.matches(_event("bash", {}), _violation("ANY"))

    def test_input_contains_filter(self):
        rule = WhitelistRule(
            rule_ids=["SHELL_SUDO"],
            input_contains=["# example"],
        )
        event_match = _event("bash", {"command": "sudo apt-get install # example"})
        event_no_match = _event("bash", {"command": "sudo rm -rf /"})
        assert rule.matches(event_match, _violation("SHELL_SUDO"))
        assert not rule.matches(event_no_match, _violation("SHELL_SUDO"))

    def test_all_conditions_must_hold(self):
        rule = WhitelistRule(
            rule_ids=["SHELL_SUDO"],
            tool_names=["bash"],
            input_contains=["# example"],
        )
        # wrong tool_name
        assert not rule.matches(_event("python", {"command": "sudo # example"}), _violation("SHELL_SUDO"))
        # wrong rule_id
        assert not rule.matches(_event("bash", {"command": "sudo # example"}), _violation("PATH_PASSWD"))
        # missing input_contains
        assert not rule.matches(_event("bash", {"command": "sudo rm -rf /"}), _violation("SHELL_SUDO"))
        # all match
        assert rule.matches(_event("bash", {"command": "sudo # example"}), _violation("SHELL_SUDO"))


# ── Whitelist.filter ──────────────────────────────────────────────────────

class TestWhitelistFilter:
    def test_no_rules_returns_all_active(self):
        wl = Whitelist()
        v = _violation("SHELL_SUDO")
        active, suppressed = wl.filter(_event("bash", {}), [v])
        assert active == [v]
        assert suppressed == []

    def test_matching_rule_suppresses_violation(self):
        wl = Whitelist([WhitelistRule(rule_ids=["PATH_ENV_FILE"], reason="dev")])
        v = _violation("PATH_ENV_FILE", "high")
        active, suppressed = wl.filter(_event("read", {}), [v])
        assert active == []
        assert len(suppressed) == 1
        assert suppressed[0]["rule_id"] == "PATH_ENV_FILE"
        assert suppressed[0]["whitelist_reason"] == "dev"

    def test_non_matching_violation_stays_active(self):
        wl = Whitelist([WhitelistRule(rule_ids=["PATH_ENV_FILE"])])
        v_active = _violation("SHELL_SUDO")
        v_suppressed = _violation("PATH_ENV_FILE")
        active, suppressed = wl.filter(_event("bash", {}), [v_active, v_suppressed])
        assert active == [v_active]
        assert len(suppressed) == 1

    def test_empty_violations_list(self):
        wl = Whitelist([WhitelistRule(rule_ids=["PATH_ENV_FILE"])])
        active, suppressed = wl.filter(_event("bash", {}), [])
        assert active == []
        assert suppressed == []

    def test_suppressed_contains_severity_and_matched_value(self):
        wl = Whitelist([WhitelistRule(rule_ids=["SHELL_SUDO"], reason="ok")])
        v = Violation("SHELL_SUDO", "high", "desc", "matched!")
        _, suppressed = wl.filter(_event("bash", {}), [v])
        assert suppressed[0]["severity"] == "high"
        assert suppressed[0]["matched_value"] == "matched!"
