"""Tests for the v0.8.0 feedback loop (feedback.py)."""
from agentlens.feedback import (
    analyze,
    suggest_whitelist,
    build_report,
    Suggestion,
)


def _tool_use(tool_name, violations=None, suppressed=None):
    return {
        "event_type": "tool_use",
        "tool_name": tool_name,
        "violations": violations or [],
        "suppressed_violations": suppressed or [],
    }


def _supp(rule_id, severity="high"):
    return {"rule_id": rule_id, "severity": severity, "matched_value": "x",
            "whitelist_reason": "test"}


def _act(rule_id, severity="high"):
    return {"rule_id": rule_id, "severity": severity, "description": "d",
            "matched_value": "x"}


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #

def test_analyze_counts_active_and_suppressed_per_rule():
    events = [
        _tool_use("bash", suppressed=[_supp("PATH_ENV_FILE")]),
        _tool_use("bash", suppressed=[_supp("PATH_ENV_FILE")]),
        _tool_use("read_file", violations=[_act("PATH_ENV_FILE")]),
    ]
    stats = analyze(events)
    s = stats["PATH_ENV_FILE"]
    assert s.suppressed == 2
    assert s.active == 1
    assert s.total == 3
    assert s.tools_suppressed["bash"] == 2
    assert s.tools_active["read_file"] == 1


def test_analyze_ignores_non_tool_use_events():
    events = [
        {"event_type": "tool_result", "is_error": False},
        _tool_use("bash", suppressed=[_supp("SHELL_SUDO")]),
    ]
    stats = analyze(events)
    assert set(stats) == {"SHELL_SUDO"}


def test_fp_rate():
    events = [_tool_use("bash", suppressed=[_supp("A")]) for _ in range(9)]
    events.append(_tool_use("bash", violations=[_act("A")]))
    stats = analyze(events)
    assert stats["A"].fp_rate == 0.9


# --------------------------------------------------------------------------- #
# suggest_whitelist
# --------------------------------------------------------------------------- #

def test_suggests_narrow_tool_scoped_rule_when_concentrated():
    events = [_tool_use("bash", suppressed=[_supp("PATH_ENV_FILE")]) for _ in range(5)]
    stats = analyze(events)
    sugs = suggest_whitelist(stats, min_occurrences=3, fp_threshold=0.9)
    assert len(sugs) == 1
    assert sugs[0].rule_id == "PATH_ENV_FILE"
    assert sugs[0].tool_name == "bash"
    assert 'tool_names=["bash"]' in sugs[0].to_code()


def test_no_suggestion_below_min_occurrences():
    events = [_tool_use("bash", suppressed=[_supp("X")]) for _ in range(2)]
    stats = analyze(events)
    assert suggest_whitelist(stats, min_occurrences=3) == []


def test_no_suggestion_when_fp_rate_below_threshold():
    # 5 suppressed but also 5 active -> fp_rate 0.5, below 0.9
    events = [_tool_use("bash", suppressed=[_supp("Y")]) for _ in range(5)]
    events += [_tool_use("bash", violations=[_act("Y")]) for _ in range(5)]
    stats = analyze(events)
    assert suggest_whitelist(stats, min_occurrences=3, fp_threshold=0.9) == []


def test_falls_back_to_rulewide_when_spread_across_tools():
    events = (
        [_tool_use("bash", suppressed=[_supp("Z")]) for _ in range(2)]
        + [_tool_use("read_file", suppressed=[_supp("Z")]) for _ in range(2)]
        + [_tool_use("computer", suppressed=[_supp("Z")]) for _ in range(2)]
    )
    stats = analyze(events)
    sugs = suggest_whitelist(stats, min_occurrences=3, fp_threshold=0.9)
    assert len(sugs) == 1
    # spread across 3 tools, none dominates -> rule-wide (tool_name None)
    assert sugs[0].tool_name is None
    assert 'tool_names' not in sugs[0].to_code()


def test_suggestions_sorted_by_occurrences_desc():
    events = (
        [_tool_use("bash", suppressed=[_supp("LOW")]) for _ in range(3)]
        + [_tool_use("bash", suppressed=[_supp("HIGH")]) for _ in range(8)]
    )
    stats = analyze(events)
    sugs = suggest_whitelist(stats, min_occurrences=3, fp_threshold=0.9)
    assert [s.rule_id for s in sugs] == ["HIGH", "LOW"]


def test_to_code_escapes_quotes():
    s = Suggestion(rule_id="R", tool_name=None, occurrences=3, fp_rate=1.0,
                   rationale='has "quotes" inside')
    code = s.to_code()
    assert '"quotes"' not in code
    assert "'quotes'" in code


# --------------------------------------------------------------------------- #
# build_report
# --------------------------------------------------------------------------- #

def test_build_report_totals():
    events = [
        _tool_use("bash", suppressed=[_supp("A")]),
        _tool_use("bash", suppressed=[_supp("A")]),
        _tool_use("bash", suppressed=[_supp("A")]),
        _tool_use("read_file", violations=[_act("B")]),
        {"event_type": "tool_result"},
    ]
    report = build_report(events, min_occurrences=3, fp_threshold=0.9)
    assert report.total_events == 4          # tool_use only
    assert report.total_suppressed == 3
    assert report.total_active == 1
    assert len(report.suggestions) == 1      # A qualifies, B does not
    assert report.suggestions[0].rule_id == "A"
