"""
hooks.py — Claude Code / Claude Agent SDK hooks integration.

Turns Claude Code hook events (PreToolUse / PostToolUse) into
hash-chained, append-only audit log entries — and optionally blocks
dangerous tool calls before they execute.

Register in .claude/settings.json (run `agentlens hook install` to print this):

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "*", "hooks": [
            {"type": "command", "command": "agentlens hook pre --log ~/.agentlens/audit.jsonl --block critical"}
          ]}
        ],
        "PostToolUse": [
          {"matcher": "*", "hooks": [
            {"type": "command", "command": "agentlens hook post --log ~/.agentlens/audit.jsonl"}
          ]}
        ]
      }
    }

Design principles (same as the SDK wrapper):
  - Fail-open: a broken hook must NEVER break the agent loop.
    Malformed payloads exit 0 silently.
  - Deterministic: no LLM in the capture or blocking path.
  - Append-only: entries go through FileWriter's SHA-256 hash chain.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

from .models import ToolUseEvent, ToolResultEvent
from .rules import check
from .whitelist import Whitelist, WhitelistRule
from .writers.file import FileWriter

_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1}


def _fallback_tool_use_id(payload: dict) -> str:
    """Deterministic ID when the hook payload doesn't carry one."""
    raw = json.dumps(
        {
            "session_id": payload.get("session_id", ""),
            "tool_name": payload.get("tool_name", ""),
            "tool_input": payload.get("tool_input", {}),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return "hook_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_whitelist(path: Optional[str]) -> Whitelist:
    """Load whitelist rules from a JSON file.

    Format: [{"rule_ids": [...], "tool_names": [...], "input_contains": [...], "reason": "..."}]
    Missing file or parse error -> empty whitelist (fail-open, but suppressions
    simply don't apply — violations still get logged).
    """
    if not path:
        return Whitelist()
    p = Path(path).expanduser()
    if not p.exists():
        return Whitelist()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        rules = [
            WhitelistRule(
                rule_ids=list(r.get("rule_ids", [])),
                tool_names=list(r.get("tool_names", [])),
                input_contains=list(r.get("input_contains", [])),
                reason=str(r.get("reason", "")),
            )
            for r in data
            if isinstance(r, dict)
        ]
        return Whitelist(rules)
    except (json.JSONDecodeError, OSError):
        return Whitelist()


def handle_pre(
    payload: dict,
    writer: FileWriter,
    whitelist: Optional[Whitelist] = None,
    block_level: str = "critical",
) -> Optional[dict]:
    """Handle a PreToolUse payload.

    Logs the tool_use event (with violations) and returns a Claude Code
    deny-decision dict if the call should be blocked, else None.
    """
    event = ToolUseEvent(
        tool_use_id=payload.get("tool_use_id") or _fallback_tool_use_id(payload),
        tool_name=payload.get("tool_name", ""),
        tool_input=payload.get("tool_input") or {},
        model=payload.get("model", ""),
        session_id=payload.get("session_id"),
    )
    violations = check(event)
    active, suppressed = (whitelist or Whitelist()).filter(event, violations)
    event.violations = [
        {
            "rule_id": v.rule_id,
            "severity": v.severity,
            "description": v.description,
            "matched_value": v.matched_value,
        }
        for v in active
    ]
    event.suppressed_violations = suppressed
    writer.write(event)

    threshold = _SEVERITY_ORDER.get(block_level, 99)  # "off" -> never block
    blocking = [v for v in active if _SEVERITY_ORDER.get(v.severity, 0) >= threshold]
    if not blocking:
        return None

    reason = "; ".join(f"[{v.rule_id}] {v.description}" for v in blocking)
    reason = f"agentlens blocked this tool call: {reason} (logged to {writer.path})"
    return {
        # current Claude Code hook schema
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        # legacy/simple schema, harmless if ignored
        "decision": "block",
        "reason": reason,
    }


def handle_post(payload: dict, writer: FileWriter, standalone: bool = False) -> None:
    """Handle a PostToolUse payload.

    Default: logs only the tool_result (assumes `hook pre` logged the tool_use).
    standalone=True: logs both tool_use and tool_result.
    """
    tool_use_id = payload.get("tool_use_id") or _fallback_tool_use_id(payload)

    if standalone:
        use_event = ToolUseEvent(
            tool_use_id=tool_use_id,
            tool_name=payload.get("tool_name", ""),
            tool_input=payload.get("tool_input") or {},
            model=payload.get("model", ""),
            session_id=payload.get("session_id"),
        )
        use_event.violations = [
            {
                "rule_id": v.rule_id,
                "severity": v.severity,
                "description": v.description,
                "matched_value": v.matched_value,
            }
            for v in check(use_event)
        ]
        writer.write(use_event)

    response = payload.get("tool_response")
    is_error = False
    if isinstance(response, dict):
        is_error = bool(response.get("is_error") or response.get("isError") or False)
    result_event = ToolResultEvent(
        tool_use_id=tool_use_id,
        result_content=response,
        is_error=is_error,
        session_id=payload.get("session_id"),
    )
    writer.write(result_event)


SETTINGS_SNIPPET = """\
Add this to .claude/settings.json (project) or ~/.claude/settings.json (global):

{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {"type": "command", "command": "agentlens hook pre --log ~/.agentlens/audit.jsonl --block critical"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {"type": "command", "command": "agentlens hook post --log ~/.agentlens/audit.jsonl"}
        ]
      }
    ]
  }
}

Then verify integrity any time with:
  agentlens verify ~/.agentlens/audit.jsonl
"""


def main_hook(args: list) -> None:
    """Entry point for `agentlens hook <pre|post|install> [options]`.

    Fail-open by design: any unexpected error exits 0 so the agent loop
    is never interrupted by its own audit logger.
    """
    if not args or args[0] not in ("pre", "post", "install"):
        print("usage: agentlens hook <pre|post|install> [--log PATH] [--block critical|high|off] [--whitelist PATH] [--standalone]", file=sys.stderr)
        sys.exit(0)

    mode = args[0]
    if mode == "install":
        print(SETTINGS_SNIPPET)
        return

    log_path = "~/.agentlens/audit.jsonl"
    block_level = "critical"
    whitelist_path = None
    standalone = False
    i = 1
    while i < len(args):
        if args[i] == "--log" and i + 1 < len(args):
            log_path = args[i + 1]; i += 2
        elif args[i] == "--block" and i + 1 < len(args):
            block_level = args[i + 1]; i += 2
        elif args[i] == "--whitelist" and i + 1 < len(args):
            whitelist_path = args[i + 1]; i += 2
        elif args[i] == "--standalone":
            standalone = True; i += 1
        else:
            i += 1

    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            sys.exit(0)
    except (json.JSONDecodeError, OSError):
        sys.exit(0)

    try:
        writer = FileWriter(str(Path(log_path).expanduser()))
        if mode == "pre":
            decision = handle_pre(payload, writer, load_whitelist(whitelist_path), block_level)
            if decision is not None:
                print(json.dumps(decision, ensure_ascii=False))
        else:
            handle_post(payload, writer, standalone=standalone)
    except Exception:
        # fail-open: never break the agent because of the audit logger
        sys.exit(0)
