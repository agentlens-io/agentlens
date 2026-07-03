# agentlens

Tamper-evident audit logging for Claude agents — **Claude Code hooks** and Anthropic SDK. Local-first, append-only, OSS.

## Why

Anthropic logs API calls for their own safety monitoring — but that log is not yours.
When your Claude-powered agent takes an action, you need your own tamper-evident record:
for compliance (EU AI Act Art. 12, ISO/IEC 42001 A.6.2.8), incident response, and accountability.

**agentlens** captures every `tool_use` / `tool_result` event into a SHA-256 hash-chained JSONL file on your own machine — via **Claude Code hooks** (recommended) or as a drop-in Anthropic SDK wrapper. It can also **block dangerous tool calls before they execute** (deterministic rules, no LLM in the loop).

## Quickstart: Claude Code / Claude Agent SDK (v0.6.0+)

```bash
pip install agentlens-io
agentlens hook install   # prints the settings.json snippet
```

`.claude/settings.json`:

```json
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
```

Now every tool call in Claude Code is audit-logged, and `rm -rf /`-class commands are denied before execution:

```bash
agentlens view   ~/.agentlens/audit.jsonl        # colorized event viewer
agentlens summary ~/.agentlens/audit.jsonl       # per-session stats
agentlens verify ~/.agentlens/audit.jsonl        # ✅ hash-chain integrity / ❌ tamper detected
```

Options: `--block critical|high|off` (default `critical`), `--whitelist rules.json` (false-positive suppression — suppressed violations stay in the log), `--standalone` (post-hook logs tool_use+result when no pre-hook is registered). Hooks are **fail-open**: the logger can never break your agent loop.

## Design principles

- **Read-only interception** — requests and responses are never altered
- **Append-only writes** — log entries cannot be edited after creation
- **No AI in the logger** — capture logic is deterministic code, not an LLM
- **Your data stays local** — FileWriter (default) writes to your own machine; no data leaves your environment

## Usage: SDK wrapper

```python
from agentlens import AuditedAnthropic

# Drop-in replacement for anthropic.Anthropic()
client = AuditedAnthropic(log_path="./audit.jsonl")

response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    tools=[...],
    messages=[{"role": "user", "content": "..."}],
)
# Every tool_use and tool_result is now in audit.jsonl
```

## Log format (JSONL)

```json
{"event_type": "tool_use", "tool_use_id": "toolu_01xxx", "tool_name": "bash", "tool_input": {"command": "ls -la"}, "model": "claude-opus-4-6", "timestamp": "2026-04-05T10:00:00+00:00", "session_id": "..."}
{"event_type": "tool_result", "tool_use_id": "toolu_01xxx", "result_content": "file1.txt\nfile2.txt", "is_error": false, "timestamp": "2026-04-05T10:00:01+00:00", "session_id": "..."}
```

## Custom writer

```python
from agentlens.writers import BaseWriter

class MyWriter(BaseWriter):
    def write(self, event) -> None:
        # send to your own DB, S3, SIEM, etc.
        my_db.insert(event.to_json())

client = AuditedAnthropic(writer=MyWriter())
```

## Run tests

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

MIT
