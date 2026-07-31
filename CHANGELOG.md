# Changelog

All notable changes to `agentlens-io` are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.9.0] — streaming support

- `messages.stream()` is now wrapped on both the sync (`AuditedAnthropic`) and
  async (`AsyncAuditedAnthropic`) clients.
- Text/event iteration passes through read-only — the byte stream the caller
  sees is identical to the unwrapped SDK.
- The audit write and the pre-execution gate run exactly once, when the message
  completes (`get_final_message()`) or when the `with` block exits if the caller
  only consumed text — so streaming callers cannot silently skip the log.
- `block_on_critical` / custom `on_pre_execution` hooks fire in streaming too,
  raising `PreExecutionBlockedError` before the caller can act on tool_use.

## [0.8.0] — feedback loop

- Suggestion-only whitelist proposals: aggregate suppressed violations from the
  audit log and propose (never auto-apply) whitelist rules.

## [0.7.0] — async client

- `AsyncAuditedAnthropic`, a drop-in for `anthropic.AsyncAnthropic`, with the
  same audit logging and pre-execution blocking.

## [0.6.0] — Claude Code hooks integration

- PreToolUse blocking + PostToolUse audit outside the SDK wrapper.

## [0.5.0] — whitelist

- Whitelist-based false-positive suppression (`Whitelist`, `WhitelistRule`).

## [0.4.0] — tamper detection

- SHA-256 hash chain over log entries for tamper detection.

## [0.3.0] — pre-execution hook & CLI

- Pre-execution hook, `PreExecutionBlockedError`, `block_on_critical`.
- CLI viewer (`python -m agentlens view audit.jsonl`).
- GitHub Actions auto-publish to PyPI on tag.

## [0.2.0]

- `PostgresWriter` for Neon/PostgreSQL.
- Rule-based danger detection + GitHub Actions CI.
- Renamed package to `agentlens-io` for PyPI.

## [0.1.0]

- Initial release: `AuditedAnthropic`, `FileWriter` (append-only JSONL),
  basic tool_use / tool_result capture.
