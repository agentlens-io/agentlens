"""
cli.py — agentlens CLIビューア

使い方:
  python -m agentlens view audit.jsonl
  python -m agentlens view audit.jsonl --session abc123
  python -m agentlens view audit.jsonl --violations-only
  python -m agentlens summary audit.jsonl
"""

import json
import sys
from pathlib import Path
from typing import Optional

# ANSI カラー定数（rich不要・依存ゼロ）
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, *codes: str) -> str:
    if not _supports_color():
        return text
    return "".join(codes) + text + RESET


def _load_events(path: Path, session: Optional[str] = None) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                if session and ev.get("session_id") != session:
                    continue
                events.append(ev)
            except json.JSONDecodeError:
                continue
    return events


def _format_input(tool_input: dict) -> str:
    text = json.dumps(tool_input, ensure_ascii=False)
    return text[:200] + ("…" if len(text) > 200 else "")


def _format_result(result_content) -> str:
    if isinstance(result_content, list):
        texts = [b.get("text", "") for b in result_content if isinstance(b, dict)]
        text = " ".join(texts)
    else:
        text = str(result_content)
    return text[:200] + ("…" if len(text) > 200 else "")


def _severity_color(severity: str) -> str:
    return {
        "critical": RED + BOLD,
        "high":     RED,
        "medium":   YELLOW,
    }.get(severity, WHITE)


def cmd_view(path: Path, session: Optional[str], violations_only: bool) -> None:
    if not path.exists():
        print(f"[error] ファイルが見つかりません: {path}", file=sys.stderr)
        sys.exit(1)

    events = _load_events(path, session)
    if not events:
        print(_c("イベントがありません。", DIM))
        return

    # セッションごとにグループ化して表示
    current_session = None
    for ev in events:
        sid = ev.get("session_id", "unknown")
        ts  = ev.get("timestamp", "")[:19].replace("T", " ")

        # セッションヘッダー
        if sid != current_session:
            current_session = sid
            print()
            print(_c("─" * 60, DIM))
            print(_c(f"Session: {sid}  |  {ts}", BOLD + CYAN))
            print(_c("─" * 60, DIM))

        ev_type = ev.get("event_type", "")
        violations = ev.get("violations", [])

        if violations_only and not violations:
            continue

        if ev_type == "tool_use":
            tool_name  = ev.get("tool_name", "?")
            tool_input = ev.get("tool_input", {})
            print(f"\n{_c(ts, GRAY)}  {_c('TOOL USE', BOLD + GREEN)}  →  {_c(tool_name, BOLD)}")
            print(f"  {_c('input:', DIM)} {_format_input(tool_input)}")

        elif ev_type == "tool_result":
            result  = ev.get("result_content", "")
            is_err  = ev.get("is_error", False)
            tid     = ev.get("tool_use_id", "")[:8]
            label   = _c("ERROR", RED + BOLD) if is_err else _c("TOOL RESULT", BOLD + CYAN)
            print(f"\n{_c(ts, GRAY)}  {label}  ←  {_c(tid, DIM)}")
            print(f"  {_c('result:', DIM)} {_format_result(result)}")

        # violations
        for v in violations:
            rule_id   = v.get("rule_id", "?")
            severity  = v.get("severity", "medium")
            desc      = v.get("description", "")
            matched   = v.get("matched_value", "")
            sev_color = _severity_color(severity)
            print(f"  {_c(f'⚠  {severity.upper()}  {rule_id}', sev_color)}: {desc}")
            if matched:
                print(f"     {_c('matched:', DIM)} {_c(matched, YELLOW)}")

    print()


def cmd_summary(path: Path) -> None:
    if not path.exists():
        print(f"[error] ファイルが見つかりません: {path}", file=sys.stderr)
        sys.exit(1)

    events = _load_events(path)
    if not events:
        print(_c("イベントがありません。", DIM))
        return

    sessions   = {e.get("session_id") for e in events}
    tool_uses  = [e for e in events if e.get("event_type") == "tool_use"]
    results    = [e for e in events if e.get("event_type") == "tool_result"]
    errors     = [e for e in results if e.get("is_error")]
    violations = [v for e in events for v in e.get("violations", [])]

    from collections import Counter
    tool_counts = Counter(e.get("tool_name") for e in tool_uses)
    sev_counts  = Counter(v.get("severity") for v in violations)

    print()
    print(_c("═" * 50, DIM))
    print(_c("  agentlens  audit summary", BOLD + CYAN))
    print(_c("═" * 50, DIM))
    print(f"  ファイル    : {path}")
    print(f"  セッション  : {_c(str(len(sessions)), BOLD)} 件")
    print(f"  Tool Use    : {_c(str(len(tool_uses)), BOLD)} 件")
    print(f"  Tool Result : {len(results)} 件  (エラー: {_c(str(len(errors)), RED) if errors else '0'})")
    print(f"  Violations  : {_c(str(len(violations)), RED + BOLD) if violations else _c('0', GREEN)}")

    if violations:
        print()
        print(_c("  重大度別:", BOLD))
        for sev in ["critical", "high", "medium"]:
            count = sev_counts.get(sev, 0)
            if count:
                print(f"    {_c(sev.ljust(10), _severity_color(sev))} {count}")

    if tool_counts:
        print()
        print(_c("  ツール使用 TOP5:", BOLD))
        for tool, cnt in tool_counts.most_common(5):
            print(f"    {str(cnt).rjust(4)}  {tool}")

    print(_c("═" * 50, DIM))
    print()


def cmd_verify(path: Path) -> None:
    """ハッシュチェーンを検証し、改ざんを検知する。"""
    import hashlib

    _GENESIS = "agentlens_genesis_v0.4.0"

    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    if not path.exists():
        print(f"[error] ファイルが見つかりません: {path}", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append((lineno, json.loads(line)))
            except json.JSONDecodeError:
                print(_c(f"[line {lineno}] JSONパースエラー", RED))
                sys.exit(1)

    if not entries:
        print(_c("エントリがありません。", DIM))
        return

    prev_hash = sha256(_GENESIS)
    broken_at = None

    for lineno, entry in entries:
        stored_hash = entry.get("entry_hash", "")
        if not stored_hash:
            print(_c(f"[line {lineno}] entry_hash フィールドなし（v0.3以前のログ）", YELLOW))
            continue

        # ハッシュフィールドを除いた内容で再計算
        content_dict = {k: v for k, v in entry.items() if k != "entry_hash"}
        content = json.dumps(content_dict, ensure_ascii=False)
        expected = sha256(prev_hash + content)

        if stored_hash != expected:
            broken_at = lineno
            print(_c(f"❌ 改ざん検知: line {lineno}  tool={entry.get('tool_name') or entry.get('event_type', '?')}", RED + BOLD))
            print(f"   stored  : {stored_hash[:16]}…")
            print(f"   expected: {expected[:16]}…")
            break

        prev_hash = stored_hash

    if broken_at is None:
        print(_c(f"✅ チェーン整合性OK  ({len(entries)} エントリ)", GREEN + BOLD))


def cmd_feedback(
    path: Path,
    min_occurrences: int = 3,
    fp_threshold: float = 0.9,
    emit_code: bool = False,
) -> None:
    """蓄積ログを分析し、ホワイトリスト提案を出す（自動適用はしない）。"""
    from .feedback import build_report

    if not path.exists():
        print(f"[error] ファイルが見つかりません: {path}", file=sys.stderr)
        sys.exit(1)

    events = _load_events(path)
    if not events:
        print(_c("イベントがありません。", DIM))
        return

    report = build_report(events, min_occurrences, fp_threshold)

    print()
    print(_c("═" * 56, DIM))
    print(_c("  agentlens  feedback loop", BOLD + CYAN))
    print(_c("═" * 56, DIM))
    print(f"  Tool Use            : {_c(str(report.total_events), BOLD)} 件")
    print(f"  Active violations   : {_c(str(report.total_active), RED) if report.total_active else _c('0', GREEN)}")
    print(f"  Suppressed (whitelist): {_c(str(report.total_suppressed), YELLOW)}")

    if report.stats:
        print()
        print(_c("  ルール別 発火/抑制（誤検知率）:", BOLD))
        for s in sorted(report.stats.values(), key=lambda x: x.total, reverse=True):
            rate = _c(f"{s.fp_rate:.0%}", YELLOW if s.fp_rate >= fp_threshold else DIM)
            print(f"    {s.rule_id.ljust(18)} active {str(s.active).rjust(3)}  "
                  f"suppressed {str(s.suppressed).rjust(3)}  誤検知率 {rate}")

    print()
    if not report.suggestions:
        print(_c("  提案なし（閾値を満たすルールがありません）。", GREEN))
        print(_c("═" * 56, DIM))
        print()
        return

    print(_c(f"  💡 ホワイトリスト提案（{len(report.suggestions)} 件・自動適用はしません）:", BOLD + CYAN))
    print()
    for i, sg in enumerate(report.suggestions, 1):
        scope = f"tool={sg.tool_name}" if sg.tool_name else "全ツール"
        print(_c(f"  [{i}] {sg.rule_id}  ({scope}, 抑制 {sg.occurrences} 件)", BOLD))
        print(f"      {sg.rationale}")
        if emit_code:
            print(_c(f"      {sg.to_code()}", GREEN))
        print()

    if not emit_code:
        print(_c("  --emit-code で貼り付け可能な WhitelistRule を出力します。", DIM))
    print(_c("  レビューのうえ Whitelist に追加するかは人間が判断してください。", DIM))
    print(_c("═" * 56, DIM))
    print()


def main(argv: Optional[list] = None) -> None:
    args = (argv if argv is not None else sys.argv)[1:]

    def usage():
        print("使い方:")
        print("  python -m agentlens view <file.jsonl> [--session ID] [--violations-only]")
        print("  python -m agentlens summary <file.jsonl>")
        print("  python -m agentlens verify <file.jsonl>")
        print("  python -m agentlens feedback <file.jsonl> [--min-occurrences N] [--threshold F] [--emit-code]")
        print("  agentlens hook <pre|post|install> [--log PATH] [--block critical|high|off]")
        sys.exit(1)

    if not args:
        usage()

    subcmd = args[0]

    if subcmd == "view":
        if len(args) < 2:
            usage()
        path = Path(args[1])
        session = None
        violations_only = False
        i = 2
        while i < len(args):
            if args[i] == "--session" and i + 1 < len(args):
                session = args[i + 1]; i += 2
            elif args[i] == "--violations-only":
                violations_only = True; i += 1
            else:
                i += 1
        cmd_view(path, session, violations_only)

    elif subcmd == "summary":
        if len(args) < 2:
            usage()
        cmd_summary(Path(args[1]))

    elif subcmd == "verify":
        if len(args) < 2:
            usage()
        cmd_verify(Path(args[1]))

    elif subcmd == "feedback":
        if len(args) < 2:
            usage()
        path = Path(args[1])
        min_occurrences = 3
        fp_threshold = 0.9
        emit_code = False
        i = 2
        while i < len(args):
            if args[i] == "--min-occurrences" and i + 1 < len(args):
                min_occurrences = int(args[i + 1]); i += 2
            elif args[i] == "--threshold" and i + 1 < len(args):
                fp_threshold = float(args[i + 1]); i += 2
            elif args[i] == "--emit-code":
                emit_code = True; i += 1
            else:
                i += 1
        cmd_feedback(path, min_occurrences, fp_threshold, emit_code)

    elif subcmd == "hook":
        from .hooks import main_hook
        main_hook(args[1:])

    else:
        usage()
