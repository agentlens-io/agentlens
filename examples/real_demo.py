"""
real_demo.py — agentlens v0.3.0 実走デモ

本物のAnthropicAPIを呼び出し、実際のtool_useログを記録する。
シナリオ: コードレビューエージェントがagentlensのソースを調査する
"""

import os
import json
import subprocess
from pathlib import Path
from agentlens import AuditedAnthropic, FileWriter

LOG_PATH = "./real_audit.jsonl"

# 違反を検知したらコンソールに即通知
def on_violation(event, violations):
    for v in violations:
        print(f"\n🚨 [{v.severity.upper()}] {v.rule_id}: {v.description}")
        print(f"   matched: {v.matched_value}")

client = AuditedAnthropic(
    api_key=os.environ["ANTHROPIC_API_KEY"],
    writer=FileWriter(LOG_PATH),
    on_violation=on_violation,
)

# ── ツール定義 ──────────────────────────────────────────────
tools = [
    {
        "name": "bash",
        "description": "シェルコマンドを実行する。ファイルの一覧取得・検索・内容確認に使う。",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "実行するshellコマンド"}
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "ファイルの内容を読み取る",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "読み取るファイルのパス"}
            },
            "required": ["path"],
        },
    },
]

# ── ツール実行（ローカル） ───────────────────────────────────
def execute_tool(name: str, input: dict) -> str:
    try:
        if name == "bash":
            result = subprocess.run(
                input["command"], shell=True, capture_output=True, text=True, timeout=10
            )
            return result.stdout + result.stderr
        elif name == "read_file":
            return Path(input["path"]).read_text(encoding="utf-8")
        return "unknown tool"
    except Exception as e:
        return f"[error] {e}"

# ── エージェントループ ─────────────────────────────────────
PROJECT_ROOT = str(Path(__file__).parent.parent)

messages = [
    {
        "role": "user",
        "content": f"agentlensプロジェクト（{PROJECT_ROOT}）のソースコードを調べてください。\n"
                   "① ファイル構成を確認する\n"
                   "② agentlens/__init__.pyを読んでどんな機能をexportしているか確認する\n"
                   "③ ルールファイル（rules.py）を確認し、何種類の危険パターンを検知できるか数える\n"
                   "以上3点をまとめて報告してください。",
    }
]

print(f"🔍 agentlens実走デモ — ログ: {LOG_PATH}")
print("=" * 60)

turn = 0
while True:
    turn += 1
    print(f"\n[Turn {turn}] APIコール中...", end="", flush=True)

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2048,
        tools=tools,
        messages=messages,
    )

    print(f" stop_reason={response.stop_reason}")

    if response.stop_reason == "end_turn":
        # 最終回答
        final_text = next((b.text for b in response.content if hasattr(b, "text")), "")
        print("\n" + "=" * 60)
        print("📋 エージェントの最終回答:")
        print(final_text)
        break

    if response.stop_reason != "tool_use":
        print(f"予期しないstop_reason: {response.stop_reason}")
        break

    # tool_useブロックを処理
    messages.append({"role": "assistant", "content": response.content})
    tool_results = []

    for block in response.content:
        if block.type != "tool_use":
            continue
        print(f"  → {block.name}({json.dumps(block.input, ensure_ascii=False)[:80]})")
        result = execute_tool(block.name, block.input)
        print(f"  ← {result[:100].strip()}{'...' if len(result) > 100 else ''}")
        tool_results.append({
            "type": "tool_result",
            "tool_use_id": block.id,
            "content": result,
        })

    messages.append({"role": "user", "content": tool_results})

print("\n" + "=" * 60)
print(f"✅ 完了。ログを確認: python -m agentlens view {LOG_PATH}")
print(f"            統計確認: python -m agentlens summary {LOG_PATH}")
