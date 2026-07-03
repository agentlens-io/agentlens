"""
demo_v3.py — agentlens v0.3.0 動作デモ

実際のAPIコールなしに、AuditedAnthropicが記録するであろうJSONLを
直接生成して、CLIビューアの動作を確認する。

想定シナリオ:
  コードレビューエージェントが2セッションにわたって動作する。
  sess-001: 正常なファイル操作（ls, cat, grep）
  sess-002: 危険なコマンドを含む操作（rm -rf、認証情報アクセス）

Usage:
  python examples/demo_v3.py              # audit.jsonl を生成
  python -m agentlens view audit.jsonl    # ログを確認
  python -m agentlens summary audit.jsonl # 統計サマリー
"""

import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path


def ts(base: datetime, delta_sec: int) -> str:
    return (base + timedelta(seconds=delta_sec)).isoformat() + "Z"


def write_demo_log(path: str = "./audit.jsonl") -> None:
    base1 = datetime(2026, 4, 8, 14, 31, 30)
    base2 = datetime(2026, 4, 8, 15, 12, 0)

    sess1 = "sess-a3f1b2"
    sess2 = "sess-d9e4c7"

    # tool_use_id のプレフィックスを固定してリアルに見せる
    ids = [
        "toolu_" + uuid.uuid4().hex[:12],  # 0: ls
        "toolu_" + uuid.uuid4().hex[:12],  # 1: cat requirements.txt
        "toolu_" + uuid.uuid4().hex[:12],  # 2: grep TODO
        "toolu_" + uuid.uuid4().hex[:12],  # 3: cat auth.py (sess2)
        "toolu_" + uuid.uuid4().hex[:12],  # 4: rm -rf (violation)
        "toolu_" + uuid.uuid4().hex[:12],  # 5: cat ~/.aws/credentials (violation)
    ]

    events = [
        # ── sess-001: 正常なコードレビューセッション ───────────────────────
        {
            "event_type": "tool_use",
            "tool_use_id": ids[0],
            "tool_name": "bash",
            "tool_input": {"command": "ls -la /app/src"},
            "model": "claude-opus-4-6",
            "timestamp": ts(base1, 0),
            "session_id": sess1,
            "violations": [],
        },
        {
            "event_type": "tool_result",
            "tool_use_id": ids[0],
            "result_content": "total 40\ndrwxr-xr-x  8 user group  256 Apr  8 14:31 .\n-rw-r--r--  1 user group 4821 Apr  8 14:30 app.py\n-rw-r--r--  1 user group 1203 Apr  8 14:28 requirements.txt\n-rw-r--r--  1 user group 2044 Apr  8 14:29 auth.py",
            "is_error": False,
            "timestamp": ts(base1, 1),
            "session_id": sess1,
        },
        {
            "event_type": "tool_use",
            "tool_use_id": ids[1],
            "tool_name": "read_file",
            "tool_input": {"path": "/app/src/requirements.txt"},
            "model": "claude-opus-4-6",
            "timestamp": ts(base1, 2),
            "session_id": sess1,
            "violations": [],
        },
        {
            "event_type": "tool_result",
            "tool_use_id": ids[1],
            "result_content": "anthropic>=0.40.0\nfastapi==0.110.0\nuvicorn==0.29.0\npydantic==2.7.1\n",
            "is_error": False,
            "timestamp": ts(base1, 3),
            "session_id": sess1,
        },
        {
            "event_type": "tool_use",
            "tool_use_id": ids[2],
            "tool_name": "bash",
            "tool_input": {"command": "grep -rn 'TODO\\|FIXME' /app/src"},
            "model": "claude-opus-4-6",
            "timestamp": ts(base1, 5),
            "session_id": sess1,
            "violations": [],
        },
        {
            "event_type": "tool_result",
            "tool_use_id": ids[2],
            "result_content": "app.py:42: # TODO: add rate limiting\nauth.py:18: # FIXME: token expiry not validated",
            "is_error": False,
            "timestamp": ts(base1, 6),
            "session_id": sess1,
        },

        # ── sess-002: 危険コマンドを含むセッション ─────────────────────────
        {
            "event_type": "tool_use",
            "tool_use_id": ids[3],
            "tool_name": "read_file",
            "tool_input": {"path": "/app/src/auth.py"},
            "model": "claude-opus-4-6",
            "timestamp": ts(base2, 0),
            "session_id": sess2,
            "violations": [],
        },
        {
            "event_type": "tool_result",
            "tool_use_id": ids[3],
            "result_content": "import jwt\nimport os\n\ndef verify_token(token: str):\n    secret = os.getenv('JWT_SECRET', 'fallback-secret')\n    # FIXME: token expiry not validated\n    return jwt.decode(token, secret, algorithms=['HS256'])",
            "is_error": False,
            "timestamp": ts(base2, 1),
            "session_id": sess2,
        },
        {
            "event_type": "tool_use",
            "tool_use_id": ids[4],
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /app/src/__pycache__"},
            "model": "claude-opus-4-6",
            "timestamp": ts(base2, 4),
            "session_id": sess2,
            "violations": [
                {
                    "rule_id": "SHELL_RM_RF",
                    "severity": "high",
                    "description": "rm -rf による再帰削除コマンド",
                    "matched_value": "rm -rf /app/src/__pycache__",
                }
            ],
        },
        {
            "event_type": "tool_result",
            "tool_use_id": ids[4],
            "result_content": "",
            "is_error": False,
            "timestamp": ts(base2, 5),
            "session_id": sess2,
        },
        {
            "event_type": "tool_use",
            "tool_use_id": ids[5],
            "tool_name": "read_file",
            "tool_input": {"path": "/Users/runner/.aws/credentials"},
            "model": "claude-opus-4-6",
            "timestamp": ts(base2, 8),
            "session_id": sess2,
            "violations": [
                {
                    "rule_id": "PATH_AWS_CREDENTIALS",
                    "severity": "critical",
                    "description": "AWS認証情報ファイルへのアクセス",
                    "matched_value": "/Users/runner/.aws/credentials",
                }
            ],
        },
        {
            "event_type": "tool_result",
            "tool_use_id": ids[5],
            "result_content": "",
            "is_error": True,
            "timestamp": ts(base2, 9),
            "session_id": sess2,
        },
    ]

    out = Path(path)
    with open(out, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"✓ {len(events)} イベントを {out} に書き込みました")
    print(f"  セッション: 2件 (sess-001: 正常, sess-002: 違反あり)")
    print()
    print("次のコマンドで確認できます:")
    print(f"  python -m agentlens view {out}")
    print(f"  python -m agentlens summary {out}")


if __name__ == "__main__":
    write_demo_log()
