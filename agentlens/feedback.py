"""
feedback.py — フィードバックループ：蓄積した監査ログをホワイトリスト提案に変える。

設計原則は検知（rules.py）と同じで、**決定論的・LLM不使用・そして「提案止まり」**。
このループはルールセットを自分で書き換えない。監査ログ——v0.5.0 が削除せずに残した
`suppressed_violations` を含む——を読み、人間がレビューするための、できる限り
狭いスコープの WhitelistRule を提案するだけだ。

なぜ提案止まりか：自分のログから自動でルールを書き換える系は「毒を盛れる」。
良性に見える suppression をログに大量に流し込める攻撃者は、本当に危険なパターンを
検知が無視するよう"学習"させられる。human-in-the-loop がセキュリティ境界そのものだ。

なぜ suppressed_violations が要るのか（#7 の伏線回収）：
v0.5.0 は誤検知を「消す」のではなく suppressed_violations として残す判断をした。
その判断がここで初めて価値を生む。何が抑制されたかの記録が無ければ、
「どのルールが誤検知しやすいか」をログから復元することはできない。
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# --------------------------------------------------------------------------- #
# 集計モデル
# --------------------------------------------------------------------------- #

@dataclass
class RuleStat:
    """1 つの rule_id についての発火統計。"""
    rule_id: str
    active: int = 0            # 発火し、抑制されなかった違反
    suppressed: int = 0        # ホワイトリストで抑制された違反
    tools_active: Counter = field(default_factory=Counter)      # tool_name -> active 回数
    tools_suppressed: Counter = field(default_factory=Counter)  # tool_name -> suppressed 回数

    @property
    def total(self) -> int:
        return self.active + self.suppressed

    @property
    def fp_rate(self) -> float:
        """このルールの発火のうち、人間が既にホワイトリスト化した割合（誤検知率の代理指標）。"""
        return self.suppressed / self.total if self.total else 0.0


@dataclass
class Suggestion:
    """人間がレビューするための WhitelistRule 提案。適用はしない。"""
    rule_id: str
    tool_name: Optional[str]   # 最も狭いスコープ。None は「任意のツール」
    occurrences: int           # この提案の根拠になった suppressed 回数
    fp_rate: float
    rationale: str

    def to_code(self) -> str:
        """コピペ可能な WhitelistRule のコード片を返す。"""
        tool = f', tool_names=["{self.tool_name}"]' if self.tool_name else ""
        reason = self.rationale.replace('"', "'")
        return f'WhitelistRule(rule_ids=["{self.rule_id}"]{tool}, reason="{reason}")'


@dataclass
class FeedbackReport:
    stats: Dict[str, RuleStat]
    suggestions: List[Suggestion]
    total_events: int
    total_active: int
    total_suppressed: int


# --------------------------------------------------------------------------- #
# 分析
# --------------------------------------------------------------------------- #

def analyze(events: List[dict]) -> Dict[str, RuleStat]:
    """tool_use イベント列から rule_id ごとの発火統計を組み立てる。純関数。"""
    stats: Dict[str, RuleStat] = {}

    def _stat(rule_id: str) -> RuleStat:
        if rule_id not in stats:
            stats[rule_id] = RuleStat(rule_id=rule_id)
        return stats[rule_id]

    for ev in events:
        if ev.get("event_type") != "tool_use":
            continue
        tool = (ev.get("tool_name") or "").lower() or "(unknown)"

        for v in ev.get("violations", []):
            rid = v.get("rule_id")
            if not rid:
                continue
            s = _stat(rid)
            s.active += 1
            s.tools_active[tool] += 1

        for v in ev.get("suppressed_violations", []):
            rid = v.get("rule_id")
            if not rid:
                continue
            s = _stat(rid)
            s.suppressed += 1
            s.tools_suppressed[tool] += 1

    return stats


def suggest_whitelist(
    stats: Dict[str, RuleStat],
    min_occurrences: int = 3,
    fp_threshold: float = 0.9,
) -> List[Suggestion]:
    """誤検知しやすいルールについて、狭いスコープのホワイトリスト提案を生成する。

    条件:
      - suppressed 回数が min_occurrences 以上（偶発的な 1〜2 件では提案しない）
      - fp_rate が fp_threshold 以上（active 発火がまだ多いルールは自動で緩めない）

    スコープ選択:
      抑制がある 1 つのツールに集中している場合は tool_names を付けた狭い提案を出す。
      複数ツールに散っている場合のみ rule_id 全体の提案にフォールバックする。
      —— 常に「最小の緩め幅」を優先し、セキュリティ面を最小限しか広げない。
    """
    suggestions: List[Suggestion] = []

    for s in stats.values():
        if s.suppressed < min_occurrences:
            continue
        if s.fp_rate < fp_threshold:
            continue

        tools = s.tools_suppressed.most_common()
        # 抑制が単一ツールに集中しているか？（そのツールが suppressed の大半を占める）
        if tools and tools[0][1] >= min_occurrences and (
            len(tools) == 1 or tools[0][1] >= 0.8 * s.suppressed
        ):
            tool_name, cnt = tools[0]
            rationale = (
                f"{tool_name} での {s.rule_id} は {cnt} 回すべて抑制済み"
                f"（誤検知率 {s.fp_rate:.0%}）。対象ツールに絞って明示ホワイトリスト化を推奨。"
            )
            suggestions.append(Suggestion(
                rule_id=s.rule_id,
                tool_name=tool_name if tool_name != "(unknown)" else None,
                occurrences=cnt,
                fp_rate=s.fp_rate,
                rationale=rationale,
            ))
        else:
            rationale = (
                f"{s.rule_id} は複数ツールで計 {s.suppressed} 回抑制済み"
                f"（誤検知率 {s.fp_rate:.0%}、active {s.active} 件）。ルール全体の見直しを推奨。"
            )
            suggestions.append(Suggestion(
                rule_id=s.rule_id,
                tool_name=None,
                occurrences=s.suppressed,
                fp_rate=s.fp_rate,
                rationale=rationale,
            ))

    # 根拠の強い順（抑制回数の多い順）に並べる
    suggestions.sort(key=lambda x: x.occurrences, reverse=True)
    return suggestions


def build_report(
    events: List[dict],
    min_occurrences: int = 3,
    fp_threshold: float = 0.9,
) -> FeedbackReport:
    stats = analyze(events)
    suggestions = suggest_whitelist(stats, min_occurrences, fp_threshold)
    tool_uses = [e for e in events if e.get("event_type") == "tool_use"]
    total_active = sum(s.active for s in stats.values())
    total_suppressed = sum(s.suppressed for s in stats.values())
    return FeedbackReport(
        stats=stats,
        suggestions=suggestions,
        total_events=len(tool_uses),
        total_active=total_active,
        total_suppressed=total_suppressed,
    )
