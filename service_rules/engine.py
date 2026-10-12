"""冲突检测 + 评估引擎。

冲突检测（发布前，RuleSet 内部）：
- F1 频次 > 合同槽位容量：outlet 的 visits_per_week 超过 weekday_slots
  可用槽位总数 → BLOCKING（合同相位装不下频次承诺）
- F2 频次承诺但无任何槽位 → BLOCKING（fail-closed）
- F3 频次 < 合同最低相位 → BLOCKING 提示（欠服务，REVIEW 级）
- F4 时间窗与槽位并存但窗口为空串 → 阻止（配置不完整）

评估（发布后，逐店逐日）：
- 输出 GeoGov 同型 RuleEvaluation + 聚合 GateDecision
- 不变量：缺合同相位输入=BLOCK（不猜测）；任一 C1 hard gate 失败=BLOCK
  覆盖 ALLOW；BLOCK 永不发布
"""
from __future__ import annotations

from dataclasses import dataclass

from service_rules.models import (
    AdmissionAction,
    ConflictFinding,
    GovernanceDisposition,
    Rule,
    RuleEvaluation,
    RuleSetVersion,
    RuleType,
    Severity,
)


# ---- 发布前冲突检测 ----

def detect_conflicts(rs: RuleSetVersion) -> list[ConflictFinding]:
    findings: list[ConflictFinding] = []
    freq = [r for r in rs.rules if r.type is RuleType.VISIT_FREQUENCY]
    cadence = {r.outlet_id: r for r in rs.rules if r.type is RuleType.CADENCE_SLOTS}

    for f in freq:
        cap_rule = cadence.get(f.outlet_id) or cadence.get("*")
        if cap_rule is None:
            findings.append(ConflictFinding(
                "F2", f"{f.outlet_id} 有频次承诺但无合同相位槽位", [f.rule_id],
                Severity.C1, blocking=True))
            continue
        capacity = sum(len(v) for v in cap_rule.weekday_slots.values())
        if f.visits_per_week > capacity:
            findings.append(ConflictFinding(
                "F1", f"{f.outlet_id} 频次 {f.visits_per_week}/周 > 合同槽位容量 {capacity}/周",
                [f.rule_id, cap_rule.rule_id], Severity.C1, blocking=True))
        elif f.visits_per_week < capacity // 2 and capacity > 0:
            findings.append(ConflictFinding(
                "F3", f"{f.outlet_id} 频次 {f.visits_per_week}/周 显著低于合同相位 {capacity}/周",
                [f.rule_id, cap_rule.rule_id], Severity.C2, blocking=False))

    for w in [r for r in rs.rules if r.type is RuleType.TIME_WINDOW]:
        if not (w.window_start and w.window_end):
            findings.append(ConflictFinding(
                "F4", f"{w.rule_id} 时间窗配置不完整", [w.rule_id],
                Severity.C2, blocking=True))
    return findings


# ---- 运行时评估 ----

def evaluate_outlet_day(
    rs: RuleSetVersion,
    outlet_id: str,
    weekday: int,                # 1-7
    slot_index: int,             # 当日候选槽位
    visit_time: str,             # "HH:MM"
) -> list[RuleEvaluation]:
    """对某店某日某槽位评估全部适用规则；fail-closed。"""
    evals: list[RuleEvaluation] = []
    for r in rs.rules:
        if r.outlet_id not in ("*", outlet_id):
            continue
        if r.type is RuleType.CADENCE_SLOTS:
            slots = r.weekday_slots.get(weekday)
            if slots is None:
                evals.append(RuleEvaluation(
                    r.rule_id, AdmissionAction.BLOCK, r.severity, r.hard_gate,
                    f"weekday={weekday} 无合同相位记录 → fail-closed",
                    GovernanceDisposition.QUARANTINE,
                    evidence=["missing_cadence_input"]))
            elif slot_index not in slots:
                evals.append(RuleEvaluation(
                    r.rule_id, AdmissionAction.BLOCK, r.severity, r.hard_gate,
                    f"slot {slot_index} ∉ 合同槽位 {sorted(slots)}",
                    GovernanceDisposition.QUARANTINE))
            else:
                evals.append(RuleEvaluation(
                    r.rule_id, AdmissionAction.ALLOW, r.severity, r.hard_gate,
                    f"slot {slot_index} ∈ 合同槽位"))
        elif r.type is RuleType.TIME_WINDOW and visit_time:
            if not (r.window_start and r.window_end):
                evals.append(RuleEvaluation(
                    r.rule_id, AdmissionAction.REVIEW, r.severity, r.hard_gate,
                    "时间窗配置不完整", GovernanceDisposition.REPAIR_REQUIRED))
            elif r.window_start <= visit_time <= r.window_end:
                evals.append(RuleEvaluation(
                    r.rule_id, AdmissionAction.ALLOW, r.severity, r.hard_gate,
                    f"{visit_time} ∈ 窗口 [{r.window_start},{r.window_end}]"))
            else:
                evals.append(RuleEvaluation(
                    r.rule_id, AdmissionAction.ALLOW_WITH_LIMITS, r.severity, r.hard_gate,
                    f"{visit_time} ∉ 窗口 [{r.window_start},{r.window_end}]"))
        # VISIT_FREQUENCY 在日级不评（周级聚合由调用方统计后另行评估）
    return evals


@dataclass
class GateDecision:
    """聚合裁决（GeoGov GateDecision 同型精简）。"""

    action: AdmissionAction
    hard_gates_all_pass: bool
    evaluations: list[RuleEvaluation]
    rationale: str

    @property
    def publishable(self) -> bool:
        return self.action in (AdmissionAction.ALLOW, AdmissionAction.ALLOW_WITH_LIMITS)


def aggregate(evals: list[RuleEvaluation]) -> GateDecision:
    c1_fail = [e for e in evals if e.hard_gate and e.severity is Severity.C1
               and e.verdict is AdmissionAction.BLOCK]
    any_block = [e for e in evals if e.verdict is AdmissionAction.BLOCK]
    all_pass = not any_block
    if c1_fail:
        return GateDecision(AdmissionAction.BLOCK, False, evals,
                            f"C1 hard gate 失败 {len(c1_fail)} 项 → BLOCK（覆盖任何 ALLOW）")
    if any_block:
        return GateDecision(AdmissionAction.BLOCK, all_pass, evals,
                            f"存在 BLOCK {len(any_block)} 项（非 C1）")
    if any(e.verdict is AdmissionAction.REVIEW for e in evals):
        return GateDecision(AdmissionAction.REVIEW, True, evals, "存在 REVIEW 项")
    if any(e.verdict is AdmissionAction.ALLOW_WITH_LIMITS for e in evals):
        return GateDecision(AdmissionAction.ALLOW_WITH_LIMITS, True, evals, "带限制放行")
    return GateDecision(AdmissionAction.ALLOW, True, evals, "全部放行")


def evaluate_week(
    rs: RuleSetVersion,
    outlet_id: str,
    visits: list[tuple[int, int]],   # 本周实际拜访 (weekday 1-7, slot)
) -> list[RuleEvaluation]:
    """周级频次聚合评估（挂账⑤补齐，2026-10-12）。

    - 频次承诺：outlet 专属规则覆盖默认（"*"）规则
    - 实访不足 → ALLOW_WITH_LIMITS（欠服务，C2 非硬门）
    - 实访落在合同槽位外 → BLOCK（C1 硬门，相位违规）
    - 有拜访但无合同相位记录 → REVIEW + REPAIR_REQUIRED（fail-closed 不猜测）
    """
    evals: list[RuleEvaluation] = []

    freq_rules = [r for r in rs.rules if r.type is RuleType.VISIT_FREQUENCY
                  and r.outlet_id in ("*", outlet_id)]
    specific = [r for r in freq_rules if r.outlet_id == outlet_id]
    chosen = specific or [r for r in freq_rules if r.outlet_id == "*"]
    for f in chosen:
        n = len(visits)
        if n >= f.visits_per_week:
            evals.append(RuleEvaluation(
                f.rule_id, AdmissionAction.ALLOW, f.severity, f.hard_gate,
                f"周实访 {n} ≥ 承诺 {f.visits_per_week}"))
        else:
            evals.append(RuleEvaluation(
                f.rule_id, AdmissionAction.ALLOW_WITH_LIMITS, f.severity, f.hard_gate,
                f"欠服务：周实访 {n} < 承诺 {f.visits_per_week}",
                GovernanceDisposition.NONE, evidence=[f"shortfall={f.visits_per_week - n}"]))

    cadence = [r for r in rs.rules if r.type is RuleType.CADENCE_SLOTS
               and r.outlet_id in (outlet_id, "*")]
    cad = (specific := [r for r in cadence if r.outlet_id == outlet_id]) or cadence
    if visits and not cad:
        evals.append(RuleEvaluation(
            "WEEK-CADENCE-MISSING", AdmissionAction.REVIEW, Severity.C2, False,
            "有实访但无合同相位记录 → fail-closed 不猜测",
            GovernanceDisposition.REPAIR_REQUIRED))
    elif visits and cad:
        c = cad[0]
        violations = [
            (w, s) for (w, s) in visits
            if w not in c.weekday_slots or s not in c.weekday_slots[w]
        ]
        if violations:
            evals.append(RuleEvaluation(
                c.rule_id, AdmissionAction.BLOCK, Severity.C1, True,
                f"相位违规：{violations} 不在合同槽位",
                GovernanceDisposition.QUARANTINE,
                evidence=[f"weekday={w},slot={s}" for w, s in violations]))
        else:
            evals.append(RuleEvaluation(
                c.rule_id, AdmissionAction.ALLOW, Severity.C1, True,
                f"全部 {len(visits)} 次实访均在合同槽位"))
    return evals
