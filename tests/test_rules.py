"""WP07 测试：冲突检测 / fail-closed 评估 / C1 覆盖 / 版本回滚。"""
from __future__ import annotations

import pytest

from service_rules.engine import (
    AdmissionAction,
    GateDecision,
    GovernanceDisposition,
    aggregate,
    detect_conflicts,
    evaluate_outlet_day,
)
from service_rules.models import (
    ConflictFinding,
    Rule,
    RuleEvaluation,
    RuleSetVersion,
    RuleType,
    Severity,
)
from service_rules.store import RuleStore


def _cadence(outlet="*", slots=None, rule_id="R-CAD"):
    return Rule(rule_id, RuleType.CADENCE_SLOTS, Severity.C1, True,
                outlet_id=outlet, weekday_slots=slots or {1: [0, 1], 3: [0]})


def _freq(n, outlet="*", rule_id="R-FREQ"):
    return Rule(rule_id, RuleType.VISIT_FREQUENCY, Severity.C2, False,
                outlet_id=outlet, visits_per_week=n)


def test_f1_frequency_exceeds_cadence_capacity_blocks_publish():
    rs = RuleSetVersion("v1", (_freq(4), _cadence()))  # 容量 3 < 4
    f = detect_conflicts(rs)
    assert any(x.code == "F1" and x.blocking for x in f)


def test_f2_frequency_without_cadence_blocks_publish():
    rs = RuleSetVersion("v1", (_freq(2),))
    assert any(x.code == "F2" and x.blocking for x in detect_conflicts(rs))


def test_f3_under_service_is_non_blocking():
    rs = RuleSetVersion("v1", (_freq(1), _cadence(slots={1: [0, 1], 2: [0], 3: [0]})))  # 容量4
    f = detect_conflicts(rs)
    assert any(x.code == "F3" and not x.blocking for x in f)


def test_store_rejects_publish_with_blocking_conflict(tmp_path):
    store = RuleStore(tmp_path / "r.db")
    bad = RuleSetVersion("v1", (_freq(4), _cadence()))
    with pytest.raises(ValueError):
        store.publish(bad)
    good = RuleSetVersion("v1", (_freq(3), _cadence()))
    findings = store.publish(good, activated_by="ops01")
    assert findings == []
    assert store.active_version().version == "v1"
    store.close_db()


def test_missing_cadence_is_fail_closed_block():
    rs = RuleSetVersion("v1", (_cadence(slots={2: [0]}, rule_id="R-CAD2"),))  # 周一无记录
    evals = evaluate_outlet_day(rs, "O1", weekday=1, slot_index=0, visit_time="10:00")
    e = [x for x in evals if x.rule_id == "R-CAD2"][0]
    assert e.verdict is AdmissionAction.BLOCK
    assert e.disposition is GovernanceDisposition.QUARANTINE
    assert "fail-closed" in e.measured


def test_slot_not_in_contract_blocks():
    rs = RuleSetVersion("v1", (_cadence(),))
    evals = evaluate_outlet_day(rs, "O1", weekday=1, slot_index=9, visit_time="10:00")
    assert evals[0].verdict is AdmissionAction.BLOCK


def test_time_window_limit_and_incomplete():
    win = Rule("R-WIN", RuleType.TIME_WINDOW, Severity.C3, False,
               window_start="09:00", window_end="17:00")
    rs = RuleSetVersion("v1", (win,))
    ok = evaluate_outlet_day(rs, "O1", 1, 0, "10:00")[0]
    late = evaluate_outlet_day(rs, "O1", 1, 0, "18:30")[0]
    assert ok.verdict is AdmissionAction.ALLOW
    assert late.verdict is AdmissionAction.ALLOW_WITH_LIMITS
    bad = Rule("R-WIN2", RuleType.TIME_WINDOW, Severity.C3, False)
    e = evaluate_outlet_day(RuleSetVersion("v1", (bad,)), "O1", 1, 0, "10:00")[0]
    assert e.verdict is AdmissionAction.REVIEW
    assert e.disposition is GovernanceDisposition.REPAIR_REQUIRED


def test_c1_hard_gate_failure_overrides_allow():
    evals = [
        RuleEvaluation("a", AdmissionAction.ALLOW, Severity.C3, False, "ok"),
        RuleEvaluation("b", AdmissionAction.BLOCK, Severity.C1, True, "cadence miss"),
        RuleEvaluation("c", AdmissionAction.ALLOW, Severity.C3, False, "ok"),
    ]
    d = aggregate(evals)
    assert d.action is AdmissionAction.BLOCK and not d.hard_gates_all_pass
    assert "覆盖任何 ALLOW" in d.rationale
    assert not GateDecision.publishable.fget(d)


def test_review_never_publishable():
    evals = [RuleEvaluation("a", AdmissionAction.REVIEW, Severity.C2, False, "chk")]
    d = aggregate(evals)
    assert d.action is AdmissionAction.REVIEW and not d.publishable


def test_rollback_restores_previous_version(tmp_path):
    store = RuleStore(tmp_path / "r.db")
    store.publish(RuleSetVersion("v1", (_freq(3), _cadence())), activated_by="ops01")
    store.publish(RuleSetVersion("v2", (_freq(2), _cadence())), activated_by="ops02")
    assert store.active_version().version == "v2"
    rolled = store.rollback(activated_by="ops03")
    assert rolled.rules[0].visits_per_week == 3           # 回到 v1 内容
    assert rolled.supersedes == "v2"                      # 回滚链留痕
    assert store.active_version().version == "v1-rollback"
    store.close_db()


# ---- 周级频次评估（挂账⑤补齐）----

from service_rules.engine import evaluate_week


def _cad_rule(outlet="*", slots=None, rule_id="R-CAD"):
    return Rule(rule_id, RuleType.CADENCE_SLOTS, Severity.C1, True,
                outlet_id=outlet, weekday_slots=slots or {1: [0, 1], 3: [0]})


def test_week_meets_commitment():
    rs = RuleSetVersion("v1", (_freq(3), _cad_rule()))
    evals = evaluate_week(rs, "O1", [(1, 0), (1, 1), (3, 0)])
    assert evals[0].verdict is AdmissionAction.ALLOW
    assert evals[1].verdict is AdmissionAction.ALLOW  # 相位全合法


def test_week_under_service_is_limits_not_block():
    rs = RuleSetVersion("v1", (_freq(4), _cad_rule()))
    evals = evaluate_week(rs, "O1", [(1, 0), (3, 0)])
    freq = evals[0]
    assert freq.verdict is AdmissionAction.ALLOW_WITH_LIMITS
    assert "欠服务" in freq.measured and freq.evidence == ["shortfall=2"]


def test_week_illegal_slot_blocks_c1():
    rs = RuleSetVersion("v1", (_freq(2), _cad_rule()))
    evals = evaluate_week(rs, "O1", [(1, 0), (2, 0)])  # 周二无合同槽位
    cad = [e for e in evals if e.rule_id == "R-CAD"][0]
    assert cad.verdict is AdmissionAction.BLOCK and cad.hard_gate
    assert cad.disposition is GovernanceDisposition.QUARANTINE


def test_week_visits_without_cadence_fail_closed_review():
    rs = RuleSetVersion("v1", (_freq(2),))  # 无相位规则
    evals = evaluate_week(rs, "O1", [(1, 0), (1, 1)])
    miss = [e for e in evals if e.rule_id == "WEEK-CADENCE-MISSING"][0]
    assert miss.verdict is AdmissionAction.REVIEW
    assert miss.disposition is GovernanceDisposition.REPAIR_REQUIRED


def test_week_outlet_specific_freq_overrides_default():
    rs = RuleSetVersion("v1", (_freq(5, outlet="*"), _freq(2, outlet="O1", rule_id="R-F1"),
                               _cad_rule()))
    evals = evaluate_week(rs, "O1", [(1, 0), (3, 0)])
    ids = [e.rule_id for e in evals]
    assert ids == ["R-F1", "R-CAD"]           # 专属覆盖默认
    assert evals[0].verdict is AdmissionAction.ALLOW  # 2 ≥ 2
