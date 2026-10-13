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


# ---- WP15 片区覆盖评估 ----

from service_rules.engine import evaluate_coverage


def _cover(outlet="*", rule_id="R-COV"):
    return Rule(rule_id, RuleType.TERRITORY_COVER, Severity.C2, False,
                outlet_id=outlet)


def test_coverage_no_primary_is_review_fail_closed():
    rs = RuleSetVersion("v1", (_cover(),))
    evals = evaluate_coverage(rs, "O1", has_primary=False)
    assert len(evals) == 1
    e = evals[0]
    assert e.verdict is AdmissionAction.REVIEW
    assert e.disposition is GovernanceDisposition.REPAIR_REQUIRED
    assert "no_primary_relation" in e.evidence


def test_coverage_missing_plan_ref_is_review():
    rs = RuleSetVersion("v1", (_cover(),))
    e = evaluate_coverage(rs, "O1", has_primary=True)[0]
    assert e.verdict is AdmissionAction.REVIEW
    assert "missing_plan_version_ref" in e.evidence


def test_coverage_primary_with_plan_ref_allows():
    rs = RuleSetVersion("v1", (_cover(),))
    e = evaluate_coverage(rs, "O1", has_primary=True,
                          plan_version_ref="2027Q1#2")[0]
    assert e.verdict is AdmissionAction.ALLOW


def test_coverage_outlet_specific_overrides_wildcard():
    rs = RuleSetVersion("v1", (_cover("*", "R-COV-DEF"), _cover("O9", "R-COV-O9")))
    ids = [e.rule_id for e in evaluate_coverage(rs, "O9", has_primary=True,
                                                plan_version_ref="B#1")]
    assert ids == ["R-COV-O9"]


def test_coverage_absent_rule_no_evaluation():
    rs = RuleSetVersion("v1", (_freq(2),))
    assert evaluate_coverage(rs, "O1", has_primary=False) == []


def test_coverage_rule_does_not_break_conflict_detection():
    """新规则类型加入后 F1-F4 语义不受影响（additive 变更自证）。"""
    rs = RuleSetVersion("v1", (_freq(4), _cadence(), _cover()))
    codes = {x.code for x in detect_conflicts(rs)}
    assert "F1" in codes and "F2" not in codes


def test_get_version_public_lookup(tmp_path):
    from service_rules.store import RuleStore

    st = RuleStore(tmp_path / "r.db")
    rs = RuleSetVersion("v7", (_freq(2), _cadence()))
    st.publish(rs, activated_by="ops")
    assert st.get_version("v7") is not None
    assert st.get_version("v7").version == "v7"
    assert st.get_version("nope") is None  # 未发布=None，不抛


# ---- ④WP28: KPI 带限规则型 ----

from service_rules.engine import evaluate_kpi


def _kpi(rule_id="R-KPI", kpi="coverage_rate", lo=0.6, hi=0.95, hard=False):
    return Rule(rule_id, RuleType.KPI_THRESHOLD, Severity.C2, hard,
                kpi=kpi, kpi_lo=lo, kpi_hi=hi)


def _krs(*rules):
    return RuleSetVersion("v-k", rules)


def test_kpi_in_band_allows():
    e = evaluate_kpi(_krs(_kpi()), "city-GZ", {"coverage_rate": 0.8})[0]
    assert e.verdict is AdmissionAction.ALLOW


def test_kpi_breach_reviews():
    e = evaluate_kpi(_krs(_kpi()), "city-GZ", {"coverage_rate": 0.5})[0]
    assert e.verdict is AdmissionAction.REVIEW
    assert "低于下限" in e.measured


def test_kpi_hard_gate_blocks():
    e = evaluate_kpi(_krs(_kpi(hard=True)), "city-GZ", {"coverage_rate": 0.99})[0]
    assert e.verdict is AdmissionAction.BLOCK
    assert "高于上限" in e.measured


def test_kpi_missing_fact_fail_closed():
    e = evaluate_kpi(_krs(_kpi()), "city-GZ", {})[0]
    assert e.verdict is AdmissionAction.REVIEW
    assert e.disposition is GovernanceDisposition.REPAIR_REQUIRED
    assert "缺失" in e.measured


def test_kpi_unbounded_side():
    e = evaluate_kpi(_krs(_kpi(lo=None, hi=100)), "s", {"coverage_rate": 0.0})[0]
    assert e.verdict is AdmissionAction.ALLOW  # lo=None 该侧无界


def test_kpi_rules_do_not_disturb_f1_f4():
    """additive 自证：KPI 规则混入不改变频次/节拍冲突检测（②TERRITORY_COVER 先例）。"""
    rs_bad = RuleSetVersion("v", (_freq(4), _cadence(), _kpi()))
    codes = {f.code for f in detect_conflicts(rs_bad)}
    assert "F1" in codes and "F2" not in codes
    rs_f2 = RuleSetVersion("v", (_freq(2), _kpi()))
    assert any(f.code == "F2" for f in detect_conflicts(rs_f2))
