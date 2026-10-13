"""规则类型：拜访频次 / 合同-相位 / 时间窗。

GeoGov 规则 DSL 同型（WP07 验收）：
- 每个 RuleEvaluation 带 rule_id / verdict / severity / hard_gate / evidence
- verdict ∈ AdmissionAction(4 态)：ALLOW / ALLOW_WITH_LIMITS / REVIEW / BLOCK
- disposition ∈ GovernanceDisposition(5 处置)：NONE / QUARANTINE /
  SUSPEND_SOURCE / REPAIR_REQUIRED / INVESTIGATION_REQUIRED
- 不变量照搬：fail-closed（缺失必评输入=BLOCK 不猜测）；任一 C1 hard gate
  失败=BLOCK 覆盖 ALLOW；BLOCK 永不发布；REVIEW 永不进生产
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# ---- GeoGov DSL 同型 ----
class AdmissionAction(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_LIMITS = "ALLOW_WITH_LIMITS"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class GovernanceDisposition(str, Enum):
    NONE = "NONE"
    QUARANTINE = "QUARANTINE"
    SUSPEND_SOURCE = "SUSPEND_SOURCE"
    REPAIR_REQUIRED = "REPAIR_REQUIRED"
    INVESTIGATION_REQUIRED = "INVESTIGATION_REQUIRED"


class Severity(str, Enum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    UNSPECIFIED = "UNSPECIFIED"


class RuleType(str, Enum):
    VISIT_FREQUENCY = "VISIT_FREQUENCY"      # 拜访频次：每店每周期次数
    CADENCE_SLOTS = "CADENCE_SLOTS"          # 合同-相位：每店每星期几合法槽位集
    TIME_WINDOW = "TIME_WINDOW"              # 时间窗：可服务 HH:MM-HH:MM
    TERRITORY_COVER = "TERRITORY_COVER"      # 片区覆盖：有主访+方案版本追溯键（WP15）
    KPI_THRESHOLD = "KPI_THRESHOLD"          # 业绩指标带限 [lo,hi]（④WP28）


@dataclass(frozen=True)
class Rule:
    """单条规则（不可变；版本化由 RuleSet 承载）。"""

    rule_id: str
    type: RuleType
    severity: Severity
    hard_gate: bool
    # VISIT_FREQUENCY: outlet 级或默认（outlet_id="*"）
    outlet_id: str = "*"
    visits_per_week: int = 0
    # CADENCE_SLOTS: {weekday(1-7): [slot_index,...]}（VisitIR 合同槽位同型）
    weekday_slots: dict[int, list[int]] = field(default_factory=dict)
    # TIME_WINDOW: "HH:MM-HH:MM"
    window_start: str = ""
    window_end: str = ""
    # KPI_THRESHOLD: 指标名 + 带限（None=该侧无界）
    kpi: str = ""
    kpi_lo: float | None = None
    kpi_hi: float | None = None
    description: str = ""


@dataclass(frozen=True)
class RuleSetVersion:
    """规则集版本（发布后不可变；回滚=激活上一版本）。"""

    version: str
    rules: tuple[Rule, ...]
    activated_at: str = ""
    activated_by: str = ""
    supersedes: str = ""     # 回滚链


@dataclass
class RuleEvaluation:
    """GeoGov RuleEvaluation 同型。"""

    rule_id: str
    verdict: AdmissionAction
    severity: Severity
    hard_gate: bool
    measured: str
    disposition: GovernanceDisposition = GovernanceDisposition.NONE
    evidence: list[str] = field(default_factory=list)


@dataclass
class ConflictFinding:
    """规则集内部冲突（发布前检测）。"""

    code: str
    message: str
    rule_ids: list[str]
    severity: Severity
    blocking: bool           # True=阻止发布；False=ALLOW_WITH_LIMITS 提示
