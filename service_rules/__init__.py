"""service-rules: 服务规则库 (WP07) — GeoGov DSL 同型。"""
from service_rules.engine import (GateDecision, aggregate, detect_conflicts,
                             evaluate_outlet_day, evaluate_week)
from service_rules.models import (
    AdmissionAction, ConflictFinding, GovernanceDisposition, Rule,
    RuleEvaluation, RuleSetVersion, RuleType, Severity,
)
from service_rules.store import RuleStore

__version__ = "0.1.1"

__all__ = [
    "AdmissionAction", "ConflictFinding", "GateDecision", "GovernanceDisposition",
    "Rule", "RuleEvaluation", "RuleSetVersion", "RuleStore", "RuleType",
    "Severity", "__version__", "aggregate", "detect_conflicts",
    "evaluate_outlet_day", "evaluate_week",
]
