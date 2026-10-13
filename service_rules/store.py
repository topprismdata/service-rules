"""规则集版本存储：发布不可变 + 激活指针 + 一键回滚（上一版本）。

计划验收「污染计划可回滚上一版本」：rollback() 激活 supersedes 链的
前一版本，形成新版本记录（回滚也是版本事件，不删历史）。
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from service_rules.engine import ConflictFinding, detect_conflicts
from service_rules.models import Rule, RuleSetVersion, RuleType, Severity


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class RuleStore:
    def __init__(self, db_path: str | Path = "rules.db"):
        self.db = sqlite3.connect(str(db_path))
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS rule_versions (
          version TEXT PRIMARY KEY, supersedes TEXT,
          activated_at TEXT, activated_by TEXT, doc JSON NOT NULL
        );
        CREATE TABLE IF NOT EXISTS active_pointer (
          id INTEGER PRIMARY KEY CHECK (id=1), version TEXT
        );
        """)

    @staticmethod
    def _dump(rs: RuleSetVersion) -> str:
        return json.dumps({
            "version": rs.version, "supersedes": rs.supersedes,
            "rules": [{
                "rule_id": r.rule_id, "type": r.type.value, "severity": r.severity.value,
                "hard_gate": r.hard_gate, "outlet_id": r.outlet_id,
                "visits_per_week": r.visits_per_week,
                "weekday_slots": {str(k): v for k, v in r.weekday_slots.items()},
                "window_start": r.window_start, "window_end": r.window_end,
                "description": r.description,
            } for r in rs.rules],
        }, ensure_ascii=False)

    @staticmethod
    def _load(doc: str) -> RuleSetVersion:
        d = json.loads(doc)
        rules = tuple(Rule(
            rule_id=r["rule_id"], type=RuleType(r["type"]), severity=Severity(r["severity"]),
            hard_gate=r["hard_gate"], outlet_id=r.get("outlet_id", "*"),
            visits_per_week=r.get("visits_per_week", 0),
            weekday_slots={int(k): list(v) for k, v in r.get("weekday_slots", {}).items()},
            window_start=r.get("window_start", ""), window_end=r.get("window_end", ""),
            description=r.get("description", ""),
        ) for r in d["rules"])
        return RuleSetVersion(d["version"], rules, d.get("activated_at", ""),
                              d.get("activated_by", ""), d.get("supersedes", ""))

    def publish(self, rs: RuleSetVersion, activated_by: str = "",
                force: bool = False) -> list[ConflictFinding]:
        """发布新版本：存在 BLOCKING 冲突时拒绝（除非 force 留痕）。"""
        findings = detect_conflicts(rs)
        if any(f.blocking for f in findings) and not force:
            raise ValueError(f"存在 blocking 冲突: {[f.code for f in findings if f.blocking]}")
        prev = self.active_version()
        rs = RuleSetVersion(rs.version, rs.rules, now_iso(), activated_by,
                            supersedes=prev.version if prev else "")
        self.db.execute("INSERT OR REPLACE INTO rule_versions VALUES (?,?,?,?,?)",
                        (rs.version, rs.supersedes, rs.activated_at, rs.activated_by,
                         self._dump(rs)))
        self.db.execute("INSERT OR REPLACE INTO active_pointer VALUES (1,?)", (rs.version,))
        self.db.commit()
        return findings

    def rollback(self, activated_by: str = "") -> RuleSetVersion:
        """回滚到上一版本：沿 supersedes 链一步，新建版本事件。"""
        cur = self.active_version()
        if cur is None or not cur.supersedes:
            raise ValueError("无可回滚版本")
        prev = self._get(cur.supersedes)
        rolled = RuleSetVersion(
            f"{prev.version}-rollback", prev.rules, now_iso(), activated_by,
            supersedes=cur.version)
        self.db.execute("INSERT OR REPLACE INTO rule_versions VALUES (?,?,?,?,?)",
                        (rolled.version, rolled.supersedes, rolled.activated_at,
                         rolled.activated_by, self._dump(rolled)))
        self.db.execute("INSERT OR REPLACE INTO active_pointer VALUES (1,?)",
                        (rolled.version,))
        self.db.commit()
        return rolled

    def get_version(self, version: str) -> RuleSetVersion | None:
        """公开查询任意已发布版本（#22-24 方案绑定存在性闸消费；WP22）。"""
        return self._get(version)

    def active_version(self) -> RuleSetVersion | None:
        row = self.db.execute("SELECT version FROM active_pointer WHERE id=1").fetchone()
        return self._get(row[0]) if row else None

    def _get(self, version: str) -> RuleSetVersion | None:
        row = self.db.execute(
            "SELECT doc FROM rule_versions WHERE version=?", (version,)).fetchone()
        return self._load(row[0]) if row else None

    def close_db(self) -> None:
        self.db.close()
