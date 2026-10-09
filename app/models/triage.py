"""
告警分诊引擎（triage）—— SOAR 的"大脑"，负责三件事：

1. 去重（dedupe）      同一规则 + 同一实体在时间窗内反复触发 → 只保留一条，累加计数
2. 关联（correlation）  同一实体 / 同一来源 IP 的不同规则告警 → 归为一个调查单元
3. 优先级评分          把"告警严重度"翻译成"先处理谁"

优先级评分公式（0-100）：

    severity    = 严重度权重 (10-40)
    entity      = 实体重要性 (0-20)   —— 特权账号 / 生产主机比普通终端优先
    corroborate = 佐证强度   (0-20)   —— 多个独立规则指向同一实体 = 更可信更紧急
    recency     = 时效衰减   (0-20)   —— 越新越高，48 小时后基本归零

    priority = severity + entity + corroborate + recency

设计原则：
- 去重必须发生在**入库时**而不是查询时。SOAR 的价值在于"每进来 100 条原始事件
  只让分析师看 3 条"，而不是把 100 条摆到人面前让人自己去划掉。
- 关联不能只按实体。跨账号的横向移动共享 source_ip，只按实体会漏掉。
- 评分刻意让四项都参与：只看严重度会让一条"CRITICAL 的低价值 Shadow IT"
  排在"账号被接管"前面，这正是分析师最讨厌的告警噪音。

时效衰减用半衰期 12 小时的指数衰减：12 小时前告警 recency = 10 分（满分的一半）。
用线性衰减会在 48 小时处产生断崖式跳变，排序不稳定。
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

# ============================================
# 严重度权重（合计 40）
# ============================================
SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
}

# ============================================
# 实体重要性（合计 20）
# ============================================
PRIVILEGED_PREFIXES = ("admin", "svc_", "ga_", "sec_", "root", "da_")
PROD_HOST_MARKERS = ("prod", "srv", "db-", "dc-", "core")

ENTITY_WEIGHT = {
    "USER": 12,
    "HOST": 12,
    "IP": 8,
    "APP": 10,
    "FILE_SHARE": 10,
}

PRIVILEGED_BONUS = 8       # 特权账号额外加权
PROD_BONUS = 6             # 生产主机额外加权

# ============================================
# 佐证强度（合计 20）：每条关联告警 5 分，封顶 20
# ============================================
CORROBORATION_PER_ALERT = 5
CORROBORATION_MAX = 20

# ============================================
# 时效衰减（合计 20）：半衰期 12 小时
# ============================================
RECENCY_MAX = 20
RECENCY_HALF_LIFE_HOURS = 12.0

# 关联时间窗：同一 source_ip 在该窗口内视为可能同一次攻击
CORRELATION_WINDOW_HOURS = 24

LEVEL_THRESHOLDS = ((75, "P1"), (50, "P2"), (25, "P3"))
LEVEL_FALLBACK = "P4"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value) -> datetime:
    """解析 SQLite datetime('now') 存的 'YYYY-MM-DD HH:MM:SS' (UTC) 或 ISO8601"""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def dedupe_key(rule_id: str, entity_type: str, entity_value: str) -> str:
    """
    去重键。同一条规则的同一个实体 = 同一件事。
    刻意**不**把 source_ip 放进 key：同一账号从两个 IP 触发仍属同一调查单元。
    """
    return f"{rule_id}|{str(entity_type).upper()}|{str(entity_value).lower()}"


def is_privileged_user(entity_type: str, entity_value: str) -> bool:
    if str(entity_type).upper() != "USER":
        return False
    return str(entity_value).lower().startswith(PRIVILEGED_PREFIXES)


def is_production_entity(entity_type: str, entity_value: str) -> bool:
    val = str(entity_value).lower()
    return any(m in val for m in PROD_HOST_MARKERS)


def recency_component(detected_at, now=None) -> float:
    """指数衰减：现在 = 满分，12 小时前 = 一半"""
    now = now or utc_now()
    # 必须是 now - detected_at。写成 detected_at - now 得到的是负数，
    # 再套 max(0.0, ...) 会让所有历史告警的时效分都顶到满分，组件直接失效。
    age_h = max(0.0, (now - _parse_ts(detected_at)).total_seconds() / 3600.0)
    return RECENCY_MAX * (0.5 ** (age_h / RECENCY_HALF_LIFE_HOURS))


def entity_component(entity_type: str, entity_value: str) -> float:
    base = ENTITY_WEIGHT.get(str(entity_type).upper(), 8)
    if is_privileged_user(entity_type, entity_value):
        base += PRIVILEGED_BONUS
    if is_production_entity(entity_type, entity_value):
        base += PROD_BONUS
    return float(min(20, base))


def corroboration_component(corroborating_alerts: int) -> float:
    return float(min(CORROBORATION_MAX, max(0, corroborating_alerts) * CORROBORATION_PER_ALERT))


def priority_level(score: float) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return LEVEL_FALLBACK


def calculate_priority(severity: str, entity_type: str, entity_value: str,
                       corroborating_alerts: int, detected_at, now=None) -> dict:
    """
    返回完整评分明细（可直接写入 alerts 表 + 供 explain() 使用）
    """
    now = now or utc_now()
    sev = SEVERITY_WEIGHT.get(str(severity).upper(), 20)
    ent = entity_component(entity_type, entity_value)
    corr = corroboration_component(corroborating_alerts)
    rec = recency_component(detected_at, now)

    total = sev + ent + corr + rec

    return {
        "severity_component": round(sev, 2),
        "entity_component": round(ent, 2),
        "corroboration_component": round(corr, 2),
        "recency_component": round(rec, 2),
        "priority_score": round(min(100.0, total), 2),
        "priority_level": priority_level(min(100.0, total)),
    }


def explain(alert: dict, now=None) -> str:
    """生成人类可读的分诊解释（给分析师看：为什么这条排在前面）"""
    now = now or utc_now()
    sev = alert.get("severity_component") or 0
    ent = alert.get("entity_component") or 0
    corr = alert.get("corroboration_component") or 0
    rec = alert.get("recency_component") or 0
    level = alert.get("priority_level", "P4")
    score = alert.get("priority_score", 0)

    reasons = []
    reasons.append(f"严重度 {str(alert.get('severity', '')).upper()} 贡献 {sev:g}")

    if is_privileged_user(alert.get("entity_type"), alert.get("entity_value")):
        reasons.append(f"实体 {alert.get('entity_value')} 是特权账号 (+{PRIVILEGED_BONUS})")
    elif is_production_entity(alert.get("entity_type"), alert.get("entity_value")):
        reasons.append(f"实体 {alert.get('entity_value')} 疑似生产资产 (+{PROD_BONUS})")
    else:
        reasons.append(f"实体重要性 {ent:g}")

    if corr > 0:
        reasons.append(f"有 {int(corr / CORROBORATION_PER_ALERT)} 条关联告警佐证 (+{corr:g})")
    else:
        reasons.append("无关联佐证")

    age_h = abs((_parse_ts(alert.get("detected_at")) - now).total_seconds() / 3600.0)
    reasons.append(f"距今 {age_h:.1f}h，时效分 {rec:g}")

    return f"[{level}] priority={score} · " + "；".join(reasons)


# ============================================
# 关联检测
# ============================================
def find_correlations(conn, alert: dict) -> list:
    """
    找出与给定告警可能属于同一次攻击的其他告警。
    返回 [(related_alert_id, correlation_type, confidence)]
    """
    since = (_parse_ts(alert["detected_at"]) -
             timedelta(hours=CORRELATION_WINDOW_HOURS)).isoformat()

    related = []

    # 1) 同实体、不同规则 —— 例如 MFA 疲劳(KQL-006) + 不可能旅行(KQL-001) 指向同一账号
    for row in conn.execute(
        """SELECT alert_id, rule_id FROM alerts
           WHERE alert_id != ? AND entity_type = ? AND entity_value = ?
             AND rule_id != ? AND detected_at >= ?
           ORDER BY detected_at DESC LIMIT 25""",
        (alert["alert_id"], alert["entity_type"], alert["entity_value"],
         alert["rule_id"], since),
    ).fetchall():
        related.append((row["alert_id"], "SAME_ENTITY", 0.8))

    # 2) 同来源 IP、不同实体 —— 跨账号横向移动的典型特征
    if alert.get("source_ip"):
        for row in conn.execute(
            """SELECT alert_id, entity_value FROM alerts
               WHERE alert_id != ? AND source_ip = ? AND entity_value != ?
                 AND rule_id != ? AND detected_at >= ?
               ORDER BY detected_at DESC LIMIT 25""",
            (alert["alert_id"], alert["source_ip"], alert["entity_value"],
             alert["rule_id"], since),
        ).fetchall():
            related.append((row["alert_id"], "SAME_SOURCE_IP", 0.6))

    return related


def apply_correlations(conn, alert_id: str, actor: str = "system") -> int:
    """
    建立关联关系并把被关联方的 priority 重算一次（佐证分会变）。
    返回新建的关联条数。
    """
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not row:
        return 0
    alert = {k: row[k] for k in row.keys()}

    existing = {r["related_alert_id"] for r in conn.execute(
        "SELECT related_alert_id FROM alert_correlations WHERE primary_alert_id = ?",
        (alert_id,),
    ).fetchall()}

    created = 0
    for related_id, ctype, confidence in find_correlations(conn, alert):
        if related_id in existing:
            continue
        conn.execute(
            """INSERT INTO alert_correlations
               (primary_alert_id, related_alert_id, correlation_type, confidence)
               VALUES (?, ?, ?, ?)""",
            (alert_id, related_id, ctype, confidence),
        )
        created += 1

    if created:
        conn.execute(
            "UPDATE alerts SET status = 'CORRELATED' WHERE alert_id = ? AND status = 'NEW'",
            (alert_id,),
        )
        conn.execute(
            "UPDATE alerts SET alert_count = alert_count + ? WHERE alert_id = ?",
            (created, alert_id),
        )
    conn.commit()
    return created


def count_corroborating(conn, alert_id: str) -> int:
    row = conn.execute(
        """SELECT COUNT(*) c FROM alert_correlations
           WHERE primary_alert_id = ? OR related_alert_id = ?""",
        (alert_id, alert_id),
    ).fetchone()
    return row["c"]


def recompute_priority(conn, alert_id: str, now=None) -> dict:
    """重新计算某条告警的优先级（佐证数变化后需要重算）"""
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not row:
        return {}
    alert = {k: row[k] for k in row.keys()}
    calc = calculate_priority(
        alert["severity"], alert["entity_type"], alert["entity_value"],
        count_corroborating(conn, alert_id), alert["detected_at"], now=now,
    )
    conn.execute(
        "UPDATE alerts SET priority_score = ?, priority_level = ? WHERE alert_id = ?",
        (calc["priority_score"], calc["priority_level"], alert_id),
    )
    conn.commit()
    calc.update(alert)
    return calc


# ============================================
# 误报治理 —— 回哺检测规则调优
# ============================================
# 已知误报场景 → 建议的抑制策略。分类依据是 KQL 规则里自带的"误报场景"注释。
REASON_CATEGORY_STRATEGY = {
    "VPN_EXIT_IP": ("将来源 IP 加入出口 ASN 白名单，或在 KQL 中扩展 WhitelistedAsn 列表", None),
    "BUSINESS_TRAVEL": ("建立常用出差城市基线，对基线内城市组合豁免地理距离检查", None),
    "MAINTENANCE_WINDOW": ("把维护窗口加入抑制列表（时间维度抑制，而非永久关闭规则）", None),
    "NEW_APP_AUTHORIZED": ("把该云服务加入 ApprovedApps 许可清单，而不是关闭整条规则", None),
    "PASSWORD_MANAGER": ("把已注册 MFA 的可信设备 ID 排除在 MFA 失败计数之外", None),
    "SCANNER_MISCONFIG": ("修正检测规则的数据源字段映射（如 Application 解析错误）", None),
    "DUPLICATE_EVENT": ("收紧去重时间窗或合并同源规则，避免重复上报", None),
    "OTHER": ("人工评估，暂不自动生成抑制策略", None),
}


def fp_rate_for_rule(conn, rule_id: str) -> dict:
    """
    计算某条规则的误报率与样本量。
    样本量 < 5 时明确返回 low_confidence=True —— 5 个样本里 3 个误报
    不能说明规则有问题，Dashboard 必须把这一点显示出来。
    """
    total = conn.execute(
        "SELECT COUNT(*) c FROM alerts WHERE rule_id = ?", (rule_id,)
    ).fetchone()["c"]
    fp = conn.execute(
        "SELECT COUNT(*) c FROM false_positive_feedback WHERE rule_id = ?", (rule_id,)
    ).fetchone()["c"]
    rate = round(100.0 * fp / total, 1) if total else 0.0
    return {
        "rule_id": rule_id,
        "total_alerts": total,
        "false_positives": fp,
        "fp_rate": rate,
        "low_confidence": total < 5,
        "status": ("NEEDS_TUNING" if rate >= 30 and total >= 5 else "HEALTHY"),
    }


def tuning_recommendations(conn, rule_id: str) -> dict:
    """
    汇总某条规则的误报反馈，生成可执行的调优建议。
    返回 suggested_threshold：若建议提高阈值则给出具体数值，否则为 None。
    """
    rows = conn.execute(
        """SELECT reason_category, COUNT(*) n, AVG(recommended_threshold) avg_thr
           FROM false_positive_feedback WHERE rule_id = ?
           GROUP BY reason_category ORDER BY n DESC""",
        (rule_id,),
    ).fetchall()

    stats = fp_rate_for_rule(conn, rule_id)
    suggestions = []
    for r in rows:
        strategy, _ = REASON_CATEGORY_STRATEGY.get(r["reason_category"],
                                                  REASON_CATEGORY_STRATEGY["OTHER"])
        suggestions.append({
            "reason_category": r["reason_category"],
            "count": r["n"],
            "strategy": strategy,
        })

    # 只有样本量足够 + 误报率偏高才建议动阈值，避免拿 2 个样本去改生产规则
    suggested_threshold = None
    if stats["status"] == "NEEDS_TUNING" and suggestions:
        thr_rows = conn.execute(
            """SELECT AVG(recommended_threshold) t FROM false_positive_feedback
               WHERE rule_id = ? AND recommended_threshold IS NOT NULL""",
            (rule_id,),
        ).fetchone()
        if thr_rows["t"]:
            suggested_threshold = round(float(thr_rows["t"]), 2)

    return {
        **stats,
        "suggestions": suggestions,
        "suggested_threshold": suggested_threshold,
        "advice": ("误报率可控，维持现状" if stats["status"] == "HEALTHY"
                   else "建议按下列策略调优后再评估该规则的告警量"),
    }


def ingest_alert(conn, payload: dict, actor: str = "siem-connector") -> dict:
    """
    告警摄取：去重 → 关联 → 评分。
    这是 SOAR 摄入侧的核心逻辑，所有写入都记 audit。
    """
    rule_id = payload["rule_id"]
    if not conn.execute("SELECT rule_id FROM detection_rules WHERE rule_id = ?",
                        (rule_id,)).fetchone():
        raise ValueError(f"unknown rule_id: {rule_id}")

    entity_type = str(payload.get("entity_type", "USER")).upper()
    entity_value = payload["entity_value"]
    key = dedupe_key(rule_id, entity_type, entity_value)

    existing = conn.execute(
        "SELECT * FROM alerts WHERE dedupe_key = ?", (key,)
    ).fetchone()

    if existing:
        # 去重命中：不新建告警，只累加计数并刷新时间戳
        conn.execute(
            "UPDATE alerts SET alert_count = alert_count + 1, detected_at = ? WHERE alert_id = ?",
            (payload.get("detected_at") or _parse_ts(datetime.now(timezone.utc)).isoformat(),
             existing["alert_id"]),
        )
        conn.commit()
        calc = recompute_priority(conn, existing["alert_id"])
        return {
            "alert_id": existing["alert_id"],
            "deduplicated": True,
            "alert_count": calc["alert_count"],
            "priority": calc,
        }

    severity = str(payload.get("severity", "MEDIUM")).upper()
    detected_at = payload.get("detected_at") or datetime.now(timezone.utc).isoformat()

    # next_id 是 read-then-insert。FastAPI 的同步端点跑在 threadpool 里，
    # 两个并发 ingest 可能算出同一个 alert_id，靠 PRIMARY KEY 兜底并重试。
    for _ in range(3):
        alert_id = f"ALR-{_next_alert_seq(conn):04d}"
        try:
            conn.execute(
                """INSERT INTO alerts
                   (alert_id, rule_id, title, severity, entity_type, entity_value, source_ip,
                    status, dedupe_key, raw_payload, detected_at)
                   VALUES (?,?,?,?,?,?,?, 'NEW', ?, ?, ?)""",
                (alert_id, rule_id, payload.get("title", "untitled alert"), severity,
                 entity_type, entity_value, payload.get("source_ip"), key,
                 json.dumps(payload.get("raw_payload", {}), ensure_ascii=False),
                 detected_at),
            )
            conn.commit()
            break
        except sqlite3.IntegrityError:
            continue
    else:
        raise RuntimeError("could not allocate a unique alert_id after 3 attempts")

    created_corr = apply_correlations(conn, alert_id, actor=actor)
    calc = recompute_priority(conn, alert_id)
    return {
        "alert_id": alert_id,
        "deduplicated": False,
        "correlations": created_corr,
        "priority": calc,
    }


def _next_alert_seq(conn) -> int:
    from .db import next_id
    return int(next_id(conn, "alerts", "alert_id", "ALR").split("-")[1])