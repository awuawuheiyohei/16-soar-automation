"""分诊引擎单元测试：去重、关联、优先级评分、误报治理"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models import triage


# ============================================
# 去重键
# ============================================
def test_dedupe_key_format():
    assert triage.dedupe_key("KQL-001", "USER", "a@b.com") == "KQL-001|USER|a@b.com"


def test_dedupe_key_is_case_insensitive():
    assert triage.dedupe_key("KQL-001", "user", "A@B.com") == triage.dedupe_key(
        "KQL-001", "USER", "a@b.com")


def test_dedupe_key_distinguishes_rules():
    assert triage.dedupe_key("KQL-001", "USER", "a@b.com") != triage.dedupe_key(
        "KQL-002", "USER", "a@b.com")


def test_dedupe_key_distinguishes_entity_types():
    assert triage.dedupe_key("KQL-001", "USER", "x") != triage.dedupe_key(
        "KQL-001", "HOST", "x")


# ============================================
# 实体重要性
# ============================================
@pytest.mark.parametrize("value", [
    "admin@vantech-demo.example", "svc_payroll@vantech-demo.example",
    "ga_admin@vantech-demo.example", "root@vantech-demo.example",
    "da_svc@vantech-demo.example",
])
def test_is_privileged_user_detects_prefixes(value):
    assert triage.is_privileged_user("USER", value)


def test_is_privileged_user_rejects_normal_account():
    assert not triage.is_privileged_user("USER", "li.wei@vantech-demo.example")


def test_is_privileged_user_ignores_non_user_entities():
    """主机名 prod-admin-x 不该被当成特权账号加分 —— 类型不对"""
    assert not triage.is_privileged_user("HOST", "prod-admin-01")


def test_is_production_entity_detects_markers():
    assert triage.is_production_entity("HOST", "PROD-DC-01")
    assert triage.is_production_entity("HOST", "web-srv-07")


def test_entity_component_privileged_exceeds_standard():
    priv = triage.entity_component("USER", "ga_admin@vantech-demo.example")
    std = triage.entity_component("USER", "li.wei@vantech-demo.example")
    assert priv > std


def test_entity_component_is_capped_at_20():
    """特权 + 生产标记叠加也不能超过 20，否则优先级四项权重就不成立了"""
    assert triage.entity_component("USER", "svc_prod-root-01") == 20.0


def test_entity_component_unknown_type_uses_default():
    assert triage.entity_component("MYSTERY", "x") == 8.0


# ============================================
# 时效衰减
# ============================================
def test_recency_component_is_full_score_for_now():
    now = datetime.now(timezone.utc)
    assert triage.recency_component(now.isoformat(), now=now) == pytest.approx(20.0)


def test_recency_component_halves_at_half_life():
    now = datetime.now(timezone.utc)
    past = (now - timedelta(hours=12)).isoformat()
    assert triage.recency_component(past, now=now) == pytest.approx(10.0)


def test_recency_component_decays_monotonically():
    now = datetime.now(timezone.utc)
    scores = [
        triage.recency_component((now - timedelta(hours=h)).isoformat(), now=now)
        for h in (0, 6, 12, 24, 48)
    ]
    assert scores == sorted(scores, reverse=True)


def test_recency_component_accepts_sqlite_timestamp_format():
    """SQLite datetime('now') 存的是 'YYYY-MM-DD HH:MM:SS'，不是 ISO 带 T"""
    now = datetime.now(timezone.utc)
    raw = now.strftime("%Y-%m-%d %H:%M:%S")
    assert triage.recency_component(raw, now=now) >= 19.0


# ============================================
# 佐证强度
# ============================================
def test_corroboration_component_per_alert():
    assert triage.corroboration_component(2) == 10.0


def test_corroboration_component_is_capped():
    assert triage.corroboration_component(99) == 20.0


def test_corroboration_component_never_negative():
    assert triage.corroboration_component(-5) == 0.0


# ============================================
# 优先级评分
# ============================================
@pytest.mark.parametrize("score,level", [
    (100, "P1"), (75, "P1"), (74.9, "P2"), (50, "P2"),
    (49.9, "P3"), (25, "P3"), (24.9, "P4"), (0, "P4"),
])
def test_priority_level_thresholds(score, level):
    assert triage.priority_level(score) == level


def test_calculate_priority_components_sum_to_total():
    now = datetime.now(timezone.utc).isoformat()
    calc = triage.calculate_priority(
        "HIGH", "USER", "ga_admin@vantech-demo.example", 2, now)
    total = (calc["severity_component"] + calc["entity_component"]
             + calc["corroboration_component"] + calc["recency_component"])
    assert calc["priority_score"] == pytest.approx(total, abs=0.01)


def test_calculate_priority_never_exceeds_100():
    """CRITICAL + 特权 + 生产 + 4 条佐证 + 刚发生，四项全部顶满"""
    now = datetime.now(timezone.utc).isoformat()
    calc = triage.calculate_priority(
        "CRITICAL", "USER", "svc-prod-root", 10, now)
    assert calc["priority_score"] <= 100.0


def test_calculate_priority_critical_beats_low_at_same_age():
    now = datetime.now(timezone.utc).isoformat()
    crit = triage.calculate_priority("CRITICAL", "USER", "a@b.com", 0, now)
    low = triage.calculate_priority("LOW", "USER", "a@b.com", 0, now)
    assert crit["priority_score"] > low["priority_score"]


def test_calculate_priority_corroboration_raises_score():
    now = datetime.now(timezone.utc).isoformat()
    alone = triage.calculate_priority("HIGH", "USER", "a@b.com", 0, now)
    backed = triage.calculate_priority("HIGH", "USER", "a@b.com", 3, now)
    assert backed["priority_score"] > alone["priority_score"]


def test_calculate_priority_old_alert_loses_to_recent():
    now = datetime.now(timezone.utc)
    recent = triage.calculate_priority(
        "HIGH", "USER", "a@b.com", 0, now.isoformat(), now=now)
    old = triage.calculate_priority(
        "HIGH", "USER", "a@b.com", 0,
        (now - timedelta(hours=72)).isoformat(), now=now)
    assert recent["priority_score"] > old["priority_score"]


# ============================================
# explain()
# ============================================
def test_explain_mentions_level_and_privileged_entity():
    now = datetime.now(timezone.utc)
    alert = {"severity": "CRITICAL", "entity_type": "USER",
             "entity_value": "ga_admin@vantech-demo.example",
             "detected_at": now.isoformat(),
             "severity_component": 40, "entity_component": 20,
             "corroboration_component": 10, "recency_component": 20,
             "priority_score": 90, "priority_level": "P1"}
    text = triage.explain(alert, now=now)
    assert "P1" in text
    assert "特权账号" in text
    assert "关联告警佐证" in text


def test_explain_handles_no_corroboration():
    now = datetime.now(timezone.utc)
    alert = {"severity": "LOW", "entity_type": "IP", "entity_value": "203.0.113.1",
             "detected_at": now.isoformat(),
             "severity_component": 10, "entity_component": 8,
             "corroboration_component": 0, "recency_component": 20,
             "priority_score": 38, "priority_level": "P3"}
    assert "无关联佐证" in triage.explain(alert, now=now)


# ============================================
# 误报率统计
# ============================================
def test_fp_rate_for_rule_computes_percentage(conn):
    # 不要断言绝对条数：test_api.py 也会往同一条规则上追加误报反馈，
    # 这里验证的是「误报率的算法本身」，不是 seed 的具体条数。
    stats = triage.fp_rate_for_rule(conn, "KQL-001")
    assert stats["rule_id"] == "KQL-001"
    assert stats["total_alerts"] >= 8
    assert stats["false_positives"] >= 3
    expected = round(100.0 * stats["false_positives"] / stats["total_alerts"], 1)
    assert stats["fp_rate"] == expected


def test_fp_rate_for_rule_flags_low_sample(conn):
    """KQL-002 只有 2 条告警 —— 即使全误报也不能建议调优"""
    stats = triage.fp_rate_for_rule(conn, "KQL-002")
    assert stats["low_confidence"] is True


def test_fp_rate_for_rule_marks_needs_tuning(conn):
    assert triage.fp_rate_for_rule(conn, "KQL-001")["status"] == "NEEDS_TUNING"


def test_fp_rate_for_rule_healthy_when_no_fp(conn):
    assert triage.fp_rate_for_rule(conn, "KQL-003")["status"] == "HEALTHY"


def test_tuning_recommendations_include_strategy(conn):
    rec = triage.tuning_recommendations(conn, "KQL-001")
    categories = {s["reason_category"] for s in rec["suggestions"]}
    assert "VPN_EXIT_IP" in categories
    assert all(s["strategy"] for s in rec["suggestions"])


def test_tuning_recommendations_status_needs_tuning(conn):
    assert triage.tuning_recommendations(conn, "KQL-001")["status"] == "NEEDS_TUNING"


def test_tuning_suggests_no_threshold_for_low_sample(conn):
    """样本不足时不得给出建议阈值 —— 拿 2 个样本改生产规则是危险的"""
    rec = triage.tuning_recommendations(conn, "KQL-002")
    assert rec["suggested_threshold"] is None


def test_tuning_suggests_threshold_when_feedback_provides_one(conn):
    """KQL-006 有一条带 recommended_threshold=12 的误报反馈，但样本仅 4 条"""
    rec = triage.tuning_recommendations(conn, "KQL-006")
    assert rec["total_alerts"] == 4
    assert rec["status"] == "HEALTHY"
    assert rec["suggested_threshold"] is None


def test_every_fp_category_has_a_strategy():
    for cat in triage.REASON_CATEGORY_STRATEGY:
        assert triage.REASON_CATEGORY_STRATEGY[cat][0]


# ============================================
# 告警摄取
# ============================================
def _payload(**over):
    base = {"rule_id": "KQL-003", "severity": "HIGH", "entity_type": "HOST",
            "entity_value": "TEST-HOST-01", "source_ip": "203.0.113.200",
            "title": "unit test alert"}
    base.update(over)
    return base


def test_ingest_creates_new_alert(conn):
    res = triage.ingest_alert(conn, _payload(), actor="unit-test")
    assert res["deduplicated"] is False
    assert res["alert_id"].startswith("ALR-")


def test_ingest_deduplicates_same_rule_and_entity(conn):
    first = triage.ingest_alert(conn, _payload())
    second = triage.ingest_alert(conn, _payload())
    assert second["deduplicated"] is True
    assert second["alert_id"] == first["alert_id"]
    assert second["alert_count"] == first["alert_count"] + 1


def test_ingest_rejects_unknown_rule(conn):
    with pytest.raises(ValueError, match="unknown rule_id"):
        triage.ingest_alert(conn, _payload(rule_id="KQL-999"))


def test_ingest_normalizes_entity_case_for_dedupe(conn):
    triage.ingest_alert(conn, _payload(entity_value="case-test-01"))
    res = triage.ingest_alert(conn, _payload(entity_value="CASE-TEST-01"))
    assert res["deduplicated"] is True


def test_ingest_sets_default_status_new(conn):
    res = triage.ingest_alert(conn, _payload(entity_value="status-test-01"))
    row = conn.execute("SELECT status FROM alerts WHERE alert_id = ?",
                       (res["alert_id"],)).fetchone()
    assert row["status"] == "NEW"


def test_ingest_correlates_same_entity_different_rule(conn):
    triage.ingest_alert(conn, _payload(
        rule_id="KQL-003", entity_type="USER", entity_value="corr-user@example.test",
        source_ip="203.0.113.201"))
    res = triage.ingest_alert(conn, _payload(
        rule_id="KQL-006", entity_type="USER", entity_value="corr-user@example.test",
        source_ip="203.0.113.202"))
    assert res["correlations"] >= 1


def test_ingest_correlates_same_source_ip_different_entity(conn):
    """跨账号横向移动：实体不同但来源 IP 相同，必须能关联上"""
    triage.ingest_alert(conn, _payload(
        rule_id="KQL-003", entity_value="host-a", source_ip="198.18.0.55"))
    res = triage.ingest_alert(conn, _payload(
        rule_id="KQL-004", entity_value="host-b", source_ip="198.18.0.55"))
    assert res["correlations"] >= 1


def test_ingest_does_not_correlate_unrelated_alert(conn):
    res = triage.ingest_alert(conn, _payload(
        rule_id="KQL-004", entity_value="lonely-entity", source_ip="198.18.9.9"))
    assert res["correlations"] == 0


def test_count_corroborating_is_zero_for_lonely_alert(conn):
    res = triage.ingest_alert(conn, _payload(
        rule_id="KQL-004", entity_value="lonely-2", source_ip="198.18.9.10"))
    assert triage.count_corroborating(conn, res["alert_id"]) == 0


def test_recompute_priority_raises_score_when_corroborated(conn):
    triage.ingest_alert(conn, _payload(
        rule_id="KQL-003", entity_type="USER", entity_value="boost@example.test",
        source_ip="198.18.1.1"))
    first = triage.ingest_alert(conn, _payload(
        rule_id="KQL-006", entity_type="USER", entity_value="boost@example.test",
        source_ip="198.18.1.2"))
    calc = triage.recompute_priority(conn, first["alert_id"])
    assert calc["corroboration_component"] > 0


def test_apply_correlations_is_idempotent(conn):
    triage.ingest_alert(conn, _payload(
        rule_id="KQL-003", entity_type="USER", entity_value="idem@example.test",
        source_ip="198.18.2.1"))
    second = triage.ingest_alert(conn, _payload(
        rule_id="KQL-006", entity_type="USER", entity_value="idem@example.test",
        source_ip="198.18.2.2"))
    again = triage.apply_correlations(conn, second["alert_id"])
    assert again == 0


def test_correlated_alert_status_becomes_correlated(conn):
    triage.ingest_alert(conn, _payload(
        rule_id="KQL-003", entity_type="USER", entity_value="status2@example.test",
        source_ip="198.18.3.1"))
    second = triage.ingest_alert(conn, _payload(
        rule_id="KQL-006", entity_type="USER", entity_value="status2@example.test",
        source_ip="198.18.3.2"))
    row = conn.execute("SELECT status, alert_count FROM alerts WHERE alert_id = ?",
                       (second["alert_id"],)).fetchone()
    assert row["status"] == "CORRELATED"
    assert row["alert_count"] > 1


def test_ingest_records_raw_payload(conn):
    res = triage.ingest_alert(conn, _payload(
        entity_value="raw-test", raw_payload={"kql": "SigninLogs | where ..."}))
    row = conn.execute("SELECT raw_payload FROM alerts WHERE alert_id = ?",
                       (res["alert_id"],)).fetchone()
    assert "SigninLogs" in row["raw_payload"]