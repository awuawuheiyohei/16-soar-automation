"""REST API 测试"""
import pytest


# ============================================
# 健康 / 总览
# ============================================
def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_declares_simulated_execution(client):
    """健康检查必须自曝执行器是模拟的，不能让人误以为接了真实产品"""
    assert "SIMULATED" in client.get("/api/health").json()["execution_mode"]


def test_health_version(client):
    assert client.get("/api/health").json()["version"] == "1.0.0"


def test_overview(client):
    r = client.get("/api/overview")
    assert r.status_code == 200
    assert r.json()["total_alerts"] > 0


def test_overview_has_all_sections(client):
    d = client.get("/api/overview").json()
    for key in ("alerts_by_status", "runs_by_status", "top_alerts",
                "rules_needing_tuning", "recent_runs", "pending_approvals"):
        assert key in d


def test_overview_shows_all_run_outcomes(client):
    """演示数据应当同时包含 完成/失败/回滚/待审批 四种状态"""
    statuses = client.get("/api/overview").json()["runs_by_status"]
    for s in ("COMPLETED", "FAILED", "ROLLED_BACK", "PENDING_APPROVAL"):
        assert statuses.get(s, 0) > 0, f"seed 缺少 {s} 状态的执行"


def test_overview_counts_action_steps(client):
    d = client.get("/api/overview").json()
    assert d["action_steps_by_status"].get("SUCCESS", 0) > 0
    assert d["action_steps_by_status"].get("DRY_RUN_OK", 0) > 0


# ============================================
# 检测规则
# ============================================
def test_list_rules(client):
    r = client.get("/api/rules")
    assert r.status_code == 200
    assert r.json()["count"] == 6


def test_rules_include_fp_stats(client):
    rules = client.get("/api/rules").json()["rules"]
    assert all("fp_stats" in x for x in rules)


def test_get_rule(client):
    r = client.get("/api/rules/KQL-001")
    assert r.status_code == 200
    assert r.json()["name"].startswith("Suspicious Sign-In Pattern")


def test_get_rule_unknown_returns_404(client):
    assert client.get("/api/rules/KQL-999").status_code == 404


def test_get_rule_includes_tuning(client):
    d = client.get("/api/rules/KQL-001").json()
    assert d["tuning"]["status"] == "NEEDS_TUNING"
    assert d["tuning"]["suggestions"]


def test_get_rule_includes_known_fp_scenarios(client):
    """每条规则都应带 KQL 里原有的误报场景注释 —— 调优的前提是知道误报长什么样"""
    assert client.get("/api/rules/KQL-005").json()["tuning_notes"]


# ============================================
# 告警
# ============================================
def test_list_alerts(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json()["count"] > 0


def test_alerts_sorted_by_priority_desc(client):
    scores = [a["priority_score"] for a in client.get("/api/alerts").json()["alerts"]]
    assert scores == sorted(scores, reverse=True)


def test_alerts_filter_by_status(client):
    d = client.get("/api/alerts?status=FALSE_POSITIVE").json()
    assert all(a["status"] == "FALSE_POSITIVE" for a in d["alerts"])


def test_alerts_filter_by_rule(client):
    d = client.get("/api/alerts?rule_id=KQL-001").json()
    assert all(a["rule_id"] == "KQL-001" for a in d["alerts"])


def test_alerts_filter_by_priority(client):
    d = client.get("/api/alerts?priority_level=P1").json()
    assert all(a["priority_level"] == "P1" for a in d["alerts"])


def test_alerts_search(client):
    d = client.get("/api/alerts?search=Mega").json()
    assert d["count"] >= 1


def test_alerts_limit_is_enforced(client):
    assert client.get("/api/alerts?limit=5000").status_code == 422


def test_get_alert(client):
    r = client.get("/api/alerts/ALR-0001")
    assert r.status_code == 200
    assert r.json()["alert_id"] == "ALR-0001"


def test_get_alert_unknown_returns_404(client):
    assert client.get("/api/alerts/ALR-9999").status_code == 404


def test_alert_detail_contains_explanation(client):
    """分析师必须能看到「为什么这条排在前面」，而不是只有一个神秘分数"""
    assert len(client.get("/api/alerts/ALR-0001").json()["explanation"]) > 0


def test_alert_detail_contains_score_breakdown(client):
    d = client.get("/api/alerts/ALR-0001").json()
    for k in ("severity_component", "entity_component",
              "corroboration_component", "recency_component"):
        assert k in d


def test_alert_detail_parses_raw_payload(client):
    assert isinstance(client.get("/api/alerts/ALR-0001").json()["raw_payload"], dict)


def test_alert_detail_includes_correlations(client):
    d = client.get("/api/alerts/ALR-0001").json()
    assert isinstance(d["correlations"], list)


def test_update_alert_status(client):
    r = client.patch("/api/alerts/ALR-0002/status", json={"status": "TRIAGED",
                                                         "actor": "api-test"})
    assert r.status_code == 200
    assert r.json()["status"] == "TRIAGED"


def test_update_alert_status_rejects_invalid(client):
    r = client.patch("/api/alerts/ALR-0002/status", json={"status": "BOGUS"})
    assert r.status_code == 400


def test_update_alert_status_unknown_alert(client):
    r = client.patch("/api/alerts/ALR-9999/status", json={"status": "TRIAGED"})
    assert r.status_code == 404


def test_update_alert_status_is_audited(client):
    client.patch("/api/alerts/ALR-0003/status",
                 json={"status": "RESOLVED", "actor": "api-test"})
    d = client.get("/api/audit?action=status_change").json()
    assert d["count"] >= 1


# ============================================
# 告警摄取
# ============================================
def test_ingest_creates_alert(client):
    r = client.post("/api/alerts/ingest", json={
        "rule_id": "KQL-003", "severity": "HIGH", "entity_type": "HOST",
        "entity_value": "API-TEST-HOST-01", "title": "ingest test"})
    assert r.status_code == 200
    assert r.json()["deduplicated"] is False


def test_ingest_deduplicates_repeat(client):
    payload = {"rule_id": "KQL-003", "severity": "HIGH", "entity_type": "HOST",
               "entity_value": "API-TEST-HOST-DEDUP", "title": "dup test"}
    first = client.post("/api/alerts/ingest", json=payload).json()
    second = client.post("/api/alerts/ingest", json=payload).json()
    assert second["deduplicated"] is True
    assert second["alert_id"] == first["alert_id"]


def test_ingest_requires_rule_and_entity(client):
    r = client.post("/api/alerts/ingest", json={"severity": "HIGH"})
    assert r.status_code == 400
    assert "rule_id" in r.json()["detail"]


def test_ingest_rejects_unknown_rule(client):
    r = client.post("/api/alerts/ingest", json={
        "rule_id": "KQL-999", "entity_value": "x", "entity_type": "HOST"})
    assert r.status_code == 400


def test_ingest_is_audited(client):
    res = client.post("/api/alerts/ingest", json={
        "rule_id": "KQL-005", "entity_type": "APP",
        "entity_value": "API-TEST-APP", "title": "audit test"}).json()
    d = client.get(f"/api/audit?entity_id={res['alert_id']}").json()
    assert d["count"] >= 1


# ============================================
# 误报治理
# ============================================
def test_report_false_positive(client):
    r = client.post("/api/alerts/ALR-0004/false-positive", json={
        "reason_category": "VPN_EXIT_IP", "reason_text": "corporate vpn pool",
        "suppression_target": "ASN:AS64500", "actor": "api-test"})
    assert r.status_code == 200
    assert r.json()["fp_id"].startswith("FP-")


def test_report_false_positive_returns_updated_tuning(client):
    d = client.post("/api/alerts/ALR-0005/false-positive", json={
        "reason_category": "MAINTENANCE_WINDOW"}).json()
    assert "rule_tuning" in d
    assert d["rule_tuning"]["false_positives"] >= 1


def test_report_false_positive_rejects_bad_category(client):
    r = client.post("/api/alerts/ALR-0006/false-positive",
                    json={"reason_category": "NOT_A_CATEGORY"})
    assert r.status_code == 400


def test_report_false_positive_unknown_alert(client):
    r = client.post("/api/alerts/ALR-9999/false-positive",
                    json={"reason_category": "OTHER"})
    assert r.status_code == 404


def test_false_positive_marks_alert_status(client):
    client.post("/api/alerts/ALR-0007/false-positive",
                json={"reason_category": "DUPLICATE_EVENT"})
    assert client.get("/api/alerts/ALR-0007").json()["status"] == "FALSE_POSITIVE"


def test_list_false_positives(client):
    d = client.get("/api/false-positives").json()
    assert d["count"] >= 6
    assert d["by_category"]


def test_tuning_overview_covers_every_rule(client):
    d = client.get("/api/tuning").json()
    assert d["count"] == 6
    assert all("fp_rate" in t for t in d["tuning"])


def test_tuning_overview_flags_low_sample(client):
    """样本不足必须被显式标出，否则会拿噪声去改规则"""
    d = client.get("/api/tuning").json()
    assert any(t["low_confidence"] for t in d["tuning"])


# ============================================
# Playbook
# ============================================
def test_list_playbooks(client):
    d = client.get("/api/playbooks").json()
    assert d["count"] == 5


def test_playbooks_expose_approval_gate(client):
    d = client.get("/api/playbooks").json()["playbooks"]
    assert any(p["approval_gated_actions"] > 0 for p in d)
    assert any(p["approval_gated_actions"] == 0 for p in d)


def test_get_playbook(client):
    d = client.get("/api/playbooks/PB-001").json()
    assert d["playbook_id"] == "PB-001"
    assert len(d["actions"]) == 6


def test_get_playbook_actions_ordered(client):
    steps = [a["step_no"] for a in client.get("/api/playbooks/PB-001").json()["actions"]]
    assert steps == sorted(steps)


def test_get_playbook_unknown_returns_404(client):
    assert client.get("/api/playbooks/PB-999").status_code == 404


def test_playbook_actions_expose_simulated_connector(client):
    """每个动作都必须标明自己连的是模拟器，不含糊"""
    a = client.get("/api/playbooks/PB-001").json()["actions"][0]
    assert a["simulated_connector"].startswith("sim-")


def test_trigger_dry_run(client):
    r = client.post("/api/playbooks/PB-004/run",
                    json={"mode": "DRY_RUN", "actor": "api-test"})
    assert r.status_code == 200
    assert r.json()["status"] == "COMPLETED"


def test_trigger_live_with_approval_gate_pends(client):
    r = client.post("/api/playbooks/PB-001/run",
                    json={"mode": "LIVE", "actor": "api-test"})
    assert r.json()["status"] == "PENDING_APPROVAL"
    assert r.json()["steps"] == []


def test_trigger_unknown_playbook_returns_404(client):
    r = client.post("/api/playbooks/PB-999/run", json={"mode": "DRY_RUN"})
    assert r.status_code == 404


def test_trigger_invalid_mode_returns_400(client):
    r = client.post("/api/playbooks/PB-004/run", json={"mode": "SEMI"})
    assert r.status_code == 400


# ============================================
# 执行实例
# ============================================
def test_list_runs(client):
    assert client.get("/api/runs").json()["count"] > 0


def test_list_runs_filter_by_status(client):
    d = client.get("/api/runs?status=COMPLETED").json()
    assert all(r["status"] == "COMPLETED" for r in d["runs"])


def test_list_runs_filter_by_mode(client):
    d = client.get("/api/runs?mode=DRY_RUN").json()
    assert all(r["mode"] == "DRY_RUN" for r in d["runs"])


def test_get_run(client):
    d = client.get("/api/runs/RUN-000001").json()
    assert d["run_id"] == "RUN-000001"
    assert len(d["steps"]) == 4


def test_get_run_unknown_returns_404(client):
    assert client.get("/api/runs/RUN-999999").status_code == 404


def test_run_detail_includes_audit_trail(client):
    """全链路审计是这个项目的核心承诺之一"""
    d = client.get("/api/runs/RUN-000002").json()
    assert d["audit"]
    assert any(a["action"] == "run_start" for a in d["audit"])


def test_run_detail_audit_includes_per_step_entries(client):
    """
    每一步的执行记录用 "<run_id>#<step>" 作为 entity_id，
    只做等值匹配会漏掉它们，审计轨迹就成了残缺的。
    """
    d = client.get("/api/runs/RUN-000002").json()
    assert any(a["action"] == "execute_step" for a in d["audit"])
    assert any(a["action"] == "run_finish" for a in d["audit"])


def test_run_detail_rollback_run_shows_reference(client):
    """RUN-000003 是自动回滚的run，时间线里必须有补偿动作"""
    d = client.get("/api/runs/RUN-000003").json()
    assert d["status"] == "ROLLED_BACK"
    assert any(s["is_rollback"] == 1 for s in d["steps"])


def test_approve_requires_approver(client):
    r = client.post("/api/runs/RUN-000006/approve", json={"reason": "ok"})
    assert r.status_code == 400


def test_approve_executes_run(client):
    r = client.post("/api/runs/RUN-000006/approve",
                    json={"approver": "api-test@test", "reason": "confirmed incident"})
    assert r.status_code == 200
    assert r.json()["approved_by"] == "api-test@test"


def test_approve_rejects_empty_reason(client):
    run = client.post("/api/playbooks/PB-002/run", json={"mode": "LIVE"}).json()
    r = client.post(f"/api/runs/{run['run_id']}/approve",
                    json={"approver": "x@test", "reason": "  "})
    assert r.status_code == 400


def test_approve_unknown_run_returns_404(client):
    r = client.post("/api/runs/RUN-999999/approve",
                    json={"approver": "x", "reason": "y"})
    assert r.status_code == 404


def test_reject_cancels_run(client):
    run = client.post("/api/playbooks/PB-001/run", json={"mode": "LIVE"}).json()
    r = client.post(f"/api/runs/{run['run_id']}/reject",
                    json={"approver": "api-test@test", "reason": "false positive"})
    assert r.json()["status"] == "CANCELLED"


def test_execute_is_idempotent(client):
    run = client.post("/api/playbooks/PB-004/run", json={"mode": "DRY_RUN"}).json()
    first = client.post(f"/api/runs/{run['run_id']}/execute", json={}).json()
    second = client.post(f"/api/runs/{run['run_id']}/execute", json={}).json()
    assert len(first["steps"]) == len(second["steps"])


def test_execute_blocked_by_pending_approval(client):
    run = client.post("/api/playbooks/PB-001/run", json={"mode": "LIVE"}).json()
    r = client.post(f"/api/runs/{run['run_id']}/execute", json={})
    assert r.status_code == 409


def test_rollback_creates_compensation_run(client):
    run = client.post("/api/playbooks/PB-004/run", json={"mode": "LIVE"}).json()
    r = client.post(f"/api/runs/{run['run_id']}/rollback",
                    json={"actor": "lead@test", "reason": "manual compensation"})
    assert r.status_code == 200
    assert r.json()["original_run_id"] == run["run_id"]


def test_rollback_dry_run_returns_400(client):
    run = client.post("/api/playbooks/PB-004/run", json={"mode": "DRY_RUN"}).json()
    r = client.post(f"/api/runs/{run['run_id']}/rollback", json={})
    assert r.status_code == 400


# ============================================
# url-encoded 表单审批（手写解析器，不依赖 python-multipart）
# ============================================
def test_approval_form_accepts_urlencoded(client):
    run = client.post("/api/playbooks/PB-003/run", json={"mode": "LIVE"}).json()
    r = client.post(
        f"/api/runs/{run['run_id']}/approval-form",
        content="approver=form-user%40test.example&reason=form+approved",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 200
    assert r.json()["approved_by"] == "form-user@test.example"
    assert r.json()["approval_reason"] == "form approved"


def test_approval_form_rejects_wrong_content_type(client):
    run = client.post("/api/playbooks/PB-002/run", json={"mode": "LIVE"}).json()
    r = client.post(f"/api/runs/{run['run_id']}/approval-form",
                    content="approver=x", headers={"Content-Type": "application/json"})
    assert r.status_code == 415


def test_approval_form_requires_approver(client):
    run = client.post("/api/playbooks/PB-002/run", json={"mode": "LIVE"}).json()
    r = client.post(
        f"/api/runs/{run['run_id']}/approval-form",
        content="reason=no-approver",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 400


# ============================================
# 审批队列 / 审计
# ============================================
def test_list_approvals(client):
    d = client.get("/api/approvals").json()
    assert d["count"] > 0
    assert "by_decision" in d


def test_approvals_show_gated_action_types(client):
    """审批队列要直接告诉审批人：你在批准哪些破坏性动作"""
    d = client.get("/api/approvals?decision=PENDING").json()
    assert d["approvals"]
    assert any(a["gated_action_types"] for a in d["approvals"])


def test_approvals_filter_by_decision(client):
    d = client.get("/api/approvals?decision=APPROVED").json()
    assert all(a["decision"] == "APPROVED" for a in d["approvals"])


def test_audit_is_newest_first(client):
    ids = [e["audit_id"] for e in client.get("/api/audit").json()["entries"]]
    assert ids == sorted(ids, reverse=True)


def test_audit_details_are_parsed_json(client):
    e = client.get("/api/audit").json()["entries"][0]
    assert isinstance(e["details"], (dict, str))


def test_audit_filter_by_entity(client):
    d = client.get("/api/audit?entity_type=playbook_run").json()
    assert d["count"] > 0
    assert all(e["entity_type"] == "playbook_run" for e in d["entries"])


def test_audit_limit_enforced(client):
    assert client.get("/api/audit?limit=99999").status_code == 422


# ============================================
# Dashboard / OpenAPI
# ============================================
def test_dashboard_served(client):
    assert client.get("/").status_code == 200


def test_openapi_schema_available(client):
    assert client.get("/openapi.json").status_code == 200


def test_dashboard_states_data_is_synthetic(client):
    """首页必须带有数据诚实性声明"""
    body = client.get("/").text
    assert "合成演示数据" in body
    assert "没有对接任何真实" in body