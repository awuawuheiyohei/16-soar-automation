"""Playbook 执行引擎测试：审批门、幂等、自动回滚、目标解析"""
import pytest

from app.models import automation


# ============================================
# Action 类型注册表完整性
# ============================================
def test_every_playbook_action_type_is_registered(conn):
    rows = conn.execute("SELECT DISTINCT action_type FROM playbook_actions").fetchall()
    for r in rows:
        assert r["action_type"] in automation.ACTION_TYPES, r["action_type"]


def test_every_compensating_action_is_registered(conn):
    rows = conn.execute(
        "SELECT DISTINCT compensating_action FROM playbook_actions "
        "WHERE compensating_action IS NOT NULL").fetchall()
    for r in rows:
        assert r["compensating_action"] in automation.ACTION_TYPES


def test_every_destructive_step_defines_a_compensating_action(conn):
    """
    没有补偿动作的破坏性步骤不允许存在于 playbook 中 —— 出了问题无法回退，
    就不该被放进自动化流程。
    """
    rows = conn.execute(
        "SELECT action_id, action_type FROM playbook_actions "
        "WHERE is_destructive = 1").fetchall()
    assert rows, "seed 应当至少有一个破坏性步骤"
    for r in rows:
        row = conn.execute("SELECT compensating_action FROM playbook_actions "
                           "WHERE action_id = ?", (r["action_id"],)).fetchone()
        assert row["compensating_action"], f"{r['action_type']} 缺少补偿动作"


def test_approval_gated_actions_are_destructive(conn):
    """需要审批的动作一定是破坏性的 —— 只读步骤没必要卡审批"""
    rows = conn.execute(
        "SELECT action_type FROM playbook_actions WHERE requires_approval = 1").fetchall()
    assert rows
    for r in rows:
        assert automation.ACTION_TYPES[r["action_type"]]["destructive"] is True


def test_read_only_playbook_needs_no_approval(conn):
    """PB-004 全部是只读步骤，应当可以全自动执行"""
    assert automation.playbook_requires_approval(conn, "PB-004") is False


def test_destructive_playbook_requires_approval(conn):
    assert automation.playbook_requires_approval(conn, "PB-001") is True


# ============================================
# 模拟 connector
# ============================================
def test_execute_action_dry_run_reports_no_change():
    r = automation.execute_action("disable_account", "a@b.com", dry_run=True)
    assert r["ok"] is True
    assert r["simulated"] is True
    assert "dry-run" in r["message"]


def test_execute_action_succeeds_for_normal_target():
    r = automation.execute_action("reset_password", "normal-user@example.test")
    assert r["ok"] is True
    assert r["simulated"] is True


def test_execute_action_fails_on_injected_failure():
    """失败注入必须是确定性的，否则回滚路径无法测试"""
    r = automation.execute_action("reset_password", "svc-payroll-export")
    assert r["ok"] is False
    assert "409 Conflict" in r["message"]


def test_execute_action_dry_run_bypasses_failure_injection():
    """预演时即使该目标注定失败也要返回成功 —— DRY-RUN 的目的是看流程能否走通"""
    r = automation.execute_action("reset_password", "svc-payroll-export", dry_run=True)
    assert r["ok"] is True


def test_execute_action_unknown_type_fails_cleanly():
    r = automation.execute_action("launch_missiles", "x")
    assert r["ok"] is False
    assert "unknown action_type" in r["message"]


def test_execute_action_latency_is_deterministic():
    a = automation.execute_action("isolate_host", "HOST-X")
    b = automation.execute_action("isolate_host", "HOST-X")
    assert a["latency_ms"] == b["latency_ms"]


def test_compensating_actions_are_not_reachable_as_normal_steps(conn):
    """补偿方向的动作不应出现在任何 playbook 的正常步骤里"""
    rows = conn.execute("SELECT action_type FROM playbook_actions").fetchall()
    for r in rows:
        assert r["action_type"] not in automation.COMPENSATION_ONLY


# ============================================
# 幂等键
# ============================================
def test_idempotency_key_is_stable():
    a = automation.idempotency_key("RUN-000001", 3, "ACT-PB001-03")
    b = automation.idempotency_key("RUN-000001", 3, "ACT-PB001-03")
    assert a == b


def test_idempotency_key_differs_per_run():
    assert automation.idempotency_key("RUN-000001", 1, "A") != \
           automation.idempotency_key("RUN-000002", 1, "A")


def test_idempotency_key_is_unique_in_db(conn):
    """唯一约束是幂等性的最后一道防线"""
    rows = conn.execute(
        "SELECT idempotency_key, COUNT(*) n FROM action_runs "
        "GROUP BY idempotency_key HAVING n > 1").fetchall()
    assert rows == []


# ============================================
# start_run
# ============================================
def test_start_run_dry_run_completes_immediately(conn):
    alert = conn.execute(
        "SELECT alert_id FROM alerts WHERE rule_id='KQL-001' LIMIT 1").fetchone()["alert_id"]
    run = automation.start_run(conn, "PB-002", "DRY_RUN", alert, actor="unit")
    assert run["status"] == "COMPLETED"
    assert all(s["status"] == "DRY_RUN_OK" for s in run["steps"])


def test_start_run_dry_run_produces_no_live_effects(conn):
    run = automation.start_run(conn, "PB-004", "DRY_RUN", actor="unit")
    assert all(s["dry_run"] == 1 for s in run["steps"])


def test_start_run_live_with_approval_gate_pends(conn):
    """LIVE + 含需审批步骤 => 只建 run，一个步骤都不执行"""
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    assert run["status"] == "PENDING_APPROVAL"
    assert run["steps"] == []
    assert run["approved_by"] is None


def test_start_run_live_without_approval_gate_executes(conn):
    run = automation.start_run(conn, "PB-004", "LIVE", actor="unit")
    assert run["status"] == "COMPLETED"


def test_start_run_creates_pending_approval_request(conn):
    run = automation.start_run(conn, "PB-002", "LIVE", actor="unit")
    n = conn.execute("SELECT COUNT(*) c FROM approval_requests WHERE run_id = ?",
                     (run["run_id"],)).fetchone()["c"]
    assert n == 1


def test_start_run_rejects_invalid_mode(conn):
    with pytest.raises(ValueError, match="invalid mode"):
        automation.start_run(conn, "PB-004", "SEMI_AUTO", actor="unit")


def test_start_run_unknown_playbook_raises(conn):
    with pytest.raises(LookupError, match="not found"):
        automation.start_run(conn, "PB-999", "DRY_RUN", actor="unit")


def test_start_run_unknown_alert_raises(conn):
    with pytest.raises(LookupError, match="alert"):
        automation.start_run(conn, "PB-004", "DRY_RUN", "ALR-9999", actor="unit")


def test_start_run_disabled_playbook_raises(conn):
    conn.execute("INSERT INTO playbooks (playbook_id, name, enabled) "
                 "VALUES ('PB-900','disabled pb',0)")
    conn.commit()
    with pytest.raises(ValueError, match="disabled"):
        automation.start_run(conn, "PB-900", "DRY_RUN", actor="unit")


def test_start_run_playbook_without_actions_raises(conn):
    conn.execute("INSERT INTO playbooks (playbook_id, name) VALUES ('PB-901','empty pb')")
    conn.commit()
    with pytest.raises(ValueError, match="no actions"):
        automation.start_run(conn, "PB-901", "DRY_RUN", actor="unit")


# ============================================
# 审批门
# ============================================
def test_execute_run_blocked_by_pending_approval(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    with pytest.raises(PermissionError, match="pending approval"):
        automation.execute_run(conn, run["run_id"], actor="unit")


def test_approve_run_executes_and_records_approver(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    done = automation.approve_run(conn, run["run_id"], "irene@test", "确认失陷")
    assert done["status"] == "COMPLETED"
    assert done["approved_by"] == "irene@test"
    assert done["approval_reason"] == "确认失陷"


def test_approve_run_requires_reason(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    with pytest.raises(ValueError, match="reason is required"):
        automation.approve_run(conn, run["run_id"], "irene@test", "   ")


def test_approve_run_rejects_wrong_state(conn):
    run = automation.start_run(conn, "PB-004", "DRY_RUN", actor="unit")
    with pytest.raises(ValueError, match="not awaiting approval"):
        automation.approve_run(conn, run["run_id"], "irene@test", "no")


def test_reject_run_cancels_without_executing(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    cancelled = automation.reject_run(conn, run["run_id"], "irene@test", "疑似误报")
    assert cancelled["status"] == "CANCELLED"
    assert cancelled["steps"] == []


def test_reject_run_requires_reason(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    with pytest.raises(ValueError, match="reason is required"):
        automation.reject_run(conn, run["run_id"], "irene@test", "")


def test_reject_run_writes_audit(conn):
    from app.models.db import write_audit  # noqa: F401  (确保 audit 路径可用)
    run = automation.start_run(conn, "PB-002", "LIVE", actor="unit")
    automation.reject_run(conn, run["run_id"], "irene@test", "误报")
    n = conn.execute(
        "SELECT COUNT(*) c FROM audit_log WHERE action='reject' AND entity_id=?",
        (run["run_id"],)).fetchone()["c"]
    assert n == 1


# ============================================
# 幂等执行
# ============================================
def test_execute_run_is_idempotent_on_completed_run(conn):
    run = automation.start_run(conn, "PB-004", "DRY_RUN", actor="unit")
    before = len(conn.execute(
        "SELECT * FROM action_runs WHERE run_id=?", (run["run_id"],)).fetchall())
    automation.execute_run(conn, run["run_id"], actor="unit")
    after = len(conn.execute(
        "SELECT * FROM action_runs WHERE run_id=?", (run["run_id"],)).fetchall())
    assert before == after


def test_execute_run_never_duplicates_a_step(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    automation.approve_run(conn, run["run_id"], "irene@test", "ok")
    for _ in range(3):
        automation.execute_run(conn, run["run_id"], actor="unit")
    rows = conn.execute(
        "SELECT step_no, COUNT(*) n FROM action_runs "
        "WHERE run_id=? AND is_rollback=0 GROUP BY step_no", (run["run_id"],)).fetchall()
    assert all(r["n"] == 1 for r in rows)


# ============================================
# 失败与回滚
# ============================================
def test_failed_step_triggers_auto_rollback(conn):
    """svc-payroll-export 上 reset_password 确定性失败 =>
    前一步已成功的 revoke_sessions 必须被补偿"""
    alert = conn.execute(
        "SELECT alert_id FROM alerts WHERE entity_value='svc-payroll-export' "
        "AND rule_id='KQL-006' LIMIT 1").fetchone()
    if alert is None:
        pytest.skip("seed 中缺少 svc-payroll-export 的 MFA 告警")
    run = automation.start_run(conn, "PB-001", "LIVE", alert["alert_id"], actor="unit")
    result = automation.approve_run(conn, run["run_id"], "irene@test", "处置")
    assert result["status"] == "ROLLED_BACK"


def test_rollback_executes_compensating_action(conn):
    alert = conn.execute(
        "SELECT alert_id FROM alerts WHERE entity_value='svc-payroll-export' "
        "AND rule_id='KQL-006' LIMIT 1").fetchone()
    if alert is None:
        pytest.skip("seed 中缺少 svc-payroll-export 的 MFA 告警")
    run = automation.start_run(conn, "PB-001", "LIVE", alert["alert_id"], actor="unit")
    result = automation.approve_run(conn, run["run_id"], "irene@test", "处置")
    comp = [s for s in result["steps"] if s["is_rollback"] == 1]
    assert comp, "应至少产生一条补偿执行记录"
    assert comp[0]["action_type"] == "restore_sessions"


def test_rollback_marks_original_step_rolled_back(conn):
    alert = conn.execute(
        "SELECT alert_id FROM alerts WHERE entity_value='svc-payroll-export' "
        "AND rule_id='KQL-006' LIMIT 1").fetchone()
    if alert is None:
        pytest.skip("seed 中缺少 svc-payroll-export 的 MFA 告警")
    run = automation.start_run(conn, "PB-001", "LIVE", alert["alert_id"], actor="unit")
    result = automation.approve_run(conn, run["run_id"], "irene@test", "处置")
    assert any(s["status"] == "ROLLED_BACK" for s in result["steps"])


def test_failed_run_without_prior_destructive_step_is_failed_not_rolled_back(conn):
    """PB-003 的 block_ip 是唯一的破坏性步骤，它失败时没有东西可回滚"""
    alert = conn.execute(
        "SELECT alert_id FROM alerts WHERE entity_value='MegaNz-Transfer' LIMIT 1"
    ).fetchone()
    if alert is None:
        pytest.skip("seed 中缺少 MegaNz-Transfer 告警")
    run = automation.start_run(conn, "PB-003", "LIVE", alert["alert_id"], actor="unit")
    result = automation.approve_run(conn, run["run_id"], "irene@test", "封禁")
    assert result["status"] == "FAILED"


def test_run_stops_at_first_failure(conn):
    """失败后不应继续执行后续步骤"""
    alert = conn.execute(
        "SELECT alert_id FROM alerts WHERE entity_value='MegaNz-Transfer' LIMIT 1"
    ).fetchone()
    if alert is None:
        pytest.skip("seed 中缺少 MegaNz-Transfer 告警")
    run = automation.start_run(conn, "PB-003", "LIVE", alert["alert_id"], actor="unit")
    result = automation.approve_run(conn, run["run_id"], "irene@test", "封禁")
    executed = [s for s in result["steps"] if s["is_rollback"] == 0]
    assert len(executed) == 4  # 前 3 步成功 + 第 4 步失败，之后不再执行
    assert executed[-1]["status"] == "FAILED"


# ============================================
# 手动回滚
# ============================================
def test_rollback_run_creates_new_run_with_reference(conn):
    run = automation.start_run(conn, "PB-004", "LIVE", actor="unit")
    rb = automation.rollback_run(conn, run["run_id"], "lead@test", "误判")
    assert rb["rolled_back_from"] == run["run_id"]
    assert rb["run_id"] != run["run_id"]


def test_rollback_run_on_dry_run_raises(conn):
    run = automation.start_run(conn, "PB-004", "DRY_RUN", actor="unit")
    with pytest.raises(ValueError, match="nothing to roll back"):
        automation.rollback_run(conn, run["run_id"], "lead@test", "x")


def test_rollback_run_unknown_raises(conn):
    with pytest.raises(LookupError):
        automation.rollback_run(conn, "RUN-999999", "lead@test", "x")


# ============================================
# 目标解析
# ============================================
def test_block_ip_targets_source_ip_not_entity(conn):
    """
    影子 IT 告警的实体是未授权服务名，但封禁要打的是来源 IP。
    把服务名传给防火墙 API 只会生成一条无效规则。
    """
    alert = conn.execute(
        "SELECT alert_id, entity_value, source_ip FROM alerts "
        "WHERE entity_value='MegaNz-Transfer' LIMIT 1").fetchone()
    if alert is None:
        pytest.skip("seed 中缺少 MegaNz-Transfer 告警")
    run = {"alert_id": alert["alert_id"]}
    assert automation._resolve_target(conn, run, "block_ip") == alert["source_ip"]


def test_user_actions_target_entity_value(conn):
    alert = conn.execute(
        "SELECT alert_id, entity_value FROM alerts "
        "WHERE rule_id='KQL-006' LIMIT 1").fetchone()
    run = {"alert_id": alert["alert_id"]}
    assert automation._resolve_target(conn, run, "reset_password") == alert["entity_value"]


def test_resolve_target_handles_missing_alert(conn):
    assert automation._resolve_target(conn, {"alert_id": None}, "reset_password") == "unknown"
    assert automation._resolve_target(conn, {"alert_id": "ALR-9999"}, "block_ip") == "unknown"


# ============================================
# 审批过期
# ============================================
def test_expire_stale_approvals_marks_expired(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    conn.execute("UPDATE approval_requests SET expires_at = '2000-01-01 00:00:00' "
                 "WHERE run_id = ?", (run["run_id"],))
    conn.commit()
    expired = automation.expire_stale_approvals(conn)
    assert expired >= 1
    row = conn.execute("SELECT decision FROM approval_requests WHERE run_id = ?",
                       (run["run_id"],)).fetchone()
    assert row["decision"] == "EXPIRED"


def test_expire_stale_approvals_cancels_run(conn):
    run = automation.start_run(conn, "PB-001", "LIVE", actor="unit")
    conn.execute("UPDATE approval_requests SET expires_at = '2000-01-01 00:00:00' "
                 "WHERE run_id = ?", (run["run_id"],))
    conn.commit()
    automation.expire_stale_approvals(conn)
    row = conn.execute("SELECT status FROM playbook_runs WHERE run_id = ?",
                       (run["run_id"],)).fetchone()
    assert row["status"] == "CANCELLED"


def test_expire_stale_approvals_ignores_fresh_requests(conn):
    before = conn.execute("SELECT COUNT(*) c FROM approval_requests "
                          "WHERE decision='PENDING'").fetchone()["c"]
    automation.expire_stale_approvals(conn)
    after = conn.execute("SELECT COUNT(*) c FROM approval_requests "
                         "WHERE decision='PENDING'").fetchone()["c"]
    assert before == after


# ============================================
# 审计
# ============================================
def test_run_start_is_audited(conn):
    run = automation.start_run(conn, "PB-004", "DRY_RUN", actor="auditor")
    n = conn.execute("SELECT COUNT(*) c FROM audit_log "
                     "WHERE action='run_start' AND entity_id=?",
                     (run["run_id"],)).fetchone()["c"]
    assert n == 1


def test_every_executed_step_is_audited(conn):
    run = automation.start_run(conn, "PB-004", "DRY_RUN", actor="auditor")
    n = conn.execute("SELECT COUNT(*) c FROM audit_log "
                     "WHERE action='execute_step' AND entity_id LIKE ?",
                     (f"{run['run_id']}%",)).fetchone()["c"]
    assert n == 4


def test_approval_is_audited_with_reason(conn):
    run = automation.start_run(conn, "PB-002", "LIVE", actor="unit")
    automation.approve_run(conn, run["run_id"], "irene@test", "确认真实攻击")
    row = conn.execute("SELECT details FROM audit_log WHERE action='approve' "
                       "AND entity_id=?", (run["run_id"],)).fetchone()
    assert "确认真实攻击" in row["details"]