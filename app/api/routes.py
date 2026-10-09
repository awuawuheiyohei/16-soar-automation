"""API 路由 —— SOAR 自动化响应平台"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Body, HTTPException, Query, Request

from ..models import automation, triage
from ..models.db import db_connection, row_to_dict, rows_to_dicts, write_audit
from ..models.formparse import parse_urlencoded

router = APIRouter(prefix="/api")

VALID_ALERT_STATUSES = ("NEW", "CORRELATED", "TRIAGED", "IN_PLAYBOOK",
                        "RESOLVED", "FALSE_POSITIVE")
VALID_FP_CATEGORIES = tuple(triage.REASON_CATEGORY_STRATEGY.keys())


def _http(fn, *args, **kwargs):
    """把引擎层的异常翻译成合适的 HTTP 状态码"""
    try:
        return fn(*args, **kwargs)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


# ============================================
# 健康检查 / 元信息
# ============================================
@router.get("/health")
def health():
    with db_connection() as conn:
        n_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        n_rules = conn.execute("SELECT COUNT(*) c FROM detection_rules").fetchone()["c"]
        n_runs = conn.execute("SELECT COUNT(*) c FROM playbook_runs").fetchone()["c"]
    return {
        "status": "ok",
        "service": "soar-automation-platform",
        "version": "1.0.0",
        "execution_mode": "SIMULATED (no real SIEM/SOAR/EDR/IdP integration)",
        "alerts": n_alerts,
        "detection_rules": n_rules,
        "playbook_runs": n_runs,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================
# Dashboard 总览
# ============================================
@router.get("/overview")
def overview():
    with db_connection() as conn:
        expired = automation.expire_stale_approvals(conn)

        by_status = {
            r["status"]: r["n"]
            for r in conn.execute("SELECT status, COUNT(*) n FROM alerts GROUP BY status")
        }
        by_priority = {
            r["priority_level"]: r["n"]
            for r in conn.execute(
                "SELECT priority_level, COUNT(*) n FROM alerts GROUP BY priority_level")
        }
        by_run_status = {
            r["status"]: r["n"]
            for r in conn.execute("SELECT status, COUNT(*) n FROM playbook_runs GROUP BY status")
        }
        action_stats = {
            r["status"]: r["n"]
            for r in conn.execute("SELECT status, COUNT(*) n FROM action_runs GROUP BY status")
        }

        pending_approvals = conn.execute(
            "SELECT COUNT(*) c FROM approval_requests WHERE decision = 'PENDING'"
        ).fetchone()["c"]

        fp_total = conn.execute(
            "SELECT COUNT(*) c FROM false_positive_feedback").fetchone()["c"]
        all_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

        top_alerts = rows_to_dicts(conn.execute(
            """SELECT alert_id, title, severity, entity_value, priority_score,
                      priority_level, status, rule_id
               FROM alerts WHERE status NOT IN ('FALSE_POSITIVE')
               ORDER BY priority_score DESC LIMIT 8"""))

        needs_tuning = rows_to_dicts(conn.execute(
            """SELECT dr.rule_id, dr.name, COUNT(a.alert_id) total_alerts,
                      (SELECT COUNT(*) FROM false_positive_feedback f
                        WHERE f.rule_id = dr.rule_id) false_positives
               FROM detection_rules dr
               JOIN alerts a ON a.rule_id = dr.rule_id
               GROUP BY dr.rule_id
               HAVING total_alerts >= 5
                  AND false_positives * 1.0 / total_alerts >= 0.3"""))

        recent_runs = rows_to_dicts(conn.execute(
            """SELECT r.run_id, r.playbook_id, p.name playbook_name, r.mode, r.status,
                      r.approved_by, r.summary, r.started_at, a.title alert_title
               FROM playbook_runs r
               JOIN playbooks p ON p.playbook_id = r.playbook_id
               LEFT JOIN alerts a ON a.alert_id = r.alert_id
               ORDER BY r.run_id DESC LIMIT 6"""))

    return {
        "alerts_by_status": by_status,
        "alerts_by_priority": by_priority,
        "runs_by_status": by_run_status,
        "action_steps_by_status": action_stats,
        "pending_approvals": pending_approvals,
        "approvals_expired_this_call": expired,
        "total_alerts": all_alerts,
        "false_positives": fp_total,
        "false_positive_rate": round(100.0 * fp_total / all_alerts, 1) if all_alerts else 0.0,
        "top_alerts": top_alerts,
        "rules_needing_tuning": needs_tuning,
        "recent_runs": recent_runs,
    }


# ============================================
# 检测规则
# ============================================
@router.get("/rules")
def list_rules():
    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(
            """SELECT dr.*,
                      (SELECT COUNT(*) FROM alerts a WHERE a.rule_id = dr.rule_id) alert_count,
                      (SELECT COUNT(*) FROM false_positive_feedback f
                        WHERE f.rule_id = dr.rule_id) false_positives
               FROM detection_rules dr ORDER BY dr.rule_id"""))
    for r in rows:
        with db_connection() as conn:
            r["fp_stats"] = triage.fp_rate_for_rule(conn, r["rule_id"])
    return {"count": len(rows), "rules": rows}


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM detection_rules WHERE rule_id = ?",
                           (rule_id,)).fetchone()
        if not row:
            raise HTTPException(404, f"rule {rule_id} not found")
        rule = dict(row)
        rule["tuning"] = triage.tuning_recommendations(conn, rule_id)
        rule["alerts"] = rows_to_dicts(conn.execute(
            "SELECT alert_id, title, severity, status, detected_at FROM alerts "
            "WHERE rule_id = ? ORDER BY detected_at DESC", (rule_id,)))
    return rule


# ============================================
# 告警摄取
# ============================================
@router.post("/alerts/ingest")
def ingest(payload: dict = Body(...)):
    """
    从 SIEM 摄取告警（演示为直接 POST JSON）。
    引擎会自动去重 → 建立关联 → 计算优先级 → 写审计。
    """
    required = ("rule_id", "entity_value")
    missing = [k for k in required if not payload.get(k)]
    if missing:
        raise HTTPException(400, f"missing required field(s): {missing}")

    actor = payload.get("actor", "siem-connector")
    with db_connection() as conn:
        try:
            result = triage.ingest_alert(conn, payload, actor=actor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        write_audit(conn, actor, "alert_ingest", "alert", result["alert_id"], {
            "rule_id": payload.get("rule_id"),
            "entity": payload.get("entity_value"),
            "deduplicated": result["deduplicated"],
            "priority": result["priority"],
        })
    return result


@router.get("/alerts")
def list_alerts(status: str | None = None, rule_id: str | None = None,
                priority_level: str | None = None, entity_type: str | None = None,
                search: str | None = None,
                limit: int = Query(100, ge=1, le=500),
                offset: int = Query(0, ge=0)):
    sql = """
        SELECT a.alert_id, a.rule_id, a.title, a.severity, a.entity_type, a.entity_value,
               a.source_ip, a.status, a.priority_score, a.priority_level, a.alert_count,
               a.detected_at, dr.name rule_name,
               (SELECT COUNT(*) FROM alert_correlations c
                 WHERE c.primary_alert_id = a.alert_id
                    OR c.related_alert_id = a.alert_id) correlation_count
        FROM alerts a
        JOIN detection_rules dr ON dr.rule_id = a.rule_id
        WHERE 1=1
    """
    args: list = []
    if status:
        sql += " AND a.status = ?"
        args.append(status.upper())
    if rule_id:
        sql += " AND a.rule_id = ?"
        args.append(rule_id)
    if priority_level:
        sql += " AND a.priority_level = ?"
        args.append(priority_level.upper())
    if entity_type:
        sql += " AND a.entity_type = ?"
        args.append(entity_type.upper())
    if search:
        sql += " AND (a.title LIKE ? OR a.entity_value LIKE ?)"
        args += [f"%{search}%", f"%{search}%"]
    sql += " ORDER BY a.priority_score DESC, a.alert_id LIMIT ? OFFSET ?"
    args += [limit, offset]

    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(sql, args).fetchall())
        total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    return {"count": len(rows), "total_alerts": total, "alerts": rows}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with db_connection() as conn:
        row = conn.execute(
            """SELECT a.*, dr.name rule_name, dr.tactic, dr.data_source,
                      dr.tuning_notes
               FROM alerts a JOIN detection_rules dr ON dr.rule_id = a.rule_id
               WHERE a.alert_id = ?""", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, f"alert {alert_id} not found")
        alert = dict(row)
        alert["raw_payload"] = json.loads(alert["raw_payload"]) if alert.get("raw_payload") else {}

        alert["correlations"] = rows_to_dicts(conn.execute(
            """SELECT c.*, a.title related_title, a.entity_value related_entity,
                      a.severity related_severity, a.priority_score related_priority
               FROM alert_correlations c
               JOIN alerts a ON a.alert_id = c.related_alert_id
               WHERE c.primary_alert_id = ?""", (alert_id,)))

        alert["playbook_runs"] = rows_to_dicts(conn.execute(
            """SELECT r.run_id, r.playbook_id, p.name playbook_name, r.mode, r.status,
                      r.approved_by, r.summary, r.started_at
               FROM playbook_runs r JOIN playbooks p ON p.playbook_id = r.playbook_id
               WHERE r.alert_id = ? ORDER BY r.run_id""", (alert_id,)))

        alert["false_positives"] = rows_to_dicts(conn.execute(
            "SELECT * FROM false_positive_feedback WHERE alert_id = ?", (alert_id,)))

        # 重算一遍评分明细用于 explain()
        calc = triage.calculate_priority(
            alert["severity"], alert["entity_type"], alert["entity_value"],
            triage.count_corroborating(conn, alert_id), alert["detected_at"])
        alert.update(calc)
        alert["explanation"] = triage.explain(alert)

    return alert


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, payload: dict = Body(...)):
    new_status = str(payload.get("status", "")).upper()
    note = payload.get("note", "")
    actor = payload.get("actor", "anonymous")

    if new_status not in VALID_ALERT_STATUSES:
        raise HTTPException(400, f"invalid status: {new_status}. valid={VALID_ALERT_STATUSES}")

    with db_connection() as conn:
        prev = conn.execute("SELECT status FROM alerts WHERE alert_id = ?",
                            (alert_id,)).fetchone()
        if not prev:
            raise HTTPException(404, f"alert {alert_id} not found")

        conn.execute(
            """UPDATE alerts SET status = ?, analyst_note = ?,
                                 triaged_at = COALESCE(triaged_at, datetime('now')),
                                 resolved_at = CASE WHEN ? IN ('RESOLVED','FALSE_POSITIVE')
                                                   THEN datetime('now') ELSE resolved_at END
               WHERE alert_id = ?""",
            (new_status, note or None, new_status, alert_id),
        )
        conn.commit()
        write_audit(conn, actor, "status_change", "alert", alert_id,
                    {"from": prev["status"], "to": new_status, "note": note})

    return {"updated": True, "alert_id": alert_id, "status": new_status}


# ============================================
# 误报治理
# ============================================
@router.post("/alerts/{alert_id}/false-positive")
def report_false_positive(alert_id: str, payload: dict = Body(...)):
    """
    标记误报，并把调优建议回写到该规则。
    这是 SOAR 与 SIEM 之间的闭环：告警质量必须能被度量，否则自动化只会放大噪音。
    """
    category = str(payload.get("reason_category", "")).upper()
    if category not in VALID_FP_CATEGORIES:
        raise HTTPException(400,
                            f"invalid reason_category: {category}. valid={VALID_FP_CATEGORIES}")

    actor = payload.get("actor", "soc-analyst")
    threshold = payload.get("recommended_threshold")

    with db_connection() as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not alert:
            raise HTTPException(404, f"alert {alert_id} not found")

        n = conn.execute("SELECT COUNT(*) c FROM false_positive_feedback").fetchone()["c"]
        fp_id = f"FP-{n + 1:04d}"
        conn.execute(
            """INSERT INTO false_positive_feedback
               (fp_id, alert_id, rule_id, reported_by, reason_category, reason_text,
                suppression_target, recommended_threshold)
               VALUES (?,?,?,?,?,?,?,?)""",
            (fp_id, alert_id, alert["rule_id"], actor, category,
             payload.get("reason_text"), payload.get("suppression_target"),
             float(threshold) if threshold is not None else None),
        )
        conn.execute(
            "UPDATE alerts SET status='FALSE_POSITIVE', analyst_note=?, "
            "resolved_at=datetime('now') WHERE alert_id = ?",
            (payload.get("reason_text"), alert_id),
        )
        conn.commit()

        write_audit(conn, actor, "false_positive_reported", "alert", alert_id, {
            "fp_id": fp_id, "rule_id": alert["rule_id"], "reason_category": category,
        })
        tuning = triage.tuning_recommendations(conn, alert["rule_id"])

    return {"fp_id": fp_id, "alert_id": alert_id, "rule_tuning": tuning}


@router.get("/false-positives")
def list_false_positives(rule_id: str | None = None):
    sql = """SELECT f.*, a.title alert_title, a.entity_value, dr.name rule_name
             FROM false_positive_feedback f
             JOIN alerts a ON a.alert_id = f.alert_id
             JOIN detection_rules dr ON dr.rule_id = f.rule_id"""
    args: list = []
    if rule_id:
        sql += " WHERE f.rule_id = ?"
        args.append(rule_id)
    sql += " ORDER BY f.fp_id"

    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(sql, args).fetchall())
        by_category = rows_to_dicts(conn.execute(
            """SELECT reason_category, COUNT(*) n FROM false_positive_feedback
               GROUP BY reason_category ORDER BY n DESC"""))
    return {"count": len(rows), "feedback": rows, "by_category": by_category}


@router.get("/tuning")
def tuning_overview():
    """每条检测规则的误报率与调优建议"""
    with db_connection() as conn:
        rule_ids = [r["rule_id"] for r in conn.execute(
            "SELECT rule_id FROM detection_rules ORDER BY rule_id")]
        out = [triage.tuning_recommendations(conn, rid) for rid in rule_ids]
    return {"count": len(out), "tuning": out}


# ============================================
# Playbook
# ============================================
@router.get("/playbooks")
def list_playbooks():
    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(
            """SELECT p.*,
                      (SELECT COUNT(*) FROM playbook_actions a
                        WHERE a.playbook_id = p.playbook_id) action_count,
                      (SELECT COUNT(*) FROM playbook_actions a
                        WHERE a.playbook_id = p.playbook_id AND a.requires_approval = 1)
                        approval_gated_actions,
                      (SELECT COUNT(*) FROM playbook_actions a
                        WHERE a.playbook_id = p.playbook_id AND a.is_destructive = 1)
                        destructive_actions,
                      (SELECT COUNT(*) FROM playbook_runs r
                        WHERE r.playbook_id = p.playbook_id) run_count
               FROM playbooks p ORDER BY p.playbook_id"""))
    return {"count": len(rows), "playbooks": rows}


@router.get("/playbooks/{playbook_id}")
def get_playbook(playbook_id: str):
    with db_connection() as conn:
        pb = conn.execute("SELECT * FROM playbooks WHERE playbook_id = ?",
                          (playbook_id,)).fetchone()
        if not pb:
            raise HTTPException(404, f"playbook {playbook_id} not found")
        detail = dict(pb)
        detail["actions"] = automation.playbook_actions(conn, playbook_id)
        detail["requires_approval"] = automation.playbook_requires_approval(conn, playbook_id)
        for a in detail["actions"]:
            spec = automation.ACTION_TYPES.get(a["action_type"], {})
            a["action_spec"] = spec
            a["simulated_connector"] = automation.SIMULATED_CONNECTORS.get(a["action_type"])
    return detail


@router.post("/playbooks/{playbook_id}/run")
def run_playbook(playbook_id: str, payload: dict = Body(...)):
    """
    触发一次 playbook 执行。
    body: {"mode": "DRY_RUN"|"LIVE", "alert_id": "ALR-0001", "actor": "...", "reason": "..."}

    mode=LIVE 且 playbook 含需审批步骤时，本次调用只创建 run 并挂起审批，
    **不会执行任何步骤**；必须调 /api/runs/{run_id}/approve 之后才会真正执行。
    """
    mode = str(payload.get("mode", "DRY_RUN")).upper()
    alert_id = payload.get("alert_id")
    actor = payload.get("actor", "analyst")
    reason = payload.get("reason", "")

    with db_connection() as conn:
        run = _http(automation.start_run, conn, playbook_id, mode, alert_id, actor, reason)
    return run


# ============================================
# 执行实例
# ============================================
@router.get("/runs")
def list_runs(status: str | None = None, mode: str | None = None,
              playbook_id: str | None = None,
              limit: int = Query(100, ge=1, le=500)):
    sql = """SELECT r.run_id, r.playbook_id, p.name playbook_name, r.alert_id, r.mode,
                    r.status, r.triggered_by, r.approved_by, r.rolled_back_from,
                    r.steps_total, r.steps_succeeded, r.steps_failed, r.steps_skipped,
                    r.summary, r.started_at, r.finished_at, a.title alert_title,
                    a.severity alert_severity
             FROM playbook_runs r
             JOIN playbooks p ON p.playbook_id = r.playbook_id
             LEFT JOIN alerts a ON a.alert_id = r.alert_id WHERE 1=1"""
    args: list = []
    if status:
        sql += " AND r.status = ?"
        args.append(status.upper())
    if mode:
        sql += " AND r.mode = ?"
        args.append(mode.upper())
    if playbook_id:
        sql += " AND r.playbook_id = ?"
        args.append(playbook_id)
    sql += " ORDER BY r.run_id LIMIT ?"
    args.append(limit)

    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(sql, args).fetchall())
    return {"count": len(rows), "runs": rows}


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    with db_connection() as conn:
        run = automation.run_detail(conn, run_id)
        if not run:
            raise HTTPException(404, f"run {run_id} not found")
        run["approvals"] = rows_to_dicts(conn.execute(
            "SELECT * FROM approval_requests WHERE run_id = ? ORDER BY approval_id",
            (run_id,)))
        # execute_step / rollback_step 的 entity_id 是 "<run_id>#<step>"，
        # 只用等值匹配会漏掉每一步的审计记录，全链路审计就成了残缺的。
        run["audit"] = rows_to_dicts(conn.execute(
            "SELECT * FROM audit_log WHERE entity_id = ? OR entity_id LIKE ? "
            "ORDER BY audit_id", (run_id, f"{run_id}#%")))
    return run


@router.post("/runs/{run_id}/approve")
def approve(run_id: str, payload: dict = Body(...)):
    approver = payload.get("approver") or payload.get("actor")
    reason = payload.get("reason", "")
    if not approver:
        raise HTTPException(400, "approver is required")

    with db_connection() as conn:
        run = _http(automation.approve_run, conn, run_id, approver, reason)
    return run


@router.post("/runs/{run_id}/reject")
def reject(run_id: str, payload: dict = Body(...)):
    approver = payload.get("approver") or payload.get("actor")
    reason = payload.get("reason", "")
    if not approver:
        raise HTTPException(400, "approver is required")

    with db_connection() as conn:
        run = _http(automation.reject_run, conn, run_id, approver, reason)
    return run


@router.post("/runs/{run_id}/execute")
def execute(run_id: str, payload: dict = Body(default={})):
    """
    手动触发执行。对没有审批门、审批已通过、或 DRY_RUN 的 run 有意义。
    对已完成/已终止的 run 是幂等的 —— 不会重复执行任何步骤。
    """
    actor = payload.get("actor", "analyst")
    with db_connection() as conn:
        run = _http(automation.execute_run, conn, run_id, actor)
    return run


@router.post("/runs/{run_id}/rollback")
def rollback(run_id: str, payload: dict = Body(default={})):
    """对已完成的 LIVE run 手动发起补偿（新建 run，rolled_back_from 指向原 run）"""
    actor = payload.get("actor", "soc-lead")
    reason = payload.get("reason", "")
    with db_connection() as conn:
        run = _http(automation.rollback_run, conn, run_id, actor, reason)
    return run


@router.post("/runs/{run_id}/approval-form")
async def approve_via_form(run_id: str, request: Request):
    """
    同一个审批动作的 url-encoded 表单版本。
    手写解析 application/x-www-form-urlencoded，避免为了解析几个键值对
    而引入 python-multipart 依赖。
    """
    ctype = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in ctype:
        raise HTTPException(415,
                            "expected Content-Type: application/x-www-form-urlencoded")

    form = parse_urlencoded(await request.body())
    approver = form.get("approver") or form.get("actor")
    reason = form.get("reason", "")
    if not approver:
        raise HTTPException(400, "approver is required")

    with db_connection() as conn:
        run = _http(automation.approve_run, conn, run_id, approver, reason)
    return run


# ============================================
# 审批队列
# ============================================
@router.get("/approvals")
def list_approvals(decision: str | None = None, limit: int = Query(100, ge=1, le=500)):
    sql = """SELECT ap.*, p.name playbook_name, a.title alert_title, a.severity alert_severity,
                    (SELECT GROUP_CONCAT(pa.action_type)
                       FROM playbook_actions pa
                      WHERE pa.playbook_id = r.playbook_id AND pa.requires_approval = 1)
                    gated_action_types
             FROM approval_requests ap
             JOIN playbook_runs r ON r.run_id = ap.run_id
             JOIN playbooks p ON p.playbook_id = r.playbook_id
             LEFT JOIN alerts a ON a.alert_id = r.alert_id WHERE 1=1"""
    args: list = []
    if decision:
        sql += " AND ap.decision = ?"
        args.append(decision.upper())
    sql += " ORDER BY ap.approval_id LIMIT ?"
    args.append(limit)

    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(sql, args).fetchall())
        counts = {
            r["decision"]: r["n"]
            for r in conn.execute(
                "SELECT decision, COUNT(*) n FROM approval_requests GROUP BY decision")
        }
    return {"count": len(rows), "approvals": rows, "by_decision": counts}


# ============================================
# 审计
# ============================================
@router.get("/audit")
def list_audit(entity_type: str | None = None, entity_id: str | None = None,
               action: str | None = None,
               limit: int = Query(200, ge=1, le=1000)):
    sql = "SELECT * FROM audit_log WHERE 1=1"
    args: list = []
    if entity_type:
        sql += " AND entity_type = ?"
        args.append(entity_type)
    if entity_id:
        sql += " AND entity_id = ?"
        args.append(entity_id)
    if action:
        sql += " AND action LIKE ?"
        args.append(f"{action}%")
    sql += " ORDER BY audit_id DESC LIMIT ?"
    args.append(limit)

    with db_connection() as conn:
        rows = rows_to_dicts(conn.execute(sql, args).fetchall())
        total = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
    for r in rows:
        if r.get("details"):
            try:
                r["details"] = json.loads(r["details"])
            except (ValueError, TypeError):
                pass
    return {"count": len(rows), "total_entries": total, "entries": rows}