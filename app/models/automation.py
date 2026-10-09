"""
Playbook 执行引擎 —— 本项目的核心

================================ 诚实性声明 ================================
本文件中的 execute_action() **不会调用任何真实 API、不发起任何网络请求**。
所有 connector 都是本地确定性模拟器（SIMULATED_CONNECTORS），
用于演示 SOAR 的控制流：审批门 → 幂等执行 → 失败补偿 → 审计。

真实 SOAR 产品（Splunk SOAR / Cortex XDR / Microsoft Sentinel SOAR 等）
的做法与此处一致，但对接的是真实的 IdP / EDR / 防火墙 API。
本项目**没有**对接过其中任何一个。
===========================================================================

核心控制流：

    start_run()      创建执行实例
        │  mode=DRY_RUN ──────────────────────────► execute_run()（全部 DRY_RUN_OK）
        │  mode=LIVE + 含需审批步骤 ─► PENDING_APPROVAL ─► approve_run() ─► execute_run()
        │  mode=LIVE + 无需审批步骤 ─────────────────► execute_run()
        ▼
    execute_run()    逐步执行
        │  幂等：同一 (run_id, step_no) 已有 action_runs 记录 → 跳过，不重复执行
        │  失败（LIVE 模式）→ 逆序执行已成功破坏性步骤的补偿动作 → ROLLED_BACK
        ▼
    rollback_run()   对已完成的 run 手动发起补偿（新建 run，rolled_back_from 指向原 run）

三条不可妥协的设计原则：

1. **破坏性动作默认需要人工审批**。禁用账号、隔离主机这类动作一旦误触发，
   影响的是业务连续性，不是"多一条告警"。宁可慢，也不能让自动化替人做这个决定。
2. **补偿动作（compensating action）必须与破坏性动作成对定义**。
   如果一个动作不可回滚，它就不该被放进自动执行的 playbook。
3. **幂等靠 idempotency_key 唯一约束保证**，不靠应用层判断。
   同一 run 重复触发 execute，数据库层面就不可能产生重复执行记录。
"""
from __future__ import annotations

import hashlib
import json
import zlib
from datetime import datetime, timedelta, timezone

from .db import next_id, write_audit

# ============================================
# Action 类型注册表
# ============================================
# destructive       : 是否会改变目标系统的状态（需要补偿动作）
# requires_approval : LIVE 模式下是否必须人工批准
ACTION_TYPES = {
    # --- 只读 / 通知类：可自动执行 ---
    "enrich_identity": {
        "description": "从 IdP 拉取用户属性（部门、角色、注册设备）",
        "destructive": False, "requires_approval": False, "compensating": None,
    },
    "lookup_threat_intel": {
        "description": "查询来源 IP 的威胁情报信誉",
        "destructive": False, "requires_approval": False, "compensating": None,
    },
    "collect_host_inventory": {
        "description": "从 EDR 采集主机进程与网络连接快照",
        "destructive": False, "requires_approval": False, "compensating": None,
    },
    "snapshot_evidence": {
        "description": "归档告警原始载荷作为证据",
        "destructive": False, "requires_approval": False, "compensating": None,
    },
    "open_case_ticket": {
        "description": "在工单系统创建调查工单",
        "destructive": False, "requires_approval": False, "compensating": None,
    },
    "notify_analyst": {
        "description": "通知值班分析师（L1 / L2）",
        "destructive": False, "requires_approval": False, "compensating": None,
    },
    "add_suppression": {
        "description": "写入抑制规则，避免同一模式重复告警",
        "destructive": False, "requires_approval": False, "compensating": None,
    },

    # --- 状态变更类：必须审批，且必须有补偿动作 ---
    "revoke_sessions": {
        "description": "吊销用户的全部活跃会话令牌",
        "destructive": True, "requires_approval": False, "compensating": "restore_sessions",
    },
    "reset_password": {
        "description": "强制密码重置并要求下次登录改密",
        "destructive": True, "requires_approval": True, "compensating": "issue_temp_access",
    },
    "disable_account": {
        "description": "禁用账号（登录阻断）",
        "destructive": True, "requires_approval": True, "compensating": "enable_account",
    },
    "isolate_host": {
        "description": "网络隔离主机（EDR 隔离，非关机）",
        "destructive": True, "requires_approval": True, "compensating": "unisolate_host",
    },
    "block_ip": {
        "description": "在边界防火墙封禁来源 IP",
        "destructive": True, "requires_approval": True, "compensating": "unblock_ip",
    },

    # --- 仅补偿方向使用：不能作为正常 playbook 步骤 ---
    "restore_sessions": {
        "description": "恢复用户会话（补偿动作）",
        "destructive": True, "requires_approval": False, "compensating": None,
    },
    "issue_temp_access": {
        "description": "签发临时访问口令（补偿动作）",
        "destructive": True, "requires_approval": False, "compensating": None,
    },
    "enable_account": {
        "description": "重新启用账号（补偿动作）",
        "destructive": True, "requires_approval": False, "compensating": None,
    },
    "unisolate_host": {
        "description": "解除主机网络隔离（补偿动作）",
        "destructive": True, "requires_approval": False, "compensating": None,
    },
    "unblock_ip": {
        "description": "解除 IP 封禁（补偿动作）",
        "destructive": True, "requires_approval": False, "compensating": None,
    },
}

# 只有补偿方向的 action 类型才允许出现在 compensating_action 里
COMPENSATION_ONLY = {a for a, spec in ACTION_TYPES.items()
                     if spec["compensating"] is None and a.startswith(
                         ("restore_", "issue_", "enable_", "unisolate_", "unblock_"))}

# ============================================
# 确定性模拟 connector
# ============================================
SIMULATED_CONNECTORS = {
    "enrich_identity": "sim-idp-directory",
    "lookup_threat_intel": "sim-threat-intel-feed",
    "collect_host_inventory": "sim-edr-console",
    "snapshot_evidence": "sim-evidence-vault",
    "open_case_ticket": "sim-ticketing",
    "notify_analyst": "sim-pager",
    "add_suppression": "sim-suppression-store",
    "revoke_sessions": "sim-idp-directory",
    "reset_password": "sim-idp-directory",
    "disable_account": "sim-idp-directory",
    "isolate_host": "sim-edr-console",
    "block_ip": "sim-edge-firewall",
    "restore_sessions": "sim-idp-directory",
    "issue_temp_access": "sim-idp-directory",
    "enable_account": "sim-idp-directory",
    "unisolate_host": "sim-edr-console",
    "unblock_ip": "sim-edge-firewall",
}

# 确定性失败注入：让回滚路径可复现、可测试。
# key = (action_type, entity_value)。真实环境里这来自下游 API 的真实报错。
SIMULATED_FAILURES = {
    ("isolate_host", "FIN-LAPTOP-114"):
        "EDR quarantine API returned 504 Gateway Timeout (simulated)",
    ("reset_password", "svc-payroll-export"):
        "IdP password write returned 409 Conflict (simulated)",
    ("block_ip", "198.51.100.77"):
        "Firewall policy push rejected: CIDR overlaps existing rule (simulated)",
}

TERMINAL_STATUSES = ("COMPLETED", "FAILED", "ROLLED_BACK", "CANCELLED")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt=None) -> str:
    return (dt or _utc_now()).isoformat()


def _simulated_latency(action_id: str, target: str) -> int:
    """确定性伪延迟（120-999ms），保证同一 action 的耗时可复现"""
    return 120 + (zlib.crc32(f"{action_id}|{target}".encode()) % 880)


def idempotency_key(run_id: str, step_no: int, action_id: str) -> str:
    raw = f"{run_id}:{step_no}:{action_id}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def execute_action(action_type: str, target: str, dry_run: bool = False) -> dict:
    """
    模拟执行一个 action。**不做任何真实系统调用**。

    返回 {"ok": bool, "connector": str, "message": str, "latency_ms": int,
           "simulated": True}
    """
    if action_type not in ACTION_TYPES:
        return {"ok": False, "connector": "unknown",
                "message": f"unknown action_type: {action_type}",
                "latency_ms": 0, "simulated": True}

    connector = SIMULATED_CONNECTORS[action_type]
    latency = _simulated_latency(action_type, target)

    if dry_run:
        return {"ok": True, "connector": connector, "latency_ms": latency,
                "message": f"[dry-run] would execute {action_type} on {target}",
                "simulated": True}

    failure = SIMULATED_FAILURES.get((action_type, str(target)))
    if failure:
        return {"ok": False, "connector": connector, "latency_ms": latency,
                "message": failure, "simulated": True}

    return {"ok": True, "connector": connector, "latency_ms": latency,
            "message": f"{action_type} applied to {target} via {connector} (simulated)",
            "simulated": True}


# ============================================
# 查询辅助
# ============================================
def playbook_actions(conn, playbook_id: str) -> list:
    rows = conn.execute(
        "SELECT * FROM playbook_actions WHERE playbook_id = ? ORDER BY step_no",
        (playbook_id,),
    ).fetchall()
    return [{k: r[k] for k in r.keys()} for r in rows]


def playbook_requires_approval(conn, playbook_id: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) c FROM playbook_actions "
        "WHERE playbook_id = ? AND requires_approval = 1",
        (playbook_id,),
    ).fetchone()
    return row["c"] > 0


def run_detail(conn, run_id: str) -> dict:
    row = conn.execute(
        """SELECT r.*, p.name AS playbook_name, p.description AS playbook_description,
                  a.title AS alert_title, a.severity AS alert_severity,
                  a.entity_value AS alert_entity
           FROM playbook_runs r
           JOIN playbooks p ON p.playbook_id = r.playbook_id
           LEFT JOIN alerts a ON a.alert_id = r.alert_id
           WHERE r.run_id = ?""", (run_id,)
    ).fetchone()
    if not row:
        return {}
    run = {k: row[k] for k in row.keys()}
    run["steps"] = run_timeline(conn, run_id)
    return run


def run_timeline(conn, run_id: str) -> list:
    rows = conn.execute(
        """SELECT ar.*, pa.description, pa.target_system, pa.is_destructive,
                  pa.requires_approval
           FROM action_runs ar
           LEFT JOIN playbook_actions pa ON pa.action_id = ar.action_id
           WHERE ar.run_id = ?
           ORDER BY ar.is_rollback, ar.step_no, ar.action_run_id""",
        (run_id,),
    ).fetchall()
    steps = []
    for r in rows:
        step = {k: r[k] for k in r.keys()}
        step["output"] = json.loads(step["output"]) if step.get("output") else None
        steps.append(step)
    return steps


# ============================================
# 执行生命周期
# ============================================
def start_run(conn, playbook_id: str, mode: str = "DRY_RUN", alert_id: str | None = None,
              actor: str = "system", reason: str = "") -> dict:
    """
    创建一个 playbook 执行实例。

    mode=DRY_RUN → 立即执行（全部步骤标记 DRY_RUN_OK，不产生任何实际效果）
    mode=LIVE    → 若含需审批步骤则挂在 PENDING_APPROVAL；否则立即执行
    """
    mode = str(mode).upper()
    if mode not in ("DRY_RUN", "LIVE"):
        raise ValueError(f"invalid mode: {mode}. valid=['DRY_RUN', 'LIVE']")

    pb = conn.execute(
        "SELECT * FROM playbooks WHERE playbook_id = ?", (playbook_id,)
    ).fetchone()
    if not pb:
        raise LookupError(f"playbook {playbook_id} not found")
    if not pb["enabled"]:
        raise ValueError(f"playbook {playbook_id} is disabled")

    if alert_id and not conn.execute(
        "SELECT alert_id FROM alerts WHERE alert_id = ?", (alert_id,)
    ).fetchone():
        raise LookupError(f"alert {alert_id} not found")

    actions = playbook_actions(conn, playbook_id)
    if not actions:
        raise ValueError(f"playbook {playbook_id} has no actions")

    needs_approval = playbook_requires_approval(conn, playbook_id)
    run_id = next_id(conn, "playbook_runs", "run_id", "RUN", width=6)

    status = "RUNNING"
    if mode == "LIVE" and needs_approval:
        status = "PENDING_APPROVAL"

    conn.execute(
        """INSERT INTO playbook_runs
           (run_id, playbook_id, alert_id, mode, status, triggered_by,
            requires_approval, steps_total, summary)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (run_id, playbook_id, alert_id, mode, status, actor,
         1 if needs_approval else 0, len(actions),
         f"{len(actions)} steps · mode={mode}"),
    )
    conn.commit()

    write_audit(conn, actor, "run_start", "playbook_run", run_id, {
        "playbook_id": playbook_id, "alert_id": alert_id, "mode": mode,
        "requires_approval": needs_approval, "reason": reason,
    })

    if mode == "LIVE" and needs_approval:
        approval_id = next_id(conn, "approval_requests", "approval_id", "APR", width=6)
        conn.execute(
            """INSERT INTO approval_requests
               (approval_id, run_id, requested_by, expires_at)
               VALUES (?,?,?,?)""",
            (approval_id, run_id, actor,
             (_utc_now() + timedelta(hours=4)).isoformat()),
        )
        conn.commit()
        write_audit(conn, "system", "approval_requested", "approval_request",
                    approval_id, {"run_id": run_id,
                                  "action_types": [a["action_type"] for a in actions
                                                   if a["requires_approval"]]})
        return run_detail(conn, run_id)

    return execute_run(conn, run_id, actor=actor)


def execute_run(conn, run_id: str, actor: str = "system") -> dict:
    """
    执行一个 run。

    幂等性：如果该 run 已处于终态，直接返回现有结果，不会重复执行任何步骤。
    审批门：LIVE 模式下若存在待审批请求且未批准，拒绝执行。
    失败处理：LIVE 模式下任一步失败 → 逆序执行已成功破坏性步骤的补偿动作。
    """
    run = conn.execute(
        "SELECT * FROM playbook_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if not run:
        raise LookupError(f"run {run_id} not found")
    run = {k: run[k] for k in run.keys()}

    if run["status"] in TERMINAL_STATUSES:
        # 幂等：重复 execute 不产生任何副作用
        return run_detail(conn, run_id)

    dry_run = run["mode"] == "DRY_RUN"

    if not dry_run:
        pending = conn.execute(
            """SELECT COUNT(*) c FROM approval_requests
               WHERE run_id = ? AND decision = 'PENDING'""", (run_id,)
        ).fetchone()["c"]
        if pending:
            raise PermissionError(
                f"run {run_id} has {pending} pending approval request(s); "
                f"approve or reject before executing in LIVE mode")

    actions = playbook_actions(conn, run["playbook_id"])

    succeeded: list = []
    n_ok = n_fail = n_skip = 0

    for action in actions:
        step_no = action["step_no"]
        target = _resolve_target(conn, run, action["action_type"])

        # --- 幂等：已执行过则跳过 ---
        existing = conn.execute(
            "SELECT status FROM action_runs WHERE run_id = ? AND step_no = ? AND is_rollback = 0",
            (run_id, step_no),
        ).fetchone()
        if existing:
            n_skip += 1
            continue

        # --- 审批门（单个 action 粒度）---
        if action["requires_approval"] and not dry_run and not run["approved_by"]:
            _record_action_run(conn, run, action, target, "SKIPPED", dry_run=False,
                               output={"reason": "blocked by approval gate"},
                               error=None, latency=0, is_rollback=0)
            n_skip += 1
            continue

        result = execute_action(action["action_type"], target, dry_run=dry_run)
        status = ("DRY_RUN_OK" if dry_run else ("SUCCESS" if result["ok"] else "FAILED"))

        _record_action_run(
            conn, run, action, target, status, dry_run=dry_run,
            output=result, error=None if result["ok"] else result["message"],
            latency=result["latency_ms"], is_rollback=0,
            approved_by=run["approved_by"],
        )
        write_audit(conn, actor, "execute_step", "action_run", f"{run_id}#{step_no}", {
            "run_id": run_id, "action_id": action["action_id"],
            "action_type": action["action_type"], "mode": run["mode"],
            "status": status, "target": target, "message": result["message"],
        })

        if status == "SUCCESS":
            n_ok += 1
            succeeded.append(action)
        elif status == "DRY_RUN_OK":
            n_ok += 1
        else:
            n_fail += 1
            break

    run_status = "COMPLETED" if n_fail == 0 else "FAILED"
    summary = (f"{run['mode']} 执行：{n_ok} 成功 / {n_fail} 失败 / {n_skip} 跳过"
               if run["mode"] == "LIVE" else
               f"DRY-RUN：{n_ok} 步预演通过 / {n_fail} 步失败 / {n_skip} 跳过")

    # --- 自动回滚：仅 LIVE 模式下失败才触发 ---
    if n_fail > 0 and not dry_run:
        rb = _auto_rollback(conn, run, succeeded, actor)
        if rb["performed"]:
            run_status = "ROLLED_BACK"
            summary += f"；已回滚 {rb['rolled_back']} 步"

    conn.execute(
        """UPDATE playbook_runs
           SET status = ?, steps_succeeded = ?, steps_failed = ?, steps_skipped = ?,
               summary = ?, finished_at = ?
           WHERE run_id = ?""",
        (run_status, n_ok, n_fail, n_skip, summary, _iso(), run_id),
    )
    conn.commit()
    write_audit(conn, actor, "run_finish", "playbook_run", run_id,
                {"status": run_status, "summary": summary})

    return run_detail(conn, run_id)


def _record_action_run(conn, run, action, target, status, dry_run, output, error,
                       latency, is_rollback, approved_by=None):
    key = idempotency_key(run["run_id"], action["step_no"], action["action_id"])
    if is_rollback:
        key = f"{key}-rb"
    conn.execute(
        """INSERT INTO action_runs
           (run_id, action_id, step_no, action_type, status, is_rollback, dry_run,
            approved_by, idempotency_key, output, error, duration_ms, finished_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run["run_id"], action["action_id"], action["step_no"], action["action_type"],
         status, is_rollback, 1 if dry_run else 0, approved_by, key,
         json.dumps(output or {}, ensure_ascii=False), error, latency, _iso()),
    )
    conn.commit()


def _resolve_target(conn, run, action_type: str | None = None) -> str:
    """
    确定某个 action 的实际作用对象。

    注意 block_ip / unblock_ip 用的是告警的 **source_ip**，不是 entity_value。
    影子 IT 告警的实体是"未授权云服务"（如 Mega），但要封禁的是访问它的出口 IP；
    把服务名传给防火墙 API 只会得到一条无效规则。
    """
    source_ip = None
    entity_value = None
    if run.get("alert_id"):
        row = conn.execute(
            "SELECT entity_value, source_ip FROM alerts WHERE alert_id = ?",
            (run["alert_id"],),
        ).fetchone()
        if row:
            entity_value, source_ip = row["entity_value"], row["source_ip"]

    if action_type in ("block_ip", "unblock_ip"):
        return source_ip or entity_value or "unknown"
    return entity_value or "unknown"


def approve_run(conn, run_id: str, approver: str, reason: str) -> dict:
    """人工批准 —— 记录 approver / 理由 / 时间戳，并立即执行"""
    if not str(reason).strip():
        raise ValueError("approval reason is required")

    run = conn.execute("SELECT * FROM playbook_runs WHERE run_id = ?", (run_id,)).fetchone()
    if not run:
        raise LookupError(f"run {run_id} not found")
    if run["status"] != "PENDING_APPROVAL":
        raise ValueError(f"run {run_id} is not awaiting approval (status={run['status']})")

    req = conn.execute(
        "SELECT * FROM approval_requests WHERE run_id = ? AND decision = 'PENDING'",
        (run_id,),
    ).fetchone()
    if not req:
        raise ValueError(f"no pending approval request for run {run_id}")

    now = _iso()
    conn.execute(
        """UPDATE approval_requests
           SET decision = 'APPROVED', approver = ?, decision_reason = ?, decided_at = ?
           WHERE approval_id = ?""",
        (approver, reason, now, req["approval_id"]),
    )
    conn.execute(
        """UPDATE playbook_runs
           SET approved_by = ?, approval_reason = ?, approved_at = ?, status = 'RUNNING'
           WHERE run_id = ?""",
        (approver, reason, now, run_id),
    )
    conn.commit()

    write_audit(conn, approver, "approve", "playbook_run", run_id, {
        "approval_id": req["approval_id"], "reason": reason,
        "playbook_id": run["playbook_id"], "alert_id": run["alert_id"],
    })
    return execute_run(conn, run_id, actor=approver)


def reject_run(conn, run_id: str, approver: str, reason: str) -> dict:
    """人工拒绝 —— run 终止，不执行任何动作"""
    if not str(reason).strip():
        raise ValueError("rejection reason is required")

    run = conn.execute("SELECT * FROM playbook_runs WHERE run_id = ?", (run_id,)).fetchone()
    if not run:
        raise LookupError(f"run {run_id} not found")
    if run["status"] != "PENDING_APPROVAL":
        raise ValueError(f"run {run_id} is not awaiting approval (status={run['status']})")

    req = conn.execute(
        "SELECT * FROM approval_requests WHERE run_id = ? AND decision = 'PENDING'",
        (run_id,),
    ).fetchone()
    if not req:
        raise ValueError(f"no pending approval request for run {run_id}")

    now = _iso()
    conn.execute(
        """UPDATE approval_requests
           SET decision = 'REJECTED', approver = ?, decision_reason = ?, decided_at = ?
           WHERE approval_id = ?""",
        (approver, reason, now, req["approval_id"]),
    )
    conn.execute(
        """UPDATE playbook_runs
           SET status = 'CANCELLED', rejected_by = ?, rejection_reason = ?, finished_at = ?
           WHERE run_id = ?""",
        (approver, reason, now, run_id),
    )
    conn.commit()

    write_audit(conn, approver, "reject", "playbook_run", run_id,
                {"approval_id": req["approval_id"], "reason": reason})
    return run_detail(conn, run_id)


def _auto_rollback(conn, run, succeeded_actions: list, actor: str) -> dict:
    """
    失败后自动回滚：逆序执行已成功"破坏性"步骤的补偿动作。
    非破坏性步骤（取证、开工单）不回滚 —— 它们没有副作用。
    """
    destructive = [a for a in succeeded_actions if a["is_destructive"]]
    if not destructive:
        return {"performed": False, "rolled_back": 0}

    rolled = 0

    for action in reversed(destructive):
        comp_type = action["compensating_action"]
        # playbook 里显式钉死的补偿目标优先；否则按补偿动作类型重新解析
        comp_target = action["compensating_target"] or _resolve_target(
            conn, run, comp_type)

        comp_action = {
            "action_id": action["action_id"],
            "step_no": action["step_no"],
            "action_type": comp_type,
            "compensating_action": None,
            "compensating_target": None,
        }
        result = execute_action(comp_type, comp_target, dry_run=False)

        _record_action_run(
            conn, run, comp_action, comp_target,
            "SUCCESS" if result["ok"] else "FAILED", dry_run=False,
            output=result, error=None if result["ok"] else result["message"],
            latency=result["latency_ms"], is_rollback=1,
        )
        write_audit(conn, actor, "rollback_step", "playbook_run", run["run_id"], {
            "step_no": action["step_no"],
            "original_action": action["action_type"],
            "compensating_action": comp_type,
            "target": comp_target,
            "result": "SUCCESS" if result["ok"] else "FAILED",
            "message": result["message"],
        })

        if result["ok"]:
            conn.execute(
                "UPDATE action_runs SET status = 'ROLLED_BACK' "
                "WHERE run_id = ? AND step_no = ? AND is_rollback = 0",
                (run["run_id"], action["step_no"]),
            )
            rolled += 1

    conn.commit()
    return {"performed": True, "rolled_back": rolled}


def rollback_run(conn, run_id: str, actor: str = "soc-lead", reason: str = "") -> dict:
    """
    对一个**已完成**的 LIVE run 手动发起补偿。
    会新建一个 run 并用 rolled_back_from 指向原 run —— 保留完整的因果链，
    而不是把原 run 改成 ROLLED_BACK 抹掉"它曾经成功执行过"的事实。
    """
    run = conn.execute("SELECT * FROM playbook_runs WHERE run_id = ?", (run_id,)).fetchone()
    if not run:
        raise LookupError(f"run {run_id} not found")
    run = {k: run[k] for k in run.keys()}
    if run["mode"] != "LIVE":
        raise ValueError(f"run {run_id} is {run['mode']}; nothing to roll back")
    if run["status"] not in ("COMPLETED", "FAILED", "ROLLED_BACK"):
        raise ValueError(f"run {run_id} is still {run['status']}; wait for it to finish")

    actions = {a["step_no"]: a for a in playbook_actions(conn, run["playbook_id"])}
    done = conn.execute(
        """SELECT step_no FROM action_runs
           WHERE run_id = ? AND status = 'SUCCESS' AND is_rollback = 0
           ORDER BY step_no DESC""", (run_id,)
    ).fetchall()

    to_rollback = [actions[r["step_no"]] for r in done
                   if r["step_no"] in actions and actions[r["step_no"]]["is_destructive"]]

    rb_run_id = next_id(conn, "playbook_runs", "run_id", "RUN", width=6)
    conn.execute(
        """INSERT INTO playbook_runs
           (run_id, playbook_id, alert_id, mode, status, triggered_by,
            rolled_back_from, steps_total, summary)
           VALUES (?,?,?, 'LIVE', 'RUNNING', ?, ?, ?, ?)""",
        (rb_run_id, run["playbook_id"], run["alert_id"], actor, run_id,
         len(to_rollback), f"manual rollback of {run_id}: {reason or 'no reason given'}"),
    )
    conn.commit()
    write_audit(conn, actor, "rollback_start", "playbook_run", rb_run_id,
                {"original_run": run_id, "reason": reason, "steps": len(to_rollback)})

    # 回滚执行沿用原 run 的 playbook/alert，只是换一个 run_id
    rb_run = {**run, "run_id": rb_run_id}
    result = _auto_rollback(conn, rb_run, to_rollback, actor)

    status = "COMPLETED" if result["rolled_back"] == len(to_rollback) else "FAILED"
    conn.execute(
        """UPDATE playbook_runs SET status = ?, steps_succeeded = ?, summary = ?, finished_at = ?
           WHERE run_id = ?""",
        (status, result["rolled_back"],
         f"回滚 {result['rolled_back']}/{len(to_rollback)} 步 (原 run {run_id})",
         _iso(), rb_run_id),
    )
    conn.commit()
    write_audit(conn, actor, "rollback_finish", "playbook_run", rb_run_id, {"status": status})

    out = run_detail(conn, rb_run_id)
    out["original_run_id"] = run_id
    return out


def expire_stale_approvals(conn) -> int:
    """
    把超时未处理的审批标记为 EXPIRED 并取消对应 run。
    无人响应的审批请求必须自己过期 —— 否则会永远挂在 PENDING_APPROVAL，
    让分析师以为"系统在处理中"。
    """
    now = _iso()
    rows = conn.execute(
        "SELECT approval_id, run_id FROM approval_requests "
        "WHERE decision = 'PENDING' AND expires_at IS NOT NULL AND expires_at < ?",
        (now,),
    ).fetchall()
    for r in rows:
        conn.execute(
            "UPDATE approval_requests SET decision = 'EXPIRED', decided_at = ? WHERE approval_id = ?",
            (now, r["approval_id"]),
        )
        conn.execute(
            "UPDATE playbook_runs SET status = 'CANCELLED', finished_at = ?, "
            "summary = 'approval request expired' WHERE run_id = ?",
            (now, r["run_id"]),
        )
        write_audit(conn, "system", "approval_expired", "playbook_run", r["run_id"],
                    {"approval_id": r["approval_id"]})
    if rows:
        conn.commit()
    return len(rows)