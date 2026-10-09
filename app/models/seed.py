"""
合成演示数据 —— 全部为虚构内容。

数据来源说明：
- 检测规则参考项目 02（KQL 检测规则集）的 6 条规则，规则名/战术分类沿用其注释
- 账号、主机名、IP、服务名、告警载荷**全部虚构**，不对应任何真实企业或真实事件
- playbook 里的"执行"走 automation.py 的本地模拟器，不连接任何真实系统

刻意安排了 4 种典型场景，让 Dashboard 一打开就能看出 SOAR 的完整控制流：
  1. DRY_RUN 预演通过
  2. LIVE 执行完成（经人工批准）
  3. LIVE 执行中途失败 → 自动回滚已成功的破坏性步骤
  4. LIVE 执行失败且无可回滚步骤 → 停在 FAILED
  以及一条仍在 PENDING_APPROVAL 等待人工决策的 run
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .automation import approve_run, start_run
from .db import db_connection, init_db, wipe_database, write_audit
from .triage import ingest_alert

# ============================================
# 检测规则（对齐项目 02 的 KQL 规则集）
# ============================================
RULES = [
    ("KQL-001", "Suspicious Sign-In Pattern - Impossible Travel",
     "TA0006 Credential Access / TA0043 Reconnaissance", "SigninLogs", "HIGH",
     "VPN 出口 IP 变化、跨国出差、代理服务器；建议建立出口 ASN 白名单"),
    ("KQL-002", "Privileged Account - Anomalous Role Assignment",
     "TA0005 Privilege Escalation", "AuditLogs", "CRITICAL",
     "新员工入职、工单系统自动授权、轮岗；建议建立角色使用基线"),
    ("KQL-003", "Mass Device Authentication Failure",
     "TA0006 Credential Access", "SigninLogs + AuditLogs", "HIGH",
     "大规模发版、Token 刷新峰值；建议与设备管理窗口对比"),
    ("KQL-004", "Data Exfiltration Risk - Mass Download",
     "TA0010 Exfiltration", "OfficeActivity / CloudAppEvents", "CRITICAL",
     "数据迁移、合规导出、备份任务；建议对已知数据工程账号做白名单"),
    ("KQL-005", "Shadow IT - Unauthorized Cloud Service Access",
     "TA0002 Initial Access", "CloudAppEvents", "MEDIUM",
     "个人账号处理工作、新服务未纳管；建议维护企业 SaaS 许可清单"),
    ("KQL-006", "MFA Fatigue / Phishing-resistant Attack",
     "TA0006 Credential Access", "SigninLogs", "CRITICAL",
     "密码管理器重复提交、设备时钟漂移；建议排除已注册 MFA 的可信设备"),
]

# ============================================
# Playbook 定义
# ============================================
# (action_type, description, destructive, requires_approval, compensating)
PLAYBOOKS = [
    ("PB-001", "MFA Fatigue Response", "KQL-006",
     "MFA 轰炸后账号疑似失陷：先取证、再吊销会话、最后强制改密（需人工批准）",
     [
         ("enrich_identity", "拉取账号属性与注册设备，判断是否为特权账号", 0, 0, None),
         ("lookup_threat_intel", "查询触发登录的来源 IP 信誉", 0, 0, None),
         ("snapshot_evidence", "归档 SigninLogs 原始载荷作为证据", 0, 0, None),
         ("revoke_sessions", "吊销全部活跃会话令牌", 1, 0, "restore_sessions"),
         ("reset_password", "强制密码重置并要求下次登录改密", 1, 1, "issue_temp_access"),
         ("open_case_ticket", "创建 L2 调查工单", 0, 0, None),
     ]),
    ("PB-002", "Impossible Travel Containment", "KQL-001",
     "不可能旅行：确认 IP 信誉后吊销会话，极端情况下禁用账号（需人工批准）",
     [
         ("enrich_identity", "拉取账号属性与常用登录地", 0, 0, None),
         ("lookup_threat_intel", "查询来源 IP 信誉与出口 ASN", 0, 0, None),
         ("collect_host_inventory", "采集关联主机进程与网络连接快照", 0, 0, None),
         ("revoke_sessions", "吊销全部活跃会话令牌", 1, 0, "restore_sessions"),
         ("disable_account", "禁用账号阻断登录", 1, 1, "enable_account"),
         ("open_case_ticket", "创建 L2 调查工单", 0, 0, None),
     ]),
    ("PB-003", "Shadow IT Service Block", "KQL-005",
     "影子 IT：通知分析师并加抑制，封禁来源 IP 需人工批准",
     [
         ("enrich_identity", "拉取账号属性", 0, 0, None),
         ("notify_analyst", "通知值班分析师确认该服务是否已获批", 0, 0, None),
         ("add_suppression", "写入临时抑制，避免确认期间重复告警", 0, 0, None),
         ("block_ip", "在边界防火墙封禁来源 IP", 1, 1, "unblock_ip"),
     ]),
    ("PB-004", "Mass Authentication Failure Triage", "KQL-003",
     "批量认证失败：纯只读取证 + 开工单，不做任何状态变更，因此无需审批",
     [
         ("collect_host_inventory", "采集受影响主机的设备证书与同步状态", 0, 0, None),
         ("snapshot_evidence", "归档错误码分布作为根因分析输入", 0, 0, None),
         ("open_case_ticket", "创建平台团队调查工单", 0, 0, None),
         ("notify_analyst", "同步值班分析师（无需审批，可自动执行）", 0, 0, None),
     ]),
    ("PB-005", "Data Exfiltration Containment", "KQL-004",
     "批量下载：取证 + 吊销会话 + 封禁来源 IP（需人工批准）",
     [
         ("enrich_identity", "拉取账号属性与数据权限", 0, 0, None),
         ("snapshot_evidence", "归档下载文件清单与敏感度标签", 0, 0, None),
         ("revoke_sessions", "吊销全部活跃会话令牌", 1, 0, "restore_sessions"),
         ("block_ip", "封禁外泄出口 IP", 1, 1, "unblock_ip"),
         ("open_case_ticket", "创建数据安全调查工单", 0, 0, None),
     ]),
]

# ============================================
# 告警（全部虚构）
# ============================================
# (rule_id, severity, entity_type, entity_value, source_ip, hours_ago, title)
ALERTS = [
    # --- KQL-001 不可能旅行：正常告警 + 刻意制造的误报 ---
    ("KQL-001", "HIGH", "USER", "li.wei@vantech-demo.example", "203.0.113.41", 3,
     "Impossible travel: 4 cities in 3h for li.wei"),
    ("KQL-001", "HIGH", "USER", "chen.yu@vantech-demo.example", "203.0.113.77", 9,
     "Impossible travel: Singapore->Frankfurt in 2h"),
    ("KQL-001", "MEDIUM", "USER", "zhao.min@vantech-demo.example", "198.51.100.20", 26,
     "Impossible travel: 3 cities in 4h for zhao.min"),
    ("KQL-001", "HIGH", "USER", "wang.lei@vantech-demo.example", "198.51.100.31", 50,
     "Impossible travel: 5 cities in 4h for wang.lei"),
    ("KQL-001", "MEDIUM", "USER", "sun.jie@vantech-demo.example", "198.51.100.44", 74,
     "Impossible travel: 3 cities in 5h for sun.jie"),
    # 下面两条会被标记为误报（VPN 出口 IP 变化）
    ("KQL-001", "HIGH", "USER", "liu.fang@vantech-demo.example", "198.51.100.58", 30,
     "Impossible travel: corporate VPN pool rotation"),
    ("KQL-001", "HIGH", "USER", "wu.jing@vantech-demo.example", "198.51.100.63", 44,
     "Impossible travel: corporate VPN pool rotation"),
    ("KQL-001", "MEDIUM", "USER", "zhou.qi@vantech-demo.example", "198.51.100.88", 66,
     "Impossible travel: 3 cities in 4h for zhou.qi"),

    # --- KQL-002 特权角色异常授予 ---
    ("KQL-002", "CRITICAL", "USER", "ga_admin@vantech-demo.example", "203.0.113.11", 2,
     "Cold privileged role granted to ga_admin (30d unused)"),
    ("KQL-002", "HIGH", "USER", "svc_deploy@vantech-demo.example", "198.51.100.15", 21,
     "Security Administrator granted to svc_deploy"),

    # --- KQL-003 批量认证失败 ---
    ("KQL-003", "HIGH", "HOST", "PROD-DC-01", "10.20.0.5", 5,
     "142 device auth failures in 28m (error 700016)"),
    ("KQL-003", "MEDIUM", "HOST", "PROD-APP-SRV-03", "10.20.0.8", 38,
     "31 device auth failures in 25m (error 7000222)"),

    # --- KQL-004 批量下载 ---
    ("KQL-004", "CRITICAL", "USER", "svc-payroll-export", "198.51.100.91", 1,
     "3.4GB / 812 files downloaded in 96m (Highly Confidential)"),
    ("KQL-004", "HIGH", "USER", "ga_admin@vantech-demo.example", "203.0.113.12", 7,
     "1.8GB / 214 files downloaded in 74m"),

    # --- KQL-005 影子 IT ---
    ("KQL-005", "MEDIUM", "APP", "MegaNz-Transfer", "198.51.100.77", 4,
     "Unauthorized cloud service access: Mega (blocklist)"),
    ("KQL-005", "MEDIUM", "APP", "Wetransfer-Staging", "198.51.100.84", 29,
     "Unauthorized cloud service access: Wetransfer"),
    ("KQL-005", "LOW", "APP", "Notion-Teamspace", "198.51.100.102", 55,
     "Unauthorized cloud service access: Notion"),
    ("KQL-005", "LOW", "APP", "Canva-Design", "198.51.100.115", 80,
     "Unauthorized cloud service access: Canva"),

    # --- KQL-006 MFA 疲劳 ---
    ("KQL-006", "CRITICAL", "USER", "ga_admin@vantech-demo.example", "203.0.113.13", 0.5,
     "23 MFA failures then success in 41m"),
    ("KQL-006", "HIGH", "USER", "svc-payroll-export", "198.51.100.70", 6,
     "11 MFA failures then success in 38m"),
    ("KQL-006", "HIGH", "USER", "svc_deploy@vantech-demo.example", "198.51.100.96", 33,
     "9 MFA failures then success in 22m"),
    ("KQL-006", "MEDIUM", "USER", "chen.yu@vantech-demo.example", "198.51.100.51", 60,
     "6 MFA failures then success (password manager?)"),
]

# 误报反馈：(entity_value, rule_id, category, reason, suppression_target, threshold)
FP_FEEDBACK = [
    ("liu.fang@vantech-demo.example", "KQL-001", "VPN_EXIT_IP",
     "公司 VPN 出口池轮换，同一账号每小时出口 IP 都变",
     "ASN:AS64500 (corporate VPN pool)", None),
    ("wu.jing@vantech-demo.example", "KQL-001", "VPN_EXIT_IP",
     "同上，值班同事确认当时正在使用公司 VPN",
     "ASN:AS64500 (corporate VPN pool)", None),
    ("zhou.qi@vantech-demo.example", "KQL-001", "BUSINESS_TRAVEL",
     "深圳->上海->深圳 是客户现场出差，已在出差日历中",
     "city_pair:CN-SZX,CN-SHA", None),
    ("Notion-Teamspace", "KQL-005", "NEW_APP_AUTHORIZED",
     "设计团队 3 月已采购 Notion 企业版，尚未更新许可清单",
     "service:Notion", None),
    ("Canva-Design", "KQL-005", "NEW_APP_AUTHORIZED",
     "市场部市场活动使用 Canva，走过 IT 审批",
     "service:Canva", None),
    ("chen.yu@vantech-demo.example", "KQL-006", "PASSWORD_MANAGER",
     "1Password 重复提交导致 MFA 失败计数虚高",
     "device_id:DEV-TRUSTED-77", 12),
]


def _hours_ago(h: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()


def seed_all(verbose: bool = False) -> dict:
    init_db()
    now = datetime.now(timezone.utc)

    with db_connection() as conn:
        wipe_database(conn)
        counts = {}

        # ---------- 检测规则 ----------
        for rule_id, name, tactic, source, sev, notes in RULES:
            conn.execute(
                """INSERT INTO detection_rules
                   (rule_id, name, tactic, data_source, severity_default, tuning_notes)
                   VALUES (?,?,?,?,?,?)""",
                (rule_id, name, tactic, source, sev, notes),
            )
        conn.commit()
        counts["detection_rules"] = len(RULES)
        write_audit(conn, "seed", "seed_rules", "detection_rules", "all",
                    {"count": len(RULES), "synthetic": True})

        # ---------- Playbook + 步骤 ----------
        n_actions = 0
        for pb_id, name, rule_id, desc, actions in PLAYBOOKS:
            conn.execute(
                """INSERT INTO playbooks
                   (playbook_id, name, description, trigger_rule_id, version, owner)
                   VALUES (?,?,?,?,?,?)""",
                (pb_id, name, desc, rule_id, "1.0.0", "soc-engineering"),
            )
            for idx, (atype, adesc, destructive, approval, comp) in enumerate(actions, start=1):
                conn.execute(
                    """INSERT INTO playbook_actions
                       (action_id, playbook_id, step_no, action_type, description,
                        target_system, is_destructive, requires_approval,
                        dry_run_supported, compensating_action, compensating_target)
                       VALUES (?,?,?,?,?,?,?,?,1,?,?)""",
                    (f"ACT-{pb_id}-{idx:02d}", pb_id, idx, atype, adesc,
                     "SIMULATOR", destructive, approval, comp, None),
                )
                n_actions += 1
        conn.commit()
        counts["playbooks"] = len(PLAYBOOKS)
        counts["playbook_actions"] = n_actions
        write_audit(conn, "seed", "seed_playbooks", "playbooks", "all",
                    {"playbooks": len(PLAYBOOKS), "actions": n_actions, "synthetic": True})

        # ---------- 告警摄取（走真实 ingest 逻辑：去重 + 关联 + 评分）----------
        alert_ids: list = []
        for rule_id, sev, etype, evalue, sip, hours, title in ALERTS:
            res = ingest_alert(conn, {
                "rule_id": rule_id, "severity": sev, "entity_type": etype,
                "entity_value": evalue, "source_ip": sip,
                "title": title, "detected_at": _hours_ago(hours),
                "raw_payload": {
                    "_note": "synthetic sample payload",
                    "rule": rule_id, "entity": evalue, "src_ip": sip,
                    "detected_hours_ago": hours,
                },
            }, actor="seed")
            alert_ids.append(res["alert_id"])

        # 刻意重放两条告警，演示去重（alert_count 累加、不新建告警）
        ingest_alert(conn, {
            "rule_id": "KQL-006", "severity": "CRITICAL", "entity_type": "USER",
            "entity_value": "ga_admin@vantech-demo.example", "source_ip": "203.0.113.13",
            "title": "MFA fatigue retry", "detected_at": _hours_ago(0.2),
        }, actor="seed")
        ingest_alert(conn, {
            "rule_id": "KQL-003", "severity": "HIGH", "entity_type": "HOST",
            "entity_value": "PROD-DC-01", "source_ip": "10.20.0.5",
            "title": "device auth failure retry", "detected_at": _hours_ago(4.6),
        }, actor="seed")

        # 已分诊/已解决的告警
        conn.execute(
            "UPDATE alerts SET status='TRIAGED', triaged_at=?, analyst_note=? "
            "WHERE rule_id='KQL-003'", (_hours_ago(4), "疑似证书链问题，转平台团队"))
        conn.execute(
            "UPDATE alerts SET status='IN_PLAYBOOK' WHERE rule_id IN ('KQL-002','KQL-004')")
        conn.commit()

        counts["alerts"] = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        counts["correlations"] = conn.execute(
            "SELECT COUNT(*) c FROM alert_correlations").fetchone()["c"]

        # ---------- 误报反馈 ----------
        n_fp = 0
        for evalue, rule_id, category, reason, target, thr in FP_FEEDBACK:
            row = conn.execute(
                """SELECT alert_id FROM alerts
                   WHERE rule_id = ? AND entity_value = ? LIMIT 1""",
                (rule_id, evalue),
            ).fetchone()
            if not row:
                continue
            fp_id = f"FP-{n_fp + 1:04d}"
            conn.execute(
                """INSERT INTO false_positive_feedback
                   (fp_id, alert_id, rule_id, reported_by, reason_category, reason_text,
                    suppression_target, recommended_threshold)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (fp_id, row["alert_id"], rule_id, "soc-analyst", category, reason,
                 target, thr),
            )
            conn.execute(
                "UPDATE alerts SET status='FALSE_POSITIVE' WHERE alert_id = ?",
                (row["alert_id"],),
            )
            n_fp += 1
        conn.commit()
        counts["false_positive_feedback"] = n_fp
        write_audit(conn, "seed", "seed_fp_feedback", "false_positive_feedback", "all",
                    {"count": n_fp, "synthetic": True})

    # ---------- Playbook 执行实例（在独立连接里跑，便于提交/回滚）----------
    counts["playbook_runs"] = _seed_runs()

    if verbose:
        print(f"[+] seeded: {counts}")
    return counts


def _seed_runs() -> int:
    """
    构造 4 种典型执行结果 + 1 条待审批：
      1. DRY_RUN 通过
      2. LIVE 经批准后成功
      3. LIVE 中途失败 → 自动回滚
      4. LIVE 失败且无可回滚步骤 → FAILED
      5. 仍在 PENDING_APPROVAL
    """
    created = 0

    with db_connection() as conn:
        def find_alert(rule_id, entity_value):
            row = conn.execute(
                "SELECT alert_id FROM alerts WHERE rule_id=? AND entity_value=? LIMIT 1",
                (rule_id, entity_value),
            ).fetchone()
            return row["alert_id"] if row else None

    # 1) PB-004（只读 playbook）DRY_RUN 预演
    with db_connection() as conn:
        a = find_alert("KQL-003", "PROD-DC-01")
    if a:
        with db_connection() as conn:
            start_run(conn, "PB-004", "DRY_RUN", a, actor="seed")
        created += 1

    # 2) PB-001 LIVE + 人工批准 → 成功（MFA 疲劳 / ga_admin）
    with db_connection() as conn:
        a = find_alert("KQL-006", "ga_admin@vantech-demo.example")
    if a:
        with db_connection() as conn:
            run = start_run(conn, "PB-001", "LIVE", a, actor="seed")
            approve_run(conn, run["run_id"], "irene.wu@vantech-demo.example",
                        "确认为真实 MFA 疲劳攻击，账号已失陷，执行处置")
        created += 1

    # 3) PB-001 LIVE + 批准 → 第 5 步 reset_password 在该账号上确定性失败 → 自动回滚
    with db_connection() as conn:
        a = find_alert("KQL-006", "svc-payroll-export")
    if a:
        with db_connection() as conn:
            run = start_run(conn, "PB-001", "LIVE", a, actor="seed")
            approve_run(conn, run["run_id"], "irene.wu@vantech-demo.example",
                        "MFA 失败次数超阈值，执行账号处置")
        created += 1

    # 4) PB-002 DRY_RUN 预演（不可能旅行）
    with db_connection() as conn:
        a = find_alert("KQL-001", "li.wei@vantech-demo.example")
    if a:
        with db_connection() as conn:
            start_run(conn, "PB-002", "DRY_RUN", a, actor="seed")
        created += 1

    # 5) PB-003 LIVE：block_ip 在该 IP 上确定性失败，且它是唯一的破坏性步骤 → FAILED
    with db_connection() as conn:
        a = find_alert("KQL-005", "MegaNz-Transfer")
    if a:
        with db_connection() as conn:
            run = start_run(conn, "PB-003", "LIVE", a, actor="seed")
            approve_run(conn, run["run_id"], "chen.guo@vantech-demo.example",
                        "未授权文件共享服务，批准封禁来源 IP")
        created += 1

    # 6) PB-005 LIVE 保持 PENDING_APPROVAL —— Dashboard 用于演示"卡在审批门"的状态
    with db_connection() as conn:
        a = find_alert("KQL-004", "svc-payroll-export")
    if a:
        with db_connection() as conn:
            start_run(conn, "PB-005", "LIVE", a, actor="seed")
        created += 1

    return created

if __name__ == "__main__":
    print(seed_all(verbose=True))
