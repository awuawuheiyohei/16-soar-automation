-- SOAR 自动化响应平台 - SQLite schema (v1.0)
--
-- 数据诚实性：默认加载的全部是**合成演示数据**。本项目没有对接任何真实
-- SIEM / EDR / IdP 产品（Splunk / Microsoft Sentinel / Cortex XDR / CrowdStrike 等），
-- 也没有任何真实客户或生产环境数据。action 的"执行"是本地确定性模拟器。

-- ============================================
-- 检测规则（来源：项目 02 的 KQL 规则集）
-- ============================================
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id            TEXT PRIMARY KEY,                   -- KQL-001
    name               TEXT NOT NULL,
    tactic             TEXT,                               -- MITRE ATT&CK 战术
    data_source        TEXT,                               -- SigninLogs / AuditLogs / ...
    severity_default   TEXT NOT NULL DEFAULT 'MEDIUM',     -- CRITICAL / HIGH / MEDIUM / LOW
    tuning_notes       TEXT,                               -- 该规则已知的误报场景
    enabled            INTEGER NOT NULL DEFAULT 1,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled ON detection_rules(enabled);

-- ============================================
-- 告警（SOAR 的输入）
-- ============================================
CREATE TABLE IF NOT EXISTS alerts (
    alert_id           TEXT PRIMARY KEY,                   -- ALR-0001
    rule_id            TEXT NOT NULL,
    title              TEXT NOT NULL,
    severity           TEXT NOT NULL DEFAULT 'MEDIUM',     -- CRITICAL / HIGH / MEDIUM / LOW
    entity_type        TEXT NOT NULL DEFAULT 'USER',       -- USER / HOST / IP / APP / FILE_SHARE
    entity_value       TEXT NOT NULL,
    source_ip          TEXT,
    status             TEXT NOT NULL DEFAULT 'NEW',        -- NEW / CORRELATED / TRIAGED / IN_PLAYBOOK / RESOLVED / FALSE_POSITIVE
    priority_score     REAL NOT NULL DEFAULT 0.0,          -- 0-100，见 triage.py
    priority_level     TEXT NOT NULL DEFAULT 'LOW',        -- P1 / P2 / P3 / P4
    alert_count        INTEGER NOT NULL DEFAULT 1,         -- 关联/去重后聚合的原始事件数
    dedupe_key         TEXT,                               -- 同 key 视为重复事件
    raw_payload        TEXT,                               -- JSON：模拟的 SIEM 原始事件
    detected_at        TEXT NOT NULL DEFAULT (datetime('now')),
    triaged_at         TEXT,
    resolved_at        TEXT,
    analyst_note       TEXT,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(rule_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_priority ON alerts(priority_score);
CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(dedupe_key);

-- ============================================
-- 告警关联（correlation）—— 同一实体 / 同一来源 IP 的多条告警合并处理
-- ============================================
CREATE TABLE IF NOT EXISTS alert_correlations (
    correlation_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    primary_alert_id   TEXT NOT NULL,
    related_alert_id   TEXT NOT NULL,
    correlation_type   TEXT NOT NULL,                       -- SAME_ENTITY / SAME_SOURCE_IP / SAME_RULE_ENTITY
    confidence         REAL NOT NULL DEFAULT 0.5,          -- 0-1
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (primary_alert_id) REFERENCES alerts(alert_id),
    FOREIGN KEY (related_alert_id) REFERENCES alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_corr_primary ON alert_correlations(primary_alert_id);
CREATE INDEX IF NOT EXISTS idx_corr_related ON alert_correlations(related_alert_id);

-- ============================================
-- Playbook（编排定义）
-- ============================================
CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id        TEXT PRIMARY KEY,                   -- PB-001
    name               TEXT NOT NULL,
    description        TEXT,
    trigger_rule_id    TEXT,                               -- 由哪条检测规则触发
    version            TEXT NOT NULL DEFAULT '1.0.0',
    owner              TEXT NOT NULL DEFAULT 'soc-team',
    enabled            INTEGER NOT NULL DEFAULT 1,
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (trigger_rule_id) REFERENCES detection_rules(rule_id)
);

CREATE INDEX IF NOT EXISTS idx_pb_rule ON playbooks(trigger_rule_id);

-- ============================================
-- Playbook 步骤（action 定义）
-- requires_approval=1 的破坏性动作必须人工批准后才能在 LIVE 模式执行
-- ============================================
CREATE TABLE IF NOT EXISTS playbook_actions (
    action_id              TEXT PRIMARY KEY,               -- ACT-PB001-01
    playbook_id            TEXT NOT NULL,
    step_no                INTEGER NOT NULL,
    action_type            TEXT NOT NULL,                   -- 见 automation.py ACTION_TYPES
    description            TEXT NOT NULL,
    target_system          TEXT NOT NULL DEFAULT 'SIMULATOR',
    is_destructive         INTEGER NOT NULL DEFAULT 0,
    requires_approval      INTEGER NOT NULL DEFAULT 0,
    dry_run_supported      INTEGER NOT NULL DEFAULT 1,
    timeout_sec            INTEGER NOT NULL DEFAULT 30,
    compensating_action    TEXT,                            -- 回滚时执行的补偿动作类型
    compensating_target    TEXT,                            -- 回滚时的目标
    UNIQUE (playbook_id, step_no),
    FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id)
);

CREATE INDEX IF NOT EXISTS idx_pba_playbook ON playbook_actions(playbook_id);

-- ============================================
-- Playbook 执行实例
-- ============================================
CREATE TABLE IF NOT EXISTS playbook_runs (
    run_id             TEXT PRIMARY KEY,                    -- RUN-000001
    playbook_id        TEXT NOT NULL,
    alert_id           TEXT,
    mode               TEXT NOT NULL DEFAULT 'DRY_RUN',     -- DRY_RUN / LIVE
    status             TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
    triggered_by       TEXT NOT NULL DEFAULT 'system',
    requires_approval  INTEGER NOT NULL DEFAULT 0,
    approved_by        TEXT,
    approval_reason    TEXT,
    approved_at        TEXT,
    rejected_by        TEXT,
    rejection_reason   TEXT,
    rolled_back_from   TEXT,                               -- 本 run 是对哪个 run 的回滚
    steps_total        INTEGER NOT NULL DEFAULT 0,
    steps_succeeded    INTEGER NOT NULL DEFAULT 0,
    steps_failed       INTEGER NOT NULL DEFAULT 0,
    steps_skipped      INTEGER NOT NULL DEFAULT 0,
    summary            TEXT,
    started_at         TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at        TEXT,
    FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_runs_status ON playbook_runs(status);
CREATE INDEX IF NOT EXISTS idx_runs_alert ON playbook_runs(alert_id);
CREATE INDEX IF NOT EXISTS idx_runs_started ON playbook_runs(started_at);

-- ============================================
-- 每一步的执行结果
-- idempotency_key 保证同一 (run, step) 不会被重复执行 —— 幂等性
-- ============================================
CREATE TABLE IF NOT EXISTS action_runs (
    action_run_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id             TEXT NOT NULL,
    action_id          TEXT NOT NULL,
    step_no            INTEGER NOT NULL,
    action_type        TEXT NOT NULL,
    status             TEXT NOT NULL,                      -- SUCCESS / FAILED / SKIPPED / DRY_RUN_OK / ROLLED_BACK
    is_rollback        INTEGER NOT NULL DEFAULT 0,          -- 1 = 这是一次补偿/回滚执行
    dry_run            INTEGER NOT NULL DEFAULT 0,
    approved_by        TEXT,
    idempotency_key    TEXT NOT NULL UNIQUE,
    output             TEXT,                               -- JSON
    error              TEXT,
    duration_ms        INTEGER NOT NULL DEFAULT 0,
    started_at         TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at        TEXT,
    FOREIGN KEY (run_id) REFERENCES playbook_runs(run_id),
    FOREIGN KEY (action_id) REFERENCES playbook_actions(action_id)
);

CREATE INDEX IF NOT EXISTS idx_arun_run ON action_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_arun_status ON action_runs(status);

-- ============================================
-- 人工审批门
-- ============================================
CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id        TEXT PRIMARY KEY,                    -- APR-000001
    run_id             TEXT NOT NULL,
    action_id          TEXT,                                -- 具体是哪一步需要审批
    requested_by       TEXT NOT NULL,
    requested_at       TEXT NOT NULL DEFAULT (datetime('now')),
    approver           TEXT,
    decision           TEXT NOT NULL DEFAULT 'PENDING',     -- PENDING / APPROVED / REJECTED / EXPIRED
    decision_reason    TEXT,
    decided_at         TEXT,
    expires_at         TEXT,
    FOREIGN KEY (run_id) REFERENCES playbook_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_appr_run ON approval_requests(run_id);
CREATE INDEX IF NOT EXISTS idx_appr_decision ON approval_requests(decision);

-- ============================================
-- 误报反馈（用于回哺 detection rule 调优）
-- ============================================
CREATE TABLE IF NOT EXISTS false_positive_feedback (
    fp_id              TEXT PRIMARY KEY,                    -- FP-0001
    alert_id           TEXT NOT NULL,
    rule_id            TEXT NOT NULL,
    reported_by        TEXT NOT NULL DEFAULT 'analyst',
    reason_category    TEXT NOT NULL,                       -- VPN_EXIT_IP / BUSINESS_TRAVEL / ...
    reason_text        TEXT,
    suppression_target TEXT,                                -- 建议的抑制对象（实体值）
    recommended_threshold REAL,                             -- 建议调整后的阈值
    applied            INTEGER NOT NULL DEFAULT 0,          -- 是否已应用抑制
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
    FOREIGN KEY (rule_id) REFERENCES detection_rules(rule_id)
);

CREATE INDEX IF NOT EXISTS idx_fp_rule ON false_positive_feedback(rule_id);

-- ============================================
-- 全链路审计
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    actor              TEXT,
    action             TEXT NOT NULL,                       -- alert_ingest / run_start / approve / execute_step ...
    entity_type        TEXT,
    entity_id          TEXT,
    details            TEXT,                               -- JSON
    occurred_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);