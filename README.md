# SOAR 自动化响应平台

> Security Orchestration, Automation & Response —— 受控自动化响应平台

一个可以完整讲清楚 SOAR 价值主张的作品集项目：**告警摄取 → Playbook 编排 → 人工审批门 → 幂等执行 → 失败补偿回滚 → 全链路审计 → 误报回哺调优**。

---

## ⚠️ 数据与执行诚实性声明（请先读这一段）

| 项目 | 实际情况 |
|------|----------|
| **数据** | **全部为合成演示数据**。账号、主机名、IP、云服务名、告警载荷**全部虚构**，不对应任何真实企业、真实人员或真实安全事件。 |
| **SIEM 对接** | **没有对接任何真实 SIEM**。检测规则参考了公开的 KQL 检测规则写法，但本平台**没有**从 Splunk、Microsoft Sentinel、Elastic、Microsoft Defender 等任何产品拉取过数据。 |
| **执行器** | **没有真实执行器**。Playbook 中的每一个 action 都由 `app/models/automation.py` 中的**本地确定性模拟器**执行，**不发起任何网络请求，不改变任何真实系统状态**。 |
| **真实产品集成** | **没有**。Splunk SOAR、Cortex XDR、Sentinel SOAR、Panther 等商业 SOAR 产品**均未接入**。 |
| **真实事件** | **没有**处理过任何真实安全事件或客户数据，也没有任何性能/规模数据（如"日均处理百万告警"）—— 因为没有真实数据源。 |
| **失败注入** | `automation.SIMULATED_FAILURES` 中的报错是**人为设定的确定性故障**，用来演示回滚路径可复现、可测试。 |

演示数据的价值在于**展示控制流的正确性**，而不是证明任何真实的检测或处置能力。`/api/health` 会主动返回 `"execution_mode": "SIMULATED (no real SIEM/SOAR/EDR/IdP integration)"`，Dashboard 首页也有同样的声明 —— **不打算让任何人误以为这个项目连过真实系统。**

---

## 核心叙事：SOAR 的价值不在"自动修复"

大多数 SOAR demo 停在"检测到告警 → 自动禁用账号"。这恰恰是最危险的部分 —— 自动化替人做了它不该做的决定。

本项目把重点放在**让自动化可控**的四件事上：

1. **人工审批门** — 破坏性动作（禁用账号、隔离主机、封禁 IP、强制改密）在 LIVE 模式下**必须**人工批准，并记录审批人 + 理由 + 时间戳。理由字段为空则拒绝批准。
2. **幂等性** — 每个执行步骤有 `idempotency_key` 唯一约束。重复触发执行**不会**产生重复执行记录，靠数据库约束保证而非应用层判断。
3. **补偿回滚** — 每个破坏性步骤**必须**声明配套的补偿动作。中途失败时引擎逆序执行补偿，把系统恢复到执行前状态。
4. **全链路审计** — 谁摄取、谁触发、谁批准、每步做了什么、结果如何，全部落 `audit_log`。

再加一条容易被忽略但同样重要的：**误报治理**。自动化只会成倍放大噪音，所以误报必须能被度量并回哺规则调优。

---

## 架构

```
                        ┌──────────────────────────────────────────┐
   合成 SIEM 事件 ────▶ │  告警摄取        triage.ingest_alert()    │
   (POST JSON，          │    ├─ dedupe    同规则+同实体 → 聚合计数   │
    非真实 SIEM)         │    ├─ correlate 同实体 / 同 source_ip    │
                        │    └─ score     severity+entity+         │
                        │                 corroboration+recency     │
                        └───────────────┬──────────────────────────┘
                                        ▼
                        ┌──────────────────────────────────────────┐
                        │  alerts / alert_correlations             │
                        └───────────────┬──────────────────────────┘
                                        ▼
        ┌───────────────────────────────────────────────────────────────┐
        │  Playbook 编排        playbooks + playbook_actions            │
        │    每步标注：is_destructive / requires_approval /             │
        │              compensating_action（补偿动作）                   │
        └───────────────┬───────────────────────────────────────────────┘
                        ▼  start_run(mode=DRY_RUN | LIVE)
        ┌───────────────────────────────────────────────────────────────┐
        │                      审批门（approval gate）                 │
        │   DRY_RUN ────────────────────────────────▶ 立即执行（无副作用）│
        │   LIVE + 含需审批步骤 ─▶ PENDING_APPROVAL ─┐                  │
        │                                             │ approve/reject  │
        │                                             ▼                 │
        │   LIVE + 纯只读步骤 ─────────────────────▶ 直接执行            │
        └───────────────┬───────────────────────────────────────────────┘
                        ▼  execute_run()
        ┌───────────────────────────────────────────────────────────────┐
        │  逐步执行                                                   │
        │    幂等：已有 action_runs 记录 → 跳过                          │
        │    失败(LIVE)：逆序执行已成功破坏性步骤的补偿动作 → ROLLED_BACK │
        └───────────────┬───────────────────────────────────────────────┘
                        ▼
        ┌───────────────────────────────────────────────────────────────┐
        │  action_runs / approval_requests / audit_log /                │
        │  false_positive_feedback ──▶ 规则误报率 ──▶ 调优建议            │
        └───────────────────────────────────────────────────────────────┘
```

### 执行器说明

`automation.execute_action()` 是**模拟器**，不是真实 API 调用。真实 SOAR 在这里会调用 IdP / EDR / 防火墙的 API；本项目只演示控制流（审批 → 幂等 → 失败 → 补偿 → 审计），这些控制流逻辑与对接的产品无关。

---

## 快速开始

```bash
git clone https://github.com/awuawuheiyohei/16-soar-automation.git
cd 16-soar-automation

pip install "fastapi>=0.110" "uvicorn>=0.27" "pytest>=8.0" "httpx>=0.27"

python main.py serve          # http://127.0.0.1:5053
python -m pytest tests/ -q    # 206 passed
./scripts/smoke_test.sh       # 72 项端到端校验
```

### CLI

```bash
python main.py serve                  # 启动服务（端口 5053）
python main.py seed                   # 重置演示数据
python main.py stats                  # 告警 / 执行 / 各规则误报统计
python main.py playbooks              # 列出所有 playbook 及其审批门
python main.py triage ALR-0019        # 解释某条告警的优先级评分构成
python main.py audit 20               # 查看最近 20 条审计记录
```

---

## API 端点

共 **23** 个 REST 端点。

| # | 方法 | 路径 | 说明 |
|---|------|------|------|
| 1 | GET | `/api/health` | 健康检查（自曝执行器为模拟器） |
| 2 | GET | `/api/overview` | Dashboard 总览：状态分布、待审批、待调优规则 |
| 3 | GET | `/api/rules` | 检测规则列表（含各规则误报统计） |
| 4 | GET | `/api/rules/{rule_id}` | 规则详情（含已知误报场景 + 调优建议） |
| 5 | POST | `/api/alerts/ingest` | 告警摄取（自动去重 → 关联 → 评分 → 审计） |
| 6 | GET | `/api/alerts` | 告警列表（状态/规则/优先级/实体类型/搜索 多维筛选） |
| 7 | GET | `/api/alerts/{alert_id}` | 告警详情（含评分四项构成 + `explanation`） |
| 8 | PATCH | `/api/alerts/{alert_id}/status` | 告警状态流转（写审计） |
| 9 | POST | `/api/alerts/{alert_id}/false-positive` | 标记误报并返回该规则的调优建议 |
| 10 | GET | `/api/false-positives` | 误报反馈列表 + 分类分布 |
| 11 | GET | `/api/tuning` | 每条规则的误报率、样本可信度、调优建议 |
| 12 | GET | `/api/playbooks` | Playbook 列表（含审批门/破坏性步骤统计） |
| 13 | GET | `/api/playbooks/{playbook_id}` | Playbook 详情（每步的补偿动作 + 模拟 connector） |
| 14 | POST | `/api/playbooks/{playbook_id}/run` | 触发执行（`DRY_RUN` / `LIVE`） |
| 15 | GET | `/api/runs` | 执行实例列表（状态/模式/playbook 筛选） |
| 16 | GET | `/api/runs/{run_id}` | 执行详情（步骤时间线 + 审批 + **该 run 的完整审计轨迹**） |
| 17 | POST | `/api/runs/{run_id}/approve` | 人工批准（记录 approver + 理由） |
| 18 | POST | `/api/runs/{run_id}/reject` | 人工拒绝（取消执行，不执行任何步骤） |
| 19 | POST | `/api/runs/{run_id}/execute` | 手动触发执行（对终态幂等） |
| 20 | POST | `/api/runs/{run_id}/rollback` | 手动发起补偿（新建 run，`rolled_back_from` 指向原 run） |
| 21 | POST | `/api/runs/{run_id}/approval-form` | 表单版审批（`application/x-www-form-urlencoded`） |
| 22 | GET | `/api/approvals` | 审批队列（含被卡住的破坏性动作类型） |
| 23 | GET | `/api/audit` | 全链路审计日志（多维筛选，details 为已解析 JSON） |

另有 `GET /`（单文件 Dashboard）与 `/docs`、`/openapi.json`。

---

## 核心算法

### 1. 告警优先级评分（`app/models/triage.py`）

```
priority = severity(0-40) + entity(0-20) + corroboration(0-20) + recency(0-20)
```

四项都参与，因为只看严重度会让"CRITICAL 的低价值影子 IT"排在"账号被接管"前面 —— 这正是分析师最讨厌的噪音。

- **entity**：特权账号（`admin` / `svc_` / `ga_` / `root` 前缀）+8，生产资产 +6
- **corroboration**：每条关联告警 +5，封顶 20（多个独立规则指向同一实体 = 更可信更紧急）
- **recency**：半衰期 **12 小时**的指数衰减。用线性衰减会在 48 小时处产生断崖跳变，排序不稳定。

`explain()` 把评分翻译成一句人话，例如：

```
[P1] priority=90.0 · 严重度 CRITICAL 贡献 40；实体 ga_admin@... 是特权账号 (+8)；
有 2 条关联告警佐证 (+10)；距今 0.2h，时效分 20
```

### 2. 去重与关联

- **去重**发生在**入库时**，不是查询时。SOAR 的价值是"每进来 100 条原始事件只让分析师看 3 条"。
- 去重键 `rule_id|entity_type|entity_value`，刻意**不**包含 `source_ip` —— 同一账号从两个 IP 触发仍属同一调查单元。
- **关联**不只看实体：跨账号横向移动共享 `source_ip`，只按实体会漏掉。

### 3. 误报治理

误报率低于阈值且样本量 < 5 时，引擎**明确拒绝**给出建议阈值：

> 3 个样本里 2 个误报不足以说明规则有问题。拿噪声去改生产规则是危险的。

命中后返回分类化调优策略（`VPN_EXIT_IP` → 加出口 ASN 白名单；`NEW_APP_AUTHORIZED` → 补许可清单；`PASSWORD_MANAGER` → 排除可信设备……），而不是笼统的"调低阈值"。

---

## 不做什么（明确边界）

- ❌ **没有对接任何真实 SIEM**（Splunk / Sentinel / Elastic / Defender 均未接入）
- ❌ **没有对接任何真实 SOAR 产品**（Splunk SOAR / Cortex XDR / Sentinel SOAR / Panther 均未接入）
- ❌ **没有真实的执行器**：所有 action 由本地模拟器执行，**不产生任何真实系统变更**
- ❌ **没有真实安全事件或客户数据** —— 全部数据是虚构的合成数据
- ❌ **没有性能/规模基准**：没有真实数据源，因此不声称任何吞吐或延迟指标
- ❌ **没有真实身份认证/授权**：审批人字段是自由文本，不是 SSO 身份
- ❌ **没有多租户 / RBAC**：`actor` 是调用方自报的，不构成可信身份
- ❌ **没有分布式调度**：单进程 SQLite，无任务队列、无水平扩展
- ❌ **没有重试策略**：步骤失败即进入补偿回滚，不做自动重试
- ❌ **没有真实 webhook / 回调**：执行是同步的，不模拟异步通知

---

## 开发中踩到并修掉的真实缺陷

这些都是本项目开发过程中**实际发生**并被测试捕获的 bug，不是事后编造的故事。

| # | 缺陷 | 根因 | 影响 | 修复 | 捕获它的测试 |
|---|------|------|------|------|-------------|
| 1 | `next_id()` 永远返回 `-1` | `SUBSTR(col, len(prefix)+1)` 从 `-0001` 开始截断，`CAST('-0001' AS INTEGER)` = `-1` | 每次生成 ID 都撞 `PRIMARY KEY`，摄取直接崩溃 | 改用 `INSTR(col,'-')+1` 定位分隔符，与前缀长度解耦 | `test_ingest_creates_new_alert` |
| 2 | 时效分恒为满分 | `recency_component()` 写成 `(detected_at - now)`，历史告警得到**负数**年龄，再套 `max(0.0, ...)` → 恒为 0 小时 | **所有历史告警时效分都顶到 20 分，评分组件完全失效**，"先处理谁"退化成只看严重度 | 改为 `(now - detected_at)` | `test_recency_component_halves_at_half_life` |
| 3 | `block_ip` 封禁了错误的 IP | `_resolve_target()` 对所有 action 一律取 `entity_value` | 影子 IT 告警的实体是"未授权云服务名"，把它传给防火墙只会生成一条无效规则 | 按 action 类型解析：`block_ip`/`unblock_ip` 取 `source_ip`，其余取 `entity_value` | `test_block_ip_targets_source_ip_not_entity` |
| 4 | 手动回滚必崩 | `rollback_run()` 中引用了从未赋值的 `rb_run` | `UnboundLocalError` → HTTP 500 | 补 `{**run, "run_id": rb_run_id}` | `test_rollback_run_creates_new_run_with_reference` |
| 5 | 补偿动作打到了假目标 | seed 把 `compensating_target` 填成 `"compensating:restore_sessions"` 这种占位串 | 回滚执行的目标是垃圾值，回滚演示名不副实 | 改为 `NULL`，由引擎按补偿动作类型重新解析 | `test_rollback_executes_compensating_action` |
| 6 | 全链路审计是残缺的 | `/api/runs/{id}` 的审计查询用 `entity_id = ?` 等值匹配 | 每步执行的 `entity_id` 是 `"<run_id>#<step>"`，**全部漏掉** —— 而"每步做了什么"正是这个项目的核心承诺 | 改为 `entity_id = ? OR entity_id LIKE '<run_id>#%'` | `test_run_detail_audit_includes_per_step_entries` |
| 7 | 并发摄取偶发 500 | `next_id` 是 read-then-insert，FastAPI 同步端点跑在 threadpool 里 | 两个并发请求算出同一个 `alert_id` → `IntegrityError` | 捕获 `IntegrityError` 重试 3 次，耗尽后抛出明确错误 | 手工并发验证 + 幂等键唯一性测试 |
| 8 | 测试互相污染 | `test_api.py` 会往 KQL-001 追加误报反馈，而 `test_triage.py` 断言了硬编码条数 | 全量跑时挂 1 个测试，单独跑两个文件都通过 | 断言改为校验**公式本身**而非具体条数 | `test_fp_rate_for_rule_computes_percentage` |

另外两个是**设计决策**而非 bug，但也值得说明：

- **不使用 `python-multipart`**：FastAPI 的 `Form()` 依赖它，但本项目只需要解析几个键值对。改为用标准库 `urllib.parse` 手写 `parse_urlencoded()`（`app/models/formparse.py`），少一个依赖就少一处供应链面。有一条测试专门断言 `multipart` 没有被导入。
- **DRY-RUN 绕过失败注入**：早期版本让预演也走失败注入，导致预演出现"注定失败"的步骤，无法回答"流程能不能走通"。现在 `dry_run=True` 时直接返回成功，语义是"只验证控制流"。

---

## 测试

```bash
python -m pytest tests/ -q      # 206 passed
./scripts/smoke_test.sh         # 72 项校验
```

| 文件 | 数量 | 覆盖 |
|------|------|------|
| `tests/test_triage.py` | 59 | 去重键、关联、评分四项、时效衰减、误报率算法、摄取 |
| `tests/test_automation.py` | 52 | Action 注册表完整性、审批门、幂等、自动回滚、目标解析、审批过期 |
| `tests/test_api.py` | 83 | 23 个端点的正常路径 + 错误码 + 不变量 |
| `tests/test_formparse.py` | 12 | 手写 url-encoded 解析器（含编码、超长 body、无效 UTF-8） |

`smoke_test.sh` 用 bash + curl 起真实的 uvicorn 进程，验证 4 种执行结果（完成 / 失败 / 回滚 / 待审批）、审批门、幂等性、urlencoded 表单审批、手动回滚，以及首页的诚实性声明。

CI 在 Python 3.11 / 3.12 / 3.13 上跑测试矩阵，另有一个 smoke job。

---

## 项目结构

```
app/
├── main.py                 # FastAPI 装配（端口 5053）
├── schema.sql              # 10 张表 + 索引
├── api/routes.py           # 23 个 REST 端点
└── models/
    ├── db.py               # db_connection() context manager (WAL + busy_timeout)
    ├── triage.py           # 去重 / 关联 / 优先级评分 / 误报治理  ← 核心算法
    ├── automation.py       # 审批门 / 幂等执行 / 补偿回滚 / 审批过期 ← 核心引擎
    ├── formparse.py        # 手写 url-encoded 解析器（无 python-multipart）
    └── seed.py             # 合成演示数据
static/index.html           # 单文件 Dashboard（原生 JS，无构建步骤）
tests/                      # 206 个 pytest 测试
scripts/smoke_test.sh       # 72 项端到端校验
```

### 数据模型

`detection_rules` · `alerts` · `alert_correlations` · `playbooks` · `playbook_actions` · `playbook_runs` · `action_runs` · `approval_requests` · `false_positive_feedback` · `audit_log`

---

## License

MIT