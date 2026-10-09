#!/usr/bin/env bash
# Smoke test —— 启动服务 → 打关键端点 → 校验 SOAR 的关键不变量 → 关闭
# 用途：CI 与本地一键验证，不依赖 pytest
set -uo pipefail

PORT="${PORT:-5053}"
BASE="http://127.0.0.1:${PORT}"
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }

check() {
  local name="$1" url="$2" expect="${3:-200}"
  local code
  code=$(curl -s -o /tmp/soar_smoke_body -w "%{http_code}" "${BASE}${url}" 2>/dev/null || echo "000")
  if [[ "${code}" == "${expect}" ]]; then
    green "  ✓ ${name} (${code})"; PASS=$((PASS+1))
  else
    red   "  ✗ ${name} — 期望 ${expect}, 实际 ${code}"; FAIL=$((FAIL+1))
  fi
}

check_json() {
  local name="$1" url="$2" expr="$3"
  local out
  out=$(curl -s "${BASE}${url}" 2>/dev/null)
  if python3 -c "
import json,sys
try:
    d=json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0 if (${expr}) else 1)
" "${out}" 2>/dev/null; then
    green "  ✓ ${name}"; PASS=$((PASS+1))
  else
    red   "  ✗ ${name} — 断言失败: ${expr}"; FAIL=$((FAIL+1))
  fi
}

check_body() {
  local name="$1" url="$2" needle="$3"
  local out
  out=$(curl -s "${BASE}${url}" 2>/dev/null)
  if [[ "${out}" == *"${needle}"* ]]; then
    green "  ✓ ${name}"; PASS=$((PASS+1))
  else
    red   "  ✗ ${name} — 未找到: ${needle}"; FAIL=$((FAIL+1))
  fi
}

check_code() {
  # check_code <name> <expected> <curl args...>
  local name="$1" expect="$2"; shift 2
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || echo "000")
  if [[ "${code}" == "${expect}" ]]; then
    green "  ✓ ${name} (${code})"; PASS=$((PASS+1))
  else
    red   "  ✗ ${name} — 期望 ${expect}, 实际 ${code}"; FAIL=$((FAIL+1))
  fi
}

echo "==> 重建演示数据"
python3 -m app.models.seed >/dev/null 2>&1 || { red "seed 失败"; exit 1; }

echo "==> 启动服务 (port ${PORT})"
python3 -m uvicorn app.main:app --host 127.0.0.1 --port "${PORT}" --log-level warning &
SERVER_PID=$!
cleanup() { kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; }
trap cleanup EXIT

for i in $(seq 1 40); do
  curl -s -o /dev/null "${BASE}/api/health" 2>/dev/null && break
  sleep 0.25
done

if ! curl -s -o /dev/null "${BASE}/api/health" 2>/dev/null; then
  red "服务未能在 10s 内就绪"; exit 1
fi

echo "==> 健康与元信息"
check "GET /api/health" /api/health
check_json "服务标识正确" /api/health "d['service'] == 'soar-automation-platform'"
check_json "version 1.0.0" /api/health "d['version'] == '1.0.0'"
check_json "自曝执行器为模拟器" /api/health "'SIMULATED' in d['execution_mode']"
check_json "检测规则 = 6" /api/health "d['detection_rules'] == 6"

echo "==> 总览"
check_json "状态键完整" /api/overview \
  "set(d['runs_by_status']) >= {'COMPLETED','FAILED','ROLLED_BACK','PENDING_APPROVAL'}"
check_json "存在待人工审批" /api/overview "d['pending_approvals'] >= 1"
check_json "存在已回滚执行" /api/overview "d['runs_by_status'].get('ROLLED_BACK',0) >= 1"
check_json "存在预演成功步骤" /api/overview "d['action_steps_by_status'].get('DRY_RUN_OK',0) > 0"
check_json "KQL-001 被判定需要调优" /api/overview \
  "any(r['rule_id']=='KQL-001' for r in d['rules_needing_tuning'])"

echo "==> 检测规则"
check_json "规则数 = 6" /api/rules "d['count'] == 6"
check_json "规则带误报统计" /api/rules "all('fp_stats' in r for r in d['rules'])"
check_json "KQL-001 需调优" /api/rules/KQL-001 "d['tuning']['status'] == 'NEEDS_TUNING'"
check_json "规则带已知误报场景" /api/rules/KQL-001 "len(d['tuning_notes']) > 0"
check "GET /api/rules/KQL-999 → 404" /api/rules/KQL-999 404

echo "==> 告警"
check_json "告警列表非空" /api/alerts "d['count'] > 0"
check_json "按优先级降序" /api/alerts \
  "[a['priority_score'] for a in d['alerts']] == sorted([a['priority_score'] for a in d['alerts']], reverse=True)"
check_json "状态过滤生效" "/api/alerts?status=FALSE_POSITIVE" \
  "all(a['status']=='FALSE_POSITIVE' for a in d['alerts'])"
check_json "规则过滤生效" "/api/alerts?rule_id=KQL-001" \
  "all(a['rule_id']=='KQL-001' for a in d['alerts'])"
check_json "搜索过滤生效" "/api/alerts?search=Mega" "d['count'] >= 1"
check "GET /api/alerts/ALR-0001" /api/alerts/ALR-0001
check_json "详情含分诊解释" /api/alerts/ALR-0001 "len(d.get('explanation','')) > 0"
check_json "评分四项构成齐全" /api/alerts/ALR-0001 \
  "all(k in d for k in ('severity_component','entity_component','corroboration_component','recency_component'))"
check "GET /api/alerts/ALR-9999 → 404" /api/alerts/ALR-9999 404

echo "==> 告警摄取（去重 + 关联）"
INGEST='{"rule_id":"KQL-003","severity":"HIGH","entity_type":"HOST","entity_value":"SMOKE-HOST-01","source_ip":"198.18.7.7","title":"smoke ingest","actor":"smoke"}'
first=$(curl -s -X POST "${BASE}/api/alerts/ingest" -H 'Content-Type: application/json' -d "$INGEST")
second=$(curl -s -X POST "${BASE}/api/alerts/ingest" -H 'Content-Type: application/json' -d "$INGEST")
if python3 -c "
import json,sys
a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2])
sys.exit(0 if (a['deduplicated'] is False and b['deduplicated'] is True
              and a['alert_id']==b['alert_id'] and b['alert_count']==2) else 1)
" "${first}" "${second}" 2>/dev/null; then
  green "  ✓ 去重生效（第二次不新建，计数累加到 2）"; PASS=$((PASS+1))
else
  red   "  ✗ 去重生效 — first=${first} second=${second}"; FAIL=$((FAIL+1))
fi
check_code "摄取缺少必填字段 → 400" 400 -X POST "${BASE}/api/alerts/ingest" \
  -H 'Content-Type: application/json' -d '{"severity":"HIGH"}'
check_code "摄取未知规则 → 400" 400 -X POST "${BASE}/api/alerts/ingest" \
  -H 'Content-Type: application/json' -d '{"rule_id":"KQL-999","entity_value":"x","entity_type":"HOST"}'

echo "==> 误报治理"
check_code "标记误报" 200 -X POST "${BASE}/api/alerts/ALR-0004/false-positive" \
  -H 'Content-Type: application/json' \
  -d '{"reason_category":"VPN_EXIT_IP","reason_text":"smoke test","actor":"smoke"}'
check_code "非法误报分类 → 400" 400 -X POST "${BASE}/api/alerts/ALR-0008/false-positive" \
  -H 'Content-Type: application/json' -d '{"reason_category":"NOT_A_CATEGORY"}'
check_json "误报列表非空" /api/false-positives "d['count'] > 0"
check_json "调优覆盖全部 6 条规则" /api/tuning "d['count'] == 6"
check_json "样本不足被显式标注" /api/tuning "any(t['low_confidence'] for t in d['tuning'])"
check_json "样本不足时不建议改阈值" /api/tuning \
  "all(t['suggested_threshold'] is None for t in d['tuning'] if t['low_confidence'])"

echo "==> Playbook 与审批门"
check_json "Playbook = 5" /api/playbooks "d['count'] == 5"
check_json "有 playbook 需要审批" /api/playbooks \
  "any(p['approval_gated_actions'] > 0 for p in d['playbooks'])"
check_json "有 playbook 可全自动" /api/playbooks \
  "any(p['approval_gated_actions'] == 0 for p in d['playbooks'])"
check_json "PB-001 共 6 步" /api/playbooks/PB-001 "len(d['actions']) == 6"
check_json "破坏性步骤均带补偿动作" /api/playbooks/PB-001 \
  "all(a['compensating_action'] for a in d['actions'] if a['is_destructive'])"
check_json "需审批动作均为破坏性" /api/playbooks/PB-001 \
  "all(a['action_spec']['destructive'] for a in d['actions'] if a['requires_approval'])"
check_json "connector 均为模拟器" /api/playbooks/PB-001 \
  "all(a['simulated_connector'].startswith('sim-') for a in d['actions'])"
check "GET /api/playbooks/PB-999 → 404" /api/playbooks/PB-999 404

echo "==> DRY-RUN 预演"
dry=$(curl -s -X POST "${BASE}/api/playbooks/PB-004/run" \
  -H 'Content-Type: application/json' -d '{"mode":"DRY_RUN","actor":"smoke"}')
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
sys.exit(0 if (d['status']=='COMPLETED' and d['mode']=='DRY_RUN'
              and all(s['status']=='DRY_RUN_OK' for s in d['steps'])) else 1)
" "${dry}" 2>/dev/null; then
  green "  ✓ DRY-RUN 完成且全部步骤标记 DRY_RUN_OK"; PASS=$((PASS+1))
else
  red   "  ✗ DRY-RUN 预演 — ${dry}"; FAIL=$((FAIL+1))
fi
check_code "非法 mode → 400" 400 -X POST "${BASE}/api/playbooks/PB-004/run" \
  -H 'Content-Type: application/json' -d '{"mode":"SEMI_AUTO"}'
check_code "未知 playbook → 404" 404 -X POST "${BASE}/api/playbooks/PB-999/run" \
  -H 'Content-Type: application/json' -d '{"mode":"DRY_RUN"}'

echo "==> 审批门（核心控制流）"
live=$(curl -s -X POST "${BASE}/api/playbooks/PB-001/run" \
  -H 'Content-Type: application/json' -d '{"mode":"LIVE","actor":"smoke"}')
RUN_ID=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['run_id'])" "${live}" 2>/dev/null)
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
sys.exit(0 if (d['status']=='PENDING_APPROVAL' and d['steps']==[]) else 1)
" "${live}" 2>/dev/null; then
  green "  ✓ LIVE 含审批步骤时挂起，未执行任何步骤"; PASS=$((PASS+1))
else
  red   "  ✗ 审批门挂起 — ${live}"; FAIL=$((FAIL+1))
fi
check_code "未批准直接执行 → 409" 409 -X POST "${BASE}/api/runs/${RUN_ID}/execute" \
  -H 'Content-Type: application/json' -d '{"actor":"smoke"}'
check_code "批准缺少 approver → 400" 400 -X POST "${BASE}/api/runs/${RUN_ID}/approve" \
  -H 'Content-Type: application/json' -d '{"reason":"x"}'
check_code "批准缺少理由 → 400" 400 -X POST "${BASE}/api/runs/${RUN_ID}/approve" \
  -H 'Content-Type: application/json' -d '{"approver":"smoke@test"}'
approved=$(curl -s -X POST "${BASE}/api/runs/${RUN_ID}/approve" \
  -H 'Content-Type: application/json' \
  -d '{"approver":"smoke.approver@test","reason":"confirmed real incident"}')
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
sys.exit(0 if (d['status']=='COMPLETED' and d['approved_by']=='smoke.approver@test') else 1)
" "${approved}" 2>/dev/null; then
  green "  ✓ 批准后执行并记录审批人"; PASS=$((PASS+1))
else
  red   "  ✗ 批准执行 — ${approved}"; FAIL=$((FAIL+1))
fi

echo "==> 幂等性"
before=$(curl -s "${BASE}/api/runs/${RUN_ID}" | python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())['steps']))")
curl -s -X POST "${BASE}/api/runs/${RUN_ID}/execute" -H 'Content-Type: application/json' -d '{}' >/dev/null
curl -s -X POST "${BASE}/api/runs/${RUN_ID}/execute" -H 'Content-Type: application/json' -d '{}' >/dev/null
after=$(curl -s "${BASE}/api/runs/${RUN_ID}" | python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())['steps']))")
if [[ "${before}" == "${after}" ]]; then
  green "  ✓ 重复执行幂等（步骤数 ${before} 不变）"; PASS=$((PASS+1))
else
  red   "  ✗ 幂等性破坏：${before} → ${after}"; FAIL=$((FAIL+1))
fi

echo "==> url-encoded 表单审批（手写解析器）"
form_run=$(curl -s -X POST "${BASE}/api/playbooks/PB-002/run" \
  -H 'Content-Type: application/json' -d '{"mode":"LIVE","actor":"smoke"}')
FORM_RUN_ID=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['run_id'])" "${form_run}" 2>/dev/null)
form=$(curl -s -X POST "${BASE}/api/runs/${FORM_RUN_ID}/approval-form" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'approver=form.user@test.example' \
  --data-urlencode 'reason=approved via urlencoded form')
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
sys.exit(0 if (d.get('approved_by')=='form.user@test.example'
              and d.get('approval_reason')=='approved via urlencoded form') else 1)
" "${form}" 2>/dev/null; then
  green "  ✓ 表单审批解析正确（含 + 与百分号编码）"; PASS=$((PASS+1))
else
  red   "  ✗ 表单审批 — ${form}"; FAIL=$((FAIL+1))
fi
check_code "表单审批 Content-Type 错误 → 415" 415 \
  -X POST "${BASE}/api/runs/${FORM_RUN_ID}/approval-form" \
  -H 'Content-Type: application/json' -d '{}'

echo "==> 拒绝路径"
rej_run=$(curl -s -X POST "${BASE}/api/playbooks/PB-003/run" \
  -H 'Content-Type: application/json' -d '{"mode":"LIVE","actor":"smoke"}')
REJ_RUN_ID=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['run_id'])" "${rej_run}" 2>/dev/null)
rejected=$(curl -s -X POST "${BASE}/api/runs/${REJ_RUN_ID}/reject" \
  -H 'Content-Type: application/json' \
  -d '{"approver":"smoke.approver@test","reason":"false positive"}')
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
sys.exit(0 if (d['status']=='CANCELLED' and d['steps']==[]) else 1)
" "${rejected}" 2>/dev/null; then
  green "  ✓ 拒绝后取消执行且未执行任何步骤"; PASS=$((PASS+1))
else
  red   "  ✗ 拒绝路径 — ${rejected}"; FAIL=$((FAIL+1))
fi

echo "==> 失败与自动回滚"
check_json "RUN-000003 状态为 ROLLED_BACK" /api/runs/RUN-000003 "d['status'] == 'ROLLED_BACK'"
check_json "回滚 run 含补偿动作" /api/runs/RUN-000003 \
  "any(s['is_rollback']==1 and s['action_type']=='restore_sessions' for s in d['steps'])"
check_json "原破坏性步骤被标记 ROLLED_BACK" /api/runs/RUN-000003 \
  "any(s['status']=='ROLLED_BACK' for s in d['steps'])"
check_json "RUN-000005 状态为 FAILED" /api/runs/RUN-000005 "d['status'] == 'FAILED'"
check_json "失败后不再执行后续步骤" /api/runs/RUN-000005 \
  "len([s for s in d['steps'] if s['is_rollback']==0]) == 4"

echo "==> 手动回滚"
rb_run=$(curl -s -X POST "${BASE}/api/playbooks/PB-004/run" \
  -H 'Content-Type: application/json' -d '{"mode":"LIVE","actor":"smoke"}')
RB_ID=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['run_id'])" "${rb_run}" 2>/dev/null)
rolled=$(curl -s -X POST "${BASE}/api/runs/${RB_ID}/rollback" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"smoke.lead@test","reason":"manual compensation"}')
if python3 -c "
import json,sys
d=json.loads(sys.argv[1])
sys.exit(0 if (d.get('rolled_back_from')==sys.argv[2] and d['run_id']!=sys.argv[2]) else 1)
" "${rolled}" "${RB_ID}" 2>/dev/null; then
  green "  ✓ 手动回滚新建 run 并保留因果链"; PASS=$((PASS+1))
else
  red   "  ✗ 手动回滚 — ${rolled}"; FAIL=$((FAIL+1))
fi
dry_rb=$(curl -s -X POST "${BASE}/api/playbooks/PB-004/run" \
  -H 'Content-Type: application/json' -d '{"mode":"DRY_RUN"}')
DRY_RB_ID=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['run_id'])" "${dry_rb}" 2>/dev/null)
check_code "回滚 DRY-RUN → 400" 400 -X POST "${BASE}/api/runs/${DRY_RB_ID}/rollback" \
  -H 'Content-Type: application/json' -d '{}'

echo "==> 审批队列与审计"
check_json "审批队列非空" /api/approvals "d['count'] > 0"
check_json "审批含受控动作类型" "/api/approvals?decision=APPROVED" \
  "all(a['gated_action_types'] for a in d['approvals'])"
check_json "审计按 ID 倒序" /api/audit \
  "[e['audit_id'] for e in d['entries']] == sorted([e['audit_id'] for e in d['entries']], reverse=True)"
check_json "审计含每步执行记录" "/api/audit?action=execute_step" "d['count'] > 0"
check_json "审计含批准记录" "/api/audit?action=approve" "d['count'] > 0"
check_json "执行实例带完整审计轨迹" /api/runs/RUN-000002 \
  "any(a['action']=='run_start' for a in d['audit']) and any(a['action']=='execute_step' for a in d['audit'])"
check_json "执行实例带审批记录" /api/runs/RUN-000002 "len(d['approvals']) >= 1"

echo "==> Dashboard 与诚实性声明"
check "GET /" /
check "GET /openapi.json" /openapi.json
check_body "首页声明演示数据" / "合成演示数据"
check_body "首页声明未对接真实产品" / "没有对接任何真实"
check_body "首页声明执行器为模拟器" / "本地确定性模拟器"

echo
echo "================================"
echo "  通过: ${PASS}    失败: ${FAIL}"
echo "================================"
[[ "${FAIL}" -eq 0 ]] || exit 1