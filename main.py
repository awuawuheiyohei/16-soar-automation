"""CLI 入口

用法：
    python main.py serve                 # 启动 FastAPI（端口 5053）
    python main.py seed                  # 仅重置演示数据
    python main.py stats                 # 打印告警/执行统计
    python main.py triage ALR-0001       # 解释某条告警的优先级评分
    python main.py playbooks             # 列出所有 playbook 及其审批门
    python main.py audit 20              # 查看最近 20 条审计记录
"""
from __future__ import annotations

import argparse
import json


def cmd_serve(args):
    from app.main import run
    print(f"[+] Dashboard: http://{args.host}:{args.port}/")
    print(f"[+] API docs : http://{args.host}:{args.port}/docs")
    run(host=args.host, port=args.port, reload=args.reload)


def cmd_seed(args):
    from app.models.seed import seed_all
    print(json.dumps(seed_all(verbose=True), ensure_ascii=False))


def cmd_stats(args):
    from app.models.db import db_connection
    with db_connection() as conn:
        alert_rows = conn.execute(
            "SELECT status, COUNT(*) n FROM alerts GROUP BY status ORDER BY n DESC"
        ).fetchall()
        run_rows = conn.execute(
            "SELECT status, COUNT(*) n FROM playbook_runs GROUP BY status ORDER BY n DESC"
        ).fetchall()
        rule_rows = conn.execute(
            """SELECT dr.rule_id,
                      COUNT(a.alert_id) total,
                      SUM(CASE WHEN a.status='FALSE_POSITIVE' THEN 1 ELSE 0 END) fp
               FROM detection_rules dr LEFT JOIN alerts a ON a.rule_id = dr.rule_id
               GROUP BY dr.rule_id ORDER BY dr.rule_id"""
        ).fetchall()

    print("== 告警状态 ==")
    for r in alert_rows:
        print(f"  {r['status']:<16}{r['n']}")

    print("== 执行状态 ==")
    for r in run_rows:
        print(f"  {r['status']:<16}{r['n']}")

    print("== 各规则误报情况 ==")
    print(f"  {'RULE':<10}{'TOTAL':<8}{'FP':<6}{'FP%':<8}")
    for r in rule_rows:
        total = r["total"] or 0
        fp = r["fp"] or 0
        pct = round(100.0 * fp / total, 1) if total else 0.0
        print(f"  {r['rule_id']:<10}{total:<8}{fp:<6}{pct:<8}")


def cmd_triage(args):
    from app.models.db import db_connection
    from app.models.triage import calculate_priority, count_corroborating, explain
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?",
                           (args.alert_id,)).fetchone()
        if not row:
            print(f"[!] alert {args.alert_id} not found")
            return
        alert = {k: row[k] for k in row.keys()}
        alert.update(calculate_priority(
            alert["severity"], alert["entity_type"], alert["entity_value"],
            count_corroborating(conn, args.alert_id), alert["detected_at"]))
    print(json.dumps({
        "alert_id": alert["alert_id"],
        "title": alert["title"],
        "severity": alert["severity"],
        "entity": f"{alert['entity_type']}:{alert['entity_value']}",
        "priority_score": alert["priority_score"],
        "priority_level": alert["priority_level"],
        "components": {
            "severity": alert["severity_component"],
            "entity": alert["entity_component"],
            "corroboration": alert["corroboration_component"],
            "recency": alert["recency_component"],
        },
        "explanation": explain(alert),
    }, ensure_ascii=False, indent=2))


def cmd_playbooks(args):
    from app.models.automation import playbook_actions, playbook_requires_approval
    from app.models.db import db_connection
    with db_connection() as conn:
        rows = conn.execute("SELECT * FROM playbooks ORDER BY playbook_id").fetchall()
        for r in rows:
            needs = playbook_requires_approval(conn, r["playbook_id"])
            acts = playbook_actions(conn, r["playbook_id"])
            print(f"\n[{r['playbook_id']}] {r['name']}  (触发: {r['trigger_rule_id']})")
            print(f"  {r['description']}")
            print(f"  审批门: {'需要人工批准' if needs else '无需审批（全部只读步骤）'}")
            for a in acts:
                flags = []
                if a["is_destructive"]:
                    flags.append("破坏性")
                if a["requires_approval"]:
                    flags.append("需审批")
                if a["compensating_action"]:
                    flags.append(f"补偿={a['compensating_action']}")
                tag = f"  [{'/'.join(flags)}]" if flags else ""
                print(f"    {a['step_no']}. {a['action_type']:<24}{a['description']}{tag}")


def cmd_audit(args):
    from app.models.db import db_connection
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT audit_id, occurred_at, actor, action, entity_type, entity_id "
            "FROM audit_log ORDER BY audit_id DESC LIMIT ?", (args.limit,)).fetchall()
    print(f"{'ID':<6}{'OCCURRED_AT':<28}{'ACTOR':<26}{'ACTION':<24}{'ENTITY'}")
    for r in rows:
        ent = f"{r['entity_type'] or ''}:{r['entity_id'] or ''}"
        print(f"{r['audit_id']:<6}{r['occurred_at']:<28}{str(r['actor'] or ''):<26}"
              f"{r['action']:<24}{ent}")


def main():
    parser = argparse.ArgumentParser(description="SOAR Automation & Response Platform")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("serve", help="启动 FastAPI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5053)
    p.add_argument("--reload", action="store_true")

    sub.add_parser("seed", help="重置演示数据")
    sub.add_parser("stats", help="告警/执行统计")
    sub.add_parser("playbooks", help="列出 playbook 与审批门")

    p = sub.add_parser("triage", help="解释某条告警的优先级评分")
    p.add_argument("alert_id")

    p = sub.add_parser("audit", help="查看审计日志")
    p.add_argument("limit", nargs="?", type=int, default=20)

    args = parser.parse_args()
    dispatch = {
        "serve": cmd_serve, "seed": cmd_seed, "stats": cmd_stats,
        "playbooks": cmd_playbooks, "triage": cmd_triage, "audit": cmd_audit,
    }
    dispatch.get(getattr(args, "command", None) or "stats", cmd_stats)(args)


if __name__ == "__main__":
    main()