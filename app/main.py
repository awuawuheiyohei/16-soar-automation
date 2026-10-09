"""FastAPI 应用入口 —— SOAR 自动化响应平台"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router
from .models.seed import seed_all

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "static"

app = FastAPI(
    title="SOAR Automation & Response Platform",
    version="1.0.0",
    description=(
        "受控自动化响应平台：告警摄取去重 → Playbook 编排 → 人工审批门 → "
        "幂等执行与补偿回滚 → 全链路审计 → 误报回哺调优。\n\n"
        "**数据与执行说明**：默认加载的是**合成演示数据**（账号、主机、IP、"
        "告警载荷均为虚构）。本项目**没有对接任何真实 SIEM / SOAR / EDR / IdP 产品**"
        "（Splunk、Sentinel、Cortex XDR 等均未接入），playbook 中的所有 action "
        "由本地确定性模拟器执行，不产生任何真实系统变更。"
    ),
)
app.include_router(router)


@app.get("/", include_in_schema=False)
def dashboard():
    if (STATIC_DIR / "index.html").exists():
        return FileResponse(STATIC_DIR / "index.html")
    return {"detail": "static/index.html not found", "docs": "/docs"}


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def run(host: str = "127.0.0.1", port: int = 5053, reload: bool = False):
    import uvicorn
    if not os.environ.get("SKIP_SEED"):
        seed_all()
    uvicorn.run("app.main:app", host=host, port=port, reload=reload)