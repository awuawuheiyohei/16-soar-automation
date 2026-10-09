"""
手写 application/x-www-form-urlencoded 解析器。

为什么不用 python-multipart：
FastAPI 的 Form(...) / FormData 依赖 python-multipart，一个纯粹为了解析
几个键值对而引入的额外依赖。本项目只需要最简单的情况，因此直接用标准库
urllib.parse 解析原始 body —— 零新增依赖，也少一处供应链面。

刻意不支持：
- 重复 key（取最后一个，与常见 Web 框架行为一致）
- 文件上传 multipart/form-data（本平台没有此需求）
- 嵌套结构
"""
from __future__ import annotations

from urllib.parse import parse_qsl

# 表单值长度上限，防止有人往解析器里灌 100MB 的 body
MAX_FORM_BYTES = 64 * 1024


def parse_urlencoded(body: bytes | str) -> dict:
    """
    >>> parse_urlencoded(b"actor=alice&reason=ok")
    {'actor': 'alice', 'reason': 'ok'}
    """
    if isinstance(body, bytes):
        if len(body) > MAX_FORM_BYTES:
            raise ValueError(f"form body too large: {len(body)} bytes")
        body = body.decode("utf-8", errors="replace")
    # keep_blank_values=True：approver= 应当得到 "" 而不是被丢掉
    pairs = parse_qsl(body, keep_blank_values=True)
    result: dict = {}
    for k, v in pairs:
        result[k] = v
    return result