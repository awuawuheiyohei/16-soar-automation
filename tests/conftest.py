"""pytest fixtures —— 每个测试会话使用独立 DB，避免污染演示数据"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 必须在 import app.* 之前设置，否则 db.py 会用默认路径
os.environ.setdefault("SOAR_DB", str(ROOT / "data" / "test_soar.db"))
os.environ.setdefault("SKIP_SEED", "1")


@pytest.fixture(scope="session")
def seeded_db():
    """整个测试会话共用一个已 seed 的库"""
    from app.models.db import DB_PATH
    from app.models.seed import seed_all
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(DB_PATH) + suffix)
        if p.exists():
            p.unlink()
    counts = seed_all()
    yield counts
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(DB_PATH) + suffix)
        if p.exists():
            p.unlink()


@pytest.fixture(scope="session")
def client(seeded_db):
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def conn(seeded_db):
    """独立的一条连接，供不需要 HTTP 层的测试直接调用引擎"""
    from app.models.db import db_connection
    with db_connection() as c:
        yield c