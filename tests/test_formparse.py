"""手写 url-encoded 解析器测试"""
import pytest

from app.models.formparse import MAX_FORM_BYTES, parse_urlencoded


def test_parses_simple_form():
    assert parse_urlencoded(b"actor=alice&reason=ok") == {"actor": "alice", "reason": "ok"}


def test_accepts_str_input():
    assert parse_urlencoded("a=1&b=2") == {"a": "1", "b": "2"}


def test_decodes_percent_escapes():
    assert parse_urlencoded(b"approver=alice%40test.example")["approver"] == "alice@test.example"


def test_decodes_plus_as_space():
    assert parse_urlencoded(b"reason=form+approved")["reason"] == "form approved"


def test_keeps_blank_values():
    """approver= 应当得到空字符串而不是被静默丢弃 —— 否则审批人字段会变成 None"""
    assert parse_urlencoded(b"approver=&reason=x")["approver"] == ""


def test_duplicate_key_keeps_last():
    """与常见 Web 框架行为一致：重复 key 取最后一个"""
    assert parse_urlencoded(b"a=1&a=2")["a"] == "2"


def test_empty_body_returns_empty_dict():
    assert parse_urlencoded(b"") == {}


def test_no_equals_sign_treated_as_blank():
    assert parse_urlencoded(b"flag") == {"flag": ""}


def test_handles_unicode():
    assert parse_urlencoded("reason=%E5%9B%9E%E6%BB%9A".encode())["reason"] == "回滚"


def test_rejects_oversized_body():
    """防止有人往解析器里灌超大 body"""
    with pytest.raises(ValueError, match="too large"):
        parse_urlencoded(b"a=" + b"x" * (MAX_FORM_BYTES + 10))


def test_handles_invalid_utf8_without_raising():
    assert parse_urlencoded(b"k=%FF%FE")["k"] is not None


def test_no_multipart_dependency():
    """本项目刻意不引入 python-multipart —— 确认没被顺手装上"""
    import sys
    assert "multipart" not in sys.modules