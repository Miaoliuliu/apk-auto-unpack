"""env.json 配置解析：uninstall 等新字段的默认值与覆盖行为。"""
from __future__ import annotations

from auto_unpack.runtime import env


def test_default_uninstall_true():
    assert env._normalize({})["uninstall"] is True


def test_uninstall_explicit_false():
    assert env._normalize({"uninstall": False})["uninstall"] is False


def test_uninstall_string_false():
    assert env._normalize({"uninstall": "false"})["uninstall"] is False


def test_uninstall_string_true():
    assert env._normalize({"uninstall": "on"})["uninstall"] is True


def test_uninstall_ignores_unknown_keys():
    cfg = env._normalize({"uninstall": True, "_private": 1, "nope": 2})
    assert cfg["uninstall"] is True
    assert "nope" not in cfg


def test_parse_bool_default_true():
    assert env.parse_bool(None, default=True) is True
    assert env.parse_bool("yes", default=True) is True
    assert env.parse_bool("off", default=True) is False
