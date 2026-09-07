"""run.py 一键启动：内嵌配置 → 命令行参数构造的行为锁定。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_run_launcher", ROOT / "run.py")
_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_run)


def test_build_argv_default():
    argv = _run._build_argv({
        "unpack": True, "install": "when_needed",
        "skip_apkid": False, "recursive": False,
    })
    assert argv == ["analyze", "--unpack", "--install", "when_needed"]


def test_build_argv_skip_apkid_recursive():
    argv = _run._build_argv({
        "unpack": True, "install": "always",
        "skip_apkid": True, "recursive": True,
    })
    assert argv == ["analyze", "--unpack", "--install", "always",
                    "--skip-apkid", "-r"]


def test_build_argv_no_unpack():
    argv = _run._build_argv({
        "unpack": False, "install": "when_needed",
        "skip_apkid": False, "recursive": False,
    })
    assert argv == ["analyze", "--install", "when_needed"]
