#!/usr/bin/env python3
"""设备环境配置：adb 是否安装、设备 ID、spawn 等待秒数。

配置文件：项目根目录 env.json（也可放在当前工作目录）。

    {
      "device": null,           // 空 = USB 第一台；多设备时填 adb/frida 设备 ID
      "install": "when_needed", // never | when_needed | always
      "sleep": 10,              // spawn 后等待秒数（360：等主页面加载再 dump）
      "unpack": false,          // 默认不动态执行 APK；要脱壳需 --unpack
      "uninstall": true,        // 脱壳完成后卸载本次 adb install 装的 app（设备原有的不动）
      "timeout": 300            // 有壳分析超时秒数
    }

install 取值：
    never        从不 adb install（包必须已在设备上）
    when_needed  仅动态脱壳且设备上没有该包时安装（默认）
    always       脱壳前一律 adb install -r

兼容旧写法：false/0 → never，true/1 → always。
命令行可 --install / --install when_needed / --no-install 覆盖本次运行。
无壳走 static 时根本不会调用安装。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def project_root() -> Path:
    """仓库根目录：有 pyproject.toml / env.json 的那一层；安装到 site-packages 时用 cwd。"""
    here = Path(__file__).resolve()
    for p in here.parents:
        if (p / "pyproject.toml").is_file():
            return p
        if (p / "env.example.json").is_file() or (p / "env.json").is_file():
            return p
    return Path.cwd()


PROJECT_ROOT = project_root()
SCRIPT_DIR = PACKAGE_DIR

INSTALL_NEVER = "never"
INSTALL_WHEN_NEEDED = "when_needed"
INSTALL_ALWAYS = "always"
INSTALL_MODES = (INSTALL_NEVER, INSTALL_WHEN_NEEDED, INSTALL_ALWAYS)

DEFAULTS: dict = {
    "device": None,
    "install": INSTALL_WHEN_NEEDED,
    "sleep": 10,
    "unpack": False,
    "uninstall": True,
    "timeout": 300,
}

_cache: dict | None = None
_cache_path: Path | None = None


def parse_install(value) -> str:
    """把 env / CLI 各种写法收成 never | when_needed | always。"""
    if value is True or value == 1:
        return INSTALL_ALWAYS
    if value is False or value == 0 or value is None:
        return INSTALL_NEVER
    s = str(value).strip().lower().replace("-", "_")
    if s in ("true", "yes", "always", "1"):
        return INSTALL_ALWAYS
    if s in ("false", "no", "never", "0", ""):
        return INSTALL_NEVER
    if s in ("when_needed", "auto", "needed"):
        return INSTALL_WHEN_NEEDED
    if s in INSTALL_MODES:
        return s
    return INSTALL_WHEN_NEEDED


def should_install(mode, package: str | None, on_device: set[str] | None) -> bool:
    """是否该对当前包执行 adb install。"""
    mode = parse_install(mode)
    if mode == INSTALL_NEVER:
        return False
    if mode == INSTALL_ALWAYS:
        return True
    if package and on_device is not None and package in on_device:
        return False
    return True


def parse_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if value in (1, 0):
        return bool(value)
    s = str(value).strip().lower()
    if s in ("true", "yes", "1", "on"):
        return True
    if s in ("false", "no", "0", "off", ""):
        return False
    return default


def add_unpack_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "--unpack", action="store_true", default=None,
        help="显式启用动态脱壳（默认关闭，不执行 APK）",
    )
    g.add_argument(
        "--skip-unpack", action="store_true",
        help="只识别+静态提取，不 spawn（默认行为）",
    )
    parser.add_argument(
        "--force-unpack", action="store_true",
        help="packed=unknown 时仍尝试动态脱壳",
    )
    parser.add_argument(
        "--timeout", type=int, help="覆盖 env.json 的 timeout（秒）",
    )


def add_install_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "--install", nargs="?", const=INSTALL_ALWAYS, default=None,
        metavar="MODE",
        help="覆盖 env.json：不带值=always；可填 never / when_needed / always",
    )
    g.add_argument("--no-install", action="store_true",
                   help="本次不 adb install")


def unpack_from_args(args) -> bool | None:
    """True=启用动态脱壳，False=关闭，None=沿用 env.json。"""
    if getattr(args, "skip_unpack", False):
        return False
    if getattr(args, "unpack", None):
        return True
    return None


def install_from_args(args) -> str | None:
    """CLI 覆盖值；None 表示沿用 env.json。"""
    if getattr(args, "no_install", False):
        return INSTALL_NEVER
    raw = getattr(args, "install", None)
    if raw is None:
        return None
    return parse_install(raw)


def config_path() -> Path:
    """已有配置文件的路径；都没有则返回项目根 env.json（供提示）。"""
    for cand in (
        Path.cwd() / "env.json",
        PROJECT_ROOT / "env.json",
        PACKAGE_DIR / "env.json",
    ):
        if cand.is_file():
            return cand
    return PROJECT_ROOT / "env.json"


def _normalize(raw: dict) -> dict:
    cfg = dict(DEFAULTS)
    for k, v in raw.items():
        if str(k).startswith("_"):
            continue
        if k not in DEFAULTS:
            continue
        cfg[k] = v
    device = cfg.get("device")
    if device is not None:
        device = str(device).strip() or None
    cfg["device"] = device
    cfg["install"] = parse_install(cfg.get("install"))
    cfg["unpack"] = parse_bool(cfg.get("unpack"), default=False)
    cfg["uninstall"] = parse_bool(cfg.get("uninstall"), default=True)
    try:
        cfg["sleep"] = int(cfg.get("sleep") or DEFAULTS["sleep"])
    except (TypeError, ValueError):
        cfg["sleep"] = DEFAULTS["sleep"]
    if cfg["sleep"] < 1:
        cfg["sleep"] = DEFAULTS["sleep"]
    try:
        cfg["timeout"] = int(cfg.get("timeout") or DEFAULTS["timeout"])
    except (TypeError, ValueError):
        cfg["timeout"] = DEFAULTS["timeout"]
    if cfg["timeout"] < 1:
        cfg["timeout"] = DEFAULTS["timeout"]
    return cfg


def load(path: Path | None = None, *, reload: bool = False) -> dict:
    """读 env.json，缺项用 DEFAULTS。返回新 dict，调用方可改。"""
    global _cache, _cache_path
    src = Path(path) if path else config_path()
    if not reload and _cache is not None and path is None:
        return dict(_cache)
    data: dict = {}
    if src.is_file():
        try:
            loaded = json.loads(src.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}
    cfg = _normalize(data)
    if path is None:
        _cache = dict(cfg)
        _cache_path = src
    return cfg


def resolve(*, device: str | None = None, sleep: int | None = None,
            install: str | None = None, unpack: bool | None = None,
            timeout: int | None = None) -> dict:
    """环境配置 + 命令行覆盖。"""
    cfg = load()
    if device:
        cfg["device"] = str(device).strip() or None
    if sleep is not None:
        cfg["sleep"] = int(sleep)
    if install is not None:
        cfg["install"] = parse_install(install)
    if unpack is not None:
        cfg["unpack"] = bool(unpack)
    if timeout is not None:
        cfg["timeout"] = int(timeout)
    return cfg


def describe(cfg: dict | None = None) -> str:
    c = cfg if cfg is not None else load()
    src = _cache_path or config_path()
    loc = src if src.is_file() else f"{src}（未找到，用默认值）"
    dev = c.get("device") or "USB"
    return (
        f"unpack={c.get('unpack')} install={c['install']} "
        f"device={dev} sleep={c['sleep']}s timeout={c.get('timeout')}s  <- {loc}"
    )
