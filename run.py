#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
【一键启动】auto-unpack 全流程

用法：把 APK 丢进 APK/ 目录，然后在 PyCharm 里点运行本文件（或终端 python run.py）。

自动完成（无需任何命令行参数）：
    识别壳 → dpt-shell 自动 frida 脱壳 → 提取 URL
           → 无壳直接静态提取 URL
           → 厂商壳 / 自研保护 / VMP 转人工（不抽 URL）

产物（自动落在 outputs/ 下）：
    outputs/packer_detection/<壳名>/      壳识别归档
    outputs/extracted_urls/<apk名>/       URL 清单（urls_by_rank.txt）
    outputs/unpacked_dex/<apk名>/         脱壳 dex（仅 dpt-shell 脱壳成功时）

运行前提：
    1. PyCharm 解释器选「系统 Python 3.10」：C:/Program Files/Python310/python.exe
       （这是唯一同时装了 frida + androguard + auto_unpack 的环境）
    2. 真机 USB 连着（adb devices 能看到设备）
    3. dpt 脱壳需要 frida-server 以 root 运行，否则 dpt 样本会自动转人工（不影响无壳样本）
"""

import os
import sys
from pathlib import Path

# 1) 定位项目根目录并切换过去（不依赖 PyCharm 的工作目录设置）
ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

# 2) 把 src/ 加进 import 路径（src 布局；即使没 editable 安装也能 import auto_unpack）
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# 3) 内嵌配置 —— 全部参数都在这里，无需命令行、无需手动调参
CONFIG = {
    "unpack": True,             # True = 有壳自动脱壳（dpt-shell）
    "install": "when_needed",   # never / when_needed / always：脱壳前是否 adb install
    "skip_apkid": False,        # False = 跑 APKiD 补强（需能联网 / 已开代理）
    "recursive": False,         # True = 递归读 APK/ 子目录
}


def _preflight() -> None:
    """启动自检 + 横幅：打印环境状态，不阻塞流程。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    inbox = ROOT / "APK"
    from auto_unpack.runtime.product import list_apk_files
    apks = list_apk_files(inbox) if inbox.is_dir() else []

    print("=" * 64)
    print("  auto-unpack 一键全流程")
    print("=" * 64)
    print(f"  项目根目录 : {ROOT}")
    print(f"  APK 输入   : {inbox}")
    print(f"  待处理样本 : {len(apks)} 个 .apk")
    print(f"  内嵌参数   : unpack={CONFIG['unpack']} "
          f"install={CONFIG['install']} skip_apkid={CONFIG['skip_apkid']}")

    try:
        import frida
        print(f"  frida      : {frida.__version__}（可动态脱壳）")
    except Exception:
        print("  frida      : 未安装 → dpt 脱壳不可用，会自动转人工。"
              "请把 PyCharm 解释器切到系统 Python 3.10")

    import shutil
    print("  adb        : " + ("已找到" if shutil.which("adb") else "未找到（脱壳/装包需要 adb）"))
    print("=" * 64)

    if not apks:
        print("[提示] APK/ 目录为空，请先放入 .apk 文件，再点运行。")
        sys.exit(0)


def _build_argv(config: dict) -> list[str]:
    """把内嵌配置转成内部命令行参数（用户无需手动输入）。"""
    argv = ["analyze"]
    if config.get("unpack"):
        argv.append("--unpack")
    if config.get("install"):
        argv += ["--install", config["install"]]
    if config.get("skip_apkid"):
        argv.append("--skip-apkid")
    if config.get("recursive"):
        argv.append("-r")
    return argv


def main() -> int:
    _preflight()

    from auto_unpack.flow.cli import main as cli_main

    return cli_main(_build_argv(CONFIG))


if __name__ == "__main__":
    raise SystemExit(main())
