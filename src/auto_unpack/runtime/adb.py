#!/usr/bin/env python3
"""adb 设备操作：包列表、安装、从安装日志取包名。

不做任何 APK 解析（包名解析在 pkg_name.py）。
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .proc import run as proc_run


def find_tool(name: str) -> str:
    found = shutil.which(name)
    return found or name  # 找不到也返回名字，交给 subprocess 报清晰错误


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"[cmd] {' '.join(cmd)}")
    return proc_run(cmd, **kw)


def list_packages(device: str | None = None) -> set[str]:
    """adb pm list packages，失败返回空集。"""
    adb = find_tool("adb")
    cmd = [adb]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages"]
    try:
        p = proc_run(
            cmd, capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return set()
    out: set[str] = set()
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            name = line.split(":", 1)[1].strip()
            if name:
                out.add(name)
    return out


def ensure_installed(apk_path: str, device: str | None) -> str | None:
    """adb install -r。返回包名：新装 diff 一个，或从 logcat 解析覆盖安装。"""
    before = list_packages(device)
    adb = find_tool("adb")
    base = [adb]
    if device:
        base += ["-s", device]
    # 清 logcat，便于覆盖安装时从 PackageManager 日志取包名
    try:
        proc_run(base + ["logcat", "-c"], capture_output=True, text=True, timeout=10)
    except Exception:
        pass
    cmd = base + ["install", "-r", "-g", apk_path]
    try:
        p = run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("adb install 超时") from e
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0 and "Success" not in out:
        raise RuntimeError(f"adb install 失败: {out.strip()}")
    after = list_packages(device)
    new = after - before
    if len(new) == 1:
        return next(iter(new))
    pkg = _package_from_install_logcat(device)
    if pkg and pkg in after:
        return pkg
    return None


_INSTALL_LOG_PKG = re.compile(
    r"(?:Update package|Adding package to system:|package installed(?: for user \d+)?:?)\s+"
    r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)",
    re.I,
)
_INSTALL_FORCE_STOP = re.compile(
    r"Force stopping ([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+) "
    r"appid=\d+.*installPackageLI",
    re.I,
)


def _package_from_install_logcat(device: str | None) -> str | None:
    """覆盖安装时 package 列表不变，从刚写入的 PackageManager 日志取包名。"""
    adb = find_tool("adb")
    cmd = [adb]
    if device:
        cmd += ["-s", device]
    cmd += ["logcat", "-d", "-t", "300"]
    try:
        p = proc_run(cmd, capture_output=True, text=True, timeout=20)
    except Exception:
        return None
    text = (p.stdout or "") + "\n" + (p.stderr or "")
    found: list[str] = []
    for rx in (_INSTALL_FORCE_STOP, _INSTALL_LOG_PKG):
        found.extend(m.group(1) for m in rx.finditer(text))
    if not found:
        return None
    # 取最后一次命中（刚装的）
    return found[-1]


def maybe_install(apk_path: str | None, device: str | None,
                  *, package: str | None = None, install=None) -> str | None:
    """按 install 模式决定是否 adb install。never 直接返回 None。

    when_needed：设备上已有 package 则跳过；always：一律 install -r。
    install=None 时读 env.json。
    """
    from .env import load, parse_install, should_install
    if not apk_path:
        return None
    mode = parse_install(install) if install is not None else load()["install"]
    on_device = list_packages(device) if mode == "when_needed" else None
    if not should_install(mode, package, on_device):
        if mode == "never":
            print("[*] install=never，跳过安装")
        elif package:
            print(f"[*] 设备已有 {package}，跳过安装")
        return None
    print(f"[*] adb install -r ({mode}) ...")
    return ensure_installed(apk_path, device)


def uninstall(package: str, device: str | None = None) -> bool:
    """adb uninstall <package>。成功返回 True，失败返回 False（不抛异常）。"""
    adb = find_tool("adb")
    base = [adb]
    if device:
        base += ["-s", device]
    cmd = base + ["uninstall", package]
    try:
        p = run(cmd, capture_output=True, text=True, timeout=60)
    except Exception:
        return False
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode == 0 and "Success" in out
