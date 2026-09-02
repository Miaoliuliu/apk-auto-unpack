#!/usr/bin/env python3
"""APK 包名解析 + 可信度标注：androguard → aapt → 裸 AXML → 字符串池启发式。

只做静态解析，不碰 adb（设备操作在 adb.py）。
供 pipeline / packer_sigs / spawn 前的包名决策使用。
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .proc import run as proc_run

# 应用包名：至少两段，排除权限/框架类字符串（畸形 AXML 只能靠字符串池猜时用）
_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
_PKG_BLOCK = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "dalvik.",
    "com.android.", "org.xmlpull.", "org.apache.", "org.json.",
)
# 畸形 Manifest 字符串池里经常先扫到 SDK 包名（定位、推送），不能拿去 spawn。
_PKG_SDK_PREFIXES = (
    "com.baidu.location", "com.baidu.lbsapi", "com.baidu.mapapi",
    "com.amap.api", "com.tencent.map",
    "com.google.android", "com.google.firebase", "com.google.gms",
    "com.facebook.react", "com.facebook.fresco",
    "com.umeng.", "cn.jpush.", "com.igexin.",
    "io.dcloud.", "com.stub.", "com.qihoo.util", "com.qihoo360.",
    "com.tencent.stubshell", "com.huawei.hms", "com.huawei.agconnect",
    "com.xiaomi.mipush", "com.bun.miitmdid", "com.blankj.utilcode",
    "org.chromium.",
)


def _looks_like_sdk_package(s: str) -> bool:
    """SDK 包名，或畸形 Manifest 在前面加了垃圾字符（Kcom.google.android...）。"""
    low = (s or "").lower()
    if any(low.startswith(p) for p in _PKG_SDK_PREFIXES):
        return True
    m = re.search(r"(com\.|org\.|io\.|cn\.)", low)
    if not m:
        return False
    trimmed = low[m.start():]
    return any(trimmed.startswith(p) for p in _PKG_SDK_PREFIXES)


def _looks_like_app_package(s: str) -> bool:
    if not s or len(s) > 200 or not _PKG_RE.match(s):
        return False
    low = s.lower()
    if any(tok in low for tok in ("permission", "intent", "widget", "webkit", "hardware")):
        return False
    last = low.rsplit(".", 1)[-1]
    if last.endswith(("activity", "service", "receiver", "provider", "application")):
        return False
    if _looks_like_sdk_package(s):
        return False
    return not any(low.startswith(p) for p in _PKG_BLOCK)


def _iter_aapt() -> list[str]:
    """PATH + 本仓库 toolchain + ANDROID_HOME/build-tools。"""
    seen: list[str] = []
    for name in ("aapt", "aapt2"):
        p = shutil.which(name)
        if p:
            seen.append(p)
    from .env import PROJECT_ROOT
    for cand in (
        PROJECT_ROOT / "toolchain" / "android-14" / "aapt2.exe",
        PROJECT_ROOT / "toolchain" / "android-14" / "aapt.exe",
        PROJECT_ROOT / "toolchain" / "android-14" / "aapt2",
        PROJECT_ROOT / "toolchain" / "android-14" / "aapt",
    ):
        if cand.exists():
            seen.append(str(cand))
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk:
        bt = Path(sdk) / "build-tools"
        if bt.is_dir():
            for d in sorted(bt.iterdir(), reverse=True):
                for name in ("aapt.exe", "aapt2.exe", "aapt", "aapt2"):
                    c = d / name
                    if c.exists():
                        seen.append(str(c))
    # 去重保序
    out, used = [], set()
    for p in seen:
        if p not in used:
            used.add(p)
            out.append(p)
    return out


def _package_from_aapt(apk_path: str) -> str | None:
    for aapt in _iter_aapt():
        try:
            p = proc_run(
                [aapt, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            continue
        # aapt 是 package: name='...'；aapt2 有时是 package  name='...'
        m = re.search(r"package:\s+name='([^']+)'", p.stdout or "")
        if m and _looks_like_app_package(m.group(1)):
            return m.group(1)
    return None


def _package_from_axml_attr(data: bytes) -> str | None:
    """只信 AXML 解析出的 package 属性，不扫字符串池。"""
    try:
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(data)
        if printer.is_valid():
            obj = printer.get_xml_obj()
            if obj is not None:
                pkg = obj.get("package")
                if pkg and _looks_like_app_package(str(pkg)):
                    return str(pkg)
            xml = printer.get_xml()
            if isinstance(xml, bytes):
                xml = xml.decode("utf-8", errors="replace")
            m = re.search(r'\bpackage="([^"]+)"', xml or "")
            if m and _looks_like_app_package(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    return None


def _package_from_axml(data: bytes) -> str | None:
    """解析二进制 AndroidManifest：先 AXMLPrinter，失败再扫字符串池。"""
    pkg = _package_from_axml_attr(data)
    if pkg:
        return pkg
    return _package_from_raw_strings(data)


def _package_from_raw_strings(data: bytes) -> str | None:
    """畸形 AXML 兜底：从 UTF-16LE / ASCII 里挑最像应用包名的串。"""
    hits: list[tuple[int, str]] = []

    i, n = 0, len(data)
    while i + 4 <= n:
        if data[i + 1] == 0 and 32 <= data[i] < 127:
            chars = []
            j = i
            while j + 1 < n and data[j + 1] == 0 and 32 <= data[j] < 127:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= 3:
                s = "".join(chars)
                if _looks_like_app_package(s):
                    hits.append((i, s))
            i = j if j > i else i + 2
        else:
            i += 1

    for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", data):
        s = m.group(0).decode("ascii", errors="ignore")
        if _looks_like_app_package(s):
            hits.append((m.start(), s))

    if not hits:
        return None
    hits.sort(key=lambda t: t[0])
    # 去重保序
    seen: set[str] = set()
    ordered: list[str] = []
    for _, s in hits:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return ordered[0]


def _pkg_info(package: str | None, source: str | None, trusted: bool,
              note: str = "") -> dict:
    return {
        "package": package,
        "package_source": source,
        "package_trusted": bool(trusted and package),
        "package_note": note,
    }


def get_package_info(apk_path: str) -> dict:
    """取包名并标注可信度。

    androguard / aapt / AXML 的 package 属性视为可信；
    畸形 Manifest 字符串池猜测不可信（可能扫到 com.baidu.location.f 这类 SDK 名）。
    """
    leftover_sdk: tuple[str, str] | None = None

    try:
        from androguard.core.apk import APK
        pkg = APK(apk_path).get_package()
        if pkg and _looks_like_app_package(pkg):
            return _pkg_info(pkg, "androguard", True)
        if pkg and _looks_like_sdk_package(pkg):
            leftover_sdk = (pkg, "androguard")
    except Exception:
        pass

    pkg = _package_from_aapt(apk_path)
    if pkg:
        return _pkg_info(pkg, "aapt", True)

    try:
        import zipfile
        with zipfile.ZipFile(apk_path) as z:
            raw = z.read("AndroidManifest.xml")
        pkg = _package_from_axml_attr(raw)
        if pkg:
            return _pkg_info(pkg, "axml", True)
        pkg = _package_from_raw_strings(raw)
        if pkg:
            return _pkg_info(
                pkg, "heuristic", False,
                "畸形 Manifest 字符串池猜测，spawn 前请用 --package 确认",
            )
    except Exception:
        pass

    if leftover_sdk:
        return _pkg_info(
            leftover_sdk[0], leftover_sdk[1], False,
            "像 SDK 包名，不能用来 spawn",
        )
    return _pkg_info(None, None, False, "未能解析包名")


def resolve_spawn_package_info(apk_path: str | None, package: str | None,
                               installed_pkg: str | None = None) -> dict:
    """决定 spawn 用的包名，并带上可信度。

    CLI --package 与 adb 新装包名视为可信；APK 解析沿用 get_package_info。
    启发式 / SDK 包名不能用来 spawn（动态脱壳应先 install 再拿设备包名）。
    """
    if package:
        return _pkg_info(package, "cli", True)
    if installed_pkg:
        return _pkg_info(installed_pkg, "adb_install", True)
    info = get_package_info(apk_path) if apk_path else _pkg_info(None, None, False)
    if info.get("package_trusted") and info.get("package"):
        return info
    guessed = info.get("package")
    if guessed:
        src = info.get("package_source") or "unknown"
        note = info.get("package_note") or "包名不可信"
        raise RuntimeError(
            f"解析到的包名 {guessed} 不可信（来源={src}，{note}），请用 --package 指定真实包名"
        )
    raise RuntimeError(
        "无法确定包名（畸形 Manifest 常见于魔改 dpt-shell），请用 --package 指定"
    )
