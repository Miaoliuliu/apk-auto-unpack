#!/usr/bin/env python3
"""样本接入：校验 ZIP/APK、计算哈希、确定任务目录。不拷贝大 APK。"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from ..runtime.product import (
    safe_product_stem,
    default_url_dir,
)
from .states import (
    E_NO_MANIFEST,
    E_NOT_FOUND,
    E_NOT_ZIP,
    E_TOO_LARGE,
    E_VALIDATE,
    E_ZIP_BOMB,
)

MAX_APK_BYTES = 512 * 1024 * 1024
MIN_APK_BYTES = 8 * 1024
MAX_ZIP_ENTRIES = 30_000
MAX_ZIP_ENTRIES_HARD = 100_000
MAX_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024
_HTML_HEADS = (b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML")


class SampleError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def hash_file(path: str | Path) -> dict:
    p = Path(path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with p.open("rb") as f:
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            size += len(buf)
            md5.update(buf)
            sha1.update(buf)
            sha256.update(buf)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": size,
    }


def validate_apk(path: str | Path) -> dict:
    """通过则返回 {names, has_dex}；失败抛 SampleError。"""
    p = Path(path)
    if not p.is_file():
        raise SampleError(E_NOT_FOUND, f"文件不存在: {p}")
    try:
        size = p.stat().st_size
    except OSError as e:
        raise SampleError(E_VALIDATE, str(e)) from e
    if size <= 0:
        raise SampleError(E_VALIDATE, "空文件")
    if size > MAX_APK_BYTES:
        raise SampleError(E_TOO_LARGE, f"超过 {MAX_APK_BYTES} 字节上限")
    with p.open("rb") as f:
        head = f.read(64)
    magic = head[:4]
    stripped = head.lstrip()
    if any(stripped.startswith(h) for h in _HTML_HEADS):
        raise SampleError(E_NOT_ZIP, "无效样本：内容是 HTML 而非 APK（常见于下载失败页）")
    if magic[:2] != b"PK":
        if size < MIN_APK_BYTES:
            raise SampleError(E_NOT_ZIP, "无效样本：体积过小且不是 ZIP（常见于下载失败页）")
        raise SampleError(E_NOT_ZIP, "不是 ZIP/APK（缺少 PK 头）")
    try:
        zf = zipfile.ZipFile(p)
    except zipfile.BadZipFile as e:
        raise SampleError(E_NOT_ZIP, f"ZIP 损坏: {e}") from e
    with zf:
        names = zf.namelist()
        norm = [n.replace("\\", "/").lstrip("/") for n in names]
        warnings: list[str] = []
        if len(names) > MAX_ZIP_ENTRIES_HARD:
            raise SampleError(E_ZIP_BOMB, f"ZIP 条目过多: {len(names)}")
        if len(names) > MAX_ZIP_ENTRIES:
            if "AndroidManifest.xml" not in norm:
                raise SampleError(E_ZIP_BOMB, f"ZIP 条目过多: {len(names)}")
            warnings.append(
                f"ZIP 条目过多: {len(names)}（阈值 {MAX_ZIP_ENTRIES}），"
                "已降级继续识别，请人工复核"
            )
        uncompressed = 0
        for info in zf.infolist():
            uncompressed += max(info.file_size, 0)
            if uncompressed > MAX_UNCOMPRESSED:
                raise SampleError(E_ZIP_BOMB, "解压体积超过上限")
        if "AndroidManifest.xml" not in norm:
            raise SampleError(E_NO_MANIFEST, "缺少 AndroidManifest.xml")
        has_dex = any(
            n.startswith("classes") and n.endswith(".dex") for n in norm
        )
    return {
        "entry_count": len(names),
        "has_dex": has_dex,
        "uncompressed": uncompressed,
        "warnings": warnings,
    }


def ingest(apk_path: str | Path, *, out_dir: str | None = None,
           package: str | None = None, trusted: bool = False) -> dict:
    """校验 + 哈希。返回 sample 字典（含 url_dir / out_dir）。

    url_dir：只放 urls_by_rank.txt，默认 extracted_urls/<apk名>/（可 -o 覆盖）
    dex_dir：仅在真正动态脱壳时由 pipeline 再写入 unpacked_dex/<apk名>/
    """
    p = Path(apk_path).resolve()
    info = validate_apk(p)
    hashes = hash_file(p)
    stem = safe_product_stem(str(p), package, trusted)
    url_dest = Path(out_dir) if out_dir else default_url_dir(str(p), package, trusted)
    # URL 目录延后到真正写出 urls_by_rank.txt 时再创建
    meta = read_apk_meta(p)
    pkg = package or meta.get("package_name")
    return {
        "path": str(p),
        "filename": p.name,
        "stem": stem,
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "size": hashes["size"],
        "entry_count": info["entry_count"],
        "has_dex": info["has_dex"],
        "uncompressed": info["uncompressed"],
        "out_dir": str(url_dest),
        "url_dir": str(url_dest),
        "dex_dir": None,
        "package_name": pkg,
        "version_name": meta.get("version_name"),
        "version_code": meta.get("version_code"),
        "min_sdk": meta.get("min_sdk"),
        "target_sdk": meta.get("target_sdk"),
        "app_name": meta.get("app_name"),
        "warnings": list(info.get("warnings") or []),
    }


def read_apk_meta(path: str | Path) -> dict:
    """包名 / 版本 / minSdk / targetSdk。解析失败则字段为 None，不阻断流水线。"""
    out = {
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "app_name": None,
    }
    try:
        from androguard.core.apk import APK
        apk = APK(str(path))
    except Exception:
        return out
    try:
        out["package_name"] = apk.get_package()
    except Exception:
        pass
    try:
        out["version_name"] = apk.get_androidversion_name()
    except Exception:
        pass
    try:
        out["version_code"] = apk.get_androidversion_code()
    except Exception:
        pass
    try:
        out["min_sdk"] = apk.get_min_sdk_version()
    except Exception:
        pass
    try:
        out["target_sdk"] = apk.get_target_sdk_version()
    except Exception:
        pass
    try:
        out["app_name"] = apk.get_app_name()
    except Exception:
        pass
    return out
