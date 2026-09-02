#!/usr/bin/env python3
"""产物目录布局与壳识别归档：可读目录名、包名可信度命名、去重归档。

只管「产物落在哪、叫什么」以及「样本从哪读」
（APK/ unpacked_dex/ extracted_urls/ packer_detection/）。
脱壳产物的结构验证在 unpacker/validate.py；flow负责实际写出。
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path

from .env import PROJECT_ROOT

APK_INBOX_ROOT = "APK"
DEX_PRODUCT_ROOT = "unpacked_dex"
URL_PRODUCT_ROOT = "extracted_urls"
DETECT_RESULT_ROOT = "packer_detection"

# 测试隔离：AUTO_UNPACK_PRODUCT_ROOT=临时目录；AUTO_UNPACK_DISABLE_ARCHIVE=1 禁止壳识别归档
# AUTO_UNPACK_APK_INBOX=临时目录 覆盖默认 APK 存放入口（测试用，避免扫正式目录）
_ENV_PRODUCT_ROOT = "AUTO_UNPACK_PRODUCT_ROOT"
_ENV_DISABLE_ARCHIVE = "AUTO_UNPACK_DISABLE_ARCHIVE"
_ENV_APK_INBOX = "AUTO_UNPACK_APK_INBOX"


def product_root() -> Path:
    """产物根目录（outputs/）。测试可设 AUTO_UNPACK_PRODUCT_ROOT 指向临时目录，避免写进正式结果。"""
    override = (os.environ.get(_ENV_PRODUCT_ROOT) or "").strip()
    if override:
        return Path(override)
    return PROJECT_ROOT / "outputs"


def archive_enabled() -> bool:
    """是否允许把样本复制到 packer_detection/。测试应设 AUTO_UNPACK_DISABLE_ARCHIVE=1。"""
    v = (os.environ.get(_ENV_DISABLE_ARCHIVE) or "").strip().lower()
    return v not in ("1", "true", "yes", "on")


def default_apk_inbox() -> Path:
    """APK 存放入口。测试可设 AUTO_UNPACK_APK_INBOX；正式环境固定项目根 APK/。

    不跟 AUTO_UNPACK_PRODUCT_ROOT 走：那是产物隔离，入口目录要始终看得见。
    """
    override = (os.environ.get(_ENV_APK_INBOX) or "").strip()
    if override:
        return Path(override)
    return PROJECT_ROOT / APK_INBOX_ROOT


def ensure_apk_inbox(root: str | Path | None = None) -> Path:
    """保证存放目录存在，返回该路径。"""
    dest = Path(root) if root else default_apk_inbox()
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def list_apk_files(root: str | Path, *, recursive: bool = False) -> list[Path]:
    """列出目录里的 .apk（大小写不敏感）。默认只看这一层，不进子目录。

    点开头的 .apk（如 ``....apk`` / ``.企音通..apk``）也视为合法样本——灰产样本
    文件名常以点开头，不能当隐藏文件跳过；非 .apk 的隐藏文件自然被后缀判断排除。
    """
    folder = Path(root)
    if not folder.is_dir():
        return []
    try:
        it = folder.rglob("*") if recursive else folder.iterdir()
    except OSError:
        return []
    out: list[Path] = []
    for p in it:
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        if p.suffix.lower() == ".apk":
            out.append(p)
    return sorted(out, key=lambda p: (str(p).casefold(), p.name))


def resolve_apk_input(
    apk: str | Path | None,
    *,
    inbox: str | Path | None = None,
    recursive: bool = False,
) -> tuple[Path, list[Path]]:
    """把 CLI 参数收成 (入口路径, APK 列表)。

    - None / 空：默认 APK/（不存在则创建）；inbox 可覆盖该目录
    - 文件：只处理这一个
    - 目录：列出其中的 .apk
    - 路径不存在：FileNotFoundError
    """
    if apk is None or str(apk).strip() == "":
        if inbox is not None and str(inbox).strip() != "":
            root = Path(inbox)
            if not root.is_dir():
                raise FileNotFoundError(f"路径不存在: {root}")
            return root, list_apk_files(root, recursive=recursive)
        root = ensure_apk_inbox()
        return root, list_apk_files(root, recursive=recursive)
    p = Path(apk)
    if p.is_file():
        return p, [p]
    if p.is_dir():
        return p, list_apk_files(p, recursive=recursive)
    raise FileNotFoundError(f"路径不存在: {p}")


_WIN_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str, max_len: int = 60) -> str:
    s = _WIN_BAD.sub("_", (name or "").strip().strip(" ."))
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:max_len] if s else ""


def _apk_id(apk_path: str | Path) -> str:
    p = Path(apk_path)
    h = hashlib.md5()
    try:
        st = p.stat()
        h.update(str(st.st_size).encode())
        with p.open("rb") as f:
            h.update(f.read(65536))
    except OSError:
        h.update(str(p).encode("utf-8", "replace"))
    return h.hexdigest()[:12]


def safe_product_stem(apk_path: str | None, package: str | None = None,
                      trusted: bool = False) -> str:
    """按 APK 文件名建子目录：原文件名优先，可信包名 / apk_<hash> 仅兜底。

    原文件名只清理 Windows 非法字符，不做可读性过滤——保证目录名与 APK 文件名一一对应。
    """
    if apk_path:
        stem = Path(apk_path).stem
        raw = sanitize_filename(stem)
        if raw:
            return raw
        # sanitize 后为空（如纯下划线 / 纯点的文件名），退回原 stem，仅替换非法字符
        raw = _WIN_BAD.sub("_", stem).strip(" .")
        if raw:
            return raw
    if trusted and package:
        pkg = sanitize_filename(package.replace(":", "-").replace(".", "_"))
        if pkg:
            return pkg
    if apk_path:
        return "apk_" + _apk_id(apk_path)
    if package:
        pkg = sanitize_filename(package.replace(":", "-").replace(".", "_"))
        if pkg:
            return pkg
    return "unpack"


def default_dex_dir(apk_path: str | None, package: str | None = None,
                    trusted: bool = False) -> Path:
    """脱壳 dex：unpacked_dex/<apk文件名>/"""
    return product_root() / DEX_PRODUCT_ROOT / safe_product_stem(
        apk_path, package, trusted
    )


def default_url_dir(apk_path: str | None, package: str | None = None,
                    trusted: bool = False) -> Path:
    """URL 清单：extracted_urls/<apk文件名>/（目录内只放 urls_by_rank.txt）"""
    return product_root() / URL_PRODUCT_ROOT / safe_product_stem(
        apk_path, package, trusted
    )


def detect_folder_name(packer_name: str | None) -> str:
    """壳识别归档子目录名：无壳 / 厂商名 / 自研保护。"""
    label = (packer_name or "").strip()
    if not label or label.lower() in ("none", "no_packer", "static"):
        return "无壳"
    low = label.lower()
    if low.startswith("dpt-shell"):
        return "dpt-shell"
    if (
        "packhub" in low
        or "jdog" in low
        or low in ("未知壳", "unknown")
    ):
        return "自研保护"
    folder = sanitize_filename(label, max_len=80)
    return folder or "自研保护"


def default_detect_dir(packer_name: str | None) -> Path:
    """壳识别归档：packer_detection/<壳名>/"""
    return product_root() / DETECT_RESULT_ROOT / detect_folder_name(packer_name)


def _file_sha256(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            buf = f.read(1024 * 1024)
            if not buf:
                break
            h.update(buf)
    return h.digest()


def _remove_stale_detect_copies(src: Path, dest: Path) -> None:
    """标签变了之后，删掉 packer_detection 其它子目录里的同名同大小副本。"""
    root = product_root() / DETECT_RESULT_ROOT
    if not root.is_dir():
        return
    try:
        dest = dest.resolve()
        dest_dir = dest.parent
        dest_size = dest.stat().st_size
    except OSError:
        return
    name = Path(src).name
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        try:
            if folder.resolve() == dest_dir:
                continue
        except OSError:
            continue
        cand = folder / name
        if not cand.is_file():
            continue
        try:
            if cand.resolve() == dest:
                continue
            if cand.stat().st_size != dest_size:
                continue
            cand.unlink()
        except OSError:
            continue
        try:
            next(folder.iterdir())
        except StopIteration:
            try:
                folder.rmdir()
            except OSError:
                pass
        except OSError:
            pass


def archive_detected_apk(apk_path: str | Path, packer_name: str | None) -> Path:
    """把 APK 放到 packer_detection/<壳名>/。同名同内容则跳过；其它标签目录的旧拷贝会删掉。

    AUTO_UNPACK_DISABLE_ARCHIVE=1 时直接返回源路径，不写正式目录（供测试使用）。
    """
    src = Path(apk_path)
    if not src.is_file():
        raise FileNotFoundError(f"APK 不存在: {src}")
    if not archive_enabled():
        return src
    dest_dir = default_detect_dir(packer_name)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    if dest.exists():
        try:
            if dest.stat().st_size == src.stat().st_size and _file_sha256(dest) == _file_sha256(src):
                _remove_stale_detect_copies(src, dest)
                return dest
        except OSError:
            pass
        dest = dest_dir / f"{src.stem}_{_apk_id(src)}{src.suffix}"
    shutil.copy2(src, dest)
    _remove_stale_detect_copies(src, dest)
    return dest
