#!/usr/bin/env python3
"""静态分析 APK / 裸 dex，提取 URL 清单和 API 端点路径。

用法:
    py -3.10 analyze.py <app.apk | classes.dex> [-o urls.txt]

原理:
    1. DEX 字符串池：完整 URL + 以 "/" 开头的端点路径
    2. APK 文本资源（Uni-app www/*.js、json、bundle、配置等）
    3. resources.arsc / 原生 .so / 二进制残留（ASCII + UTF-16LE + 裸 IP:port）
    4. 始终对 assets/res/lib/无扩展配置做有预算的二进制补扫，不依赖已有命中
    5. 统一做 URL/host 语法校验；DNS/HTTP 可达性验证需显式启用
    6. 输出三档完整指标、纯绝对 URL 及带来源/验证状态的 JSONL

    业务 URL 漏报时优先改 indicators.py 的「业务提取规则」表（规则全部在那里）。
    裸 dex（文件头 `dex\\n` / `dey\\n`）扫字符串池 + 原始字节；assets 需对原 APK 再扫一遍。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path

from androguard.core.dex import DEX
from loguru import logger

from ..dex_utils import fix_dex_header, parse_dexes
from .indicators import (
    SOURCE_LABELS,
    _collect_endpoint,
    _harvest_config,
    _harvest_encoded,
    _harvest_text,
    _host_of,
    _iter_urls,
    _maybe_harvest_dex_string,
    _scan_raw_for_urls,
    _weak_has_signal,
    business_urls,
    fold_related_urls,
    format_sources,
    is_syntax_valid_candidate,
    make_indicator,
    merge_indicators,
    render_url_line,
    url_rank,
)

# 注：HiddenApiClassDataItem.DomapiApiFlag 的兼容 patch 在 dex_utils.py 模块顶层
# （本模块 import dex_utils 时必然已生效），这里不再重复。

_ASSET_EXTS = (
    ".js", ".json", ".html", ".htm", ".xml", ".txt", ".vue",
    ".bundle", ".properties", ".env", ".dat", ".cfg", ".conf",
    ".ini", ".plist",
)
_SKIP_ASSET_SUBSTR = (
    "uni-jsframework", "/jquery", "jquery-", "vue.min", "vue.runtime",
    "chunk-vendors", "/polyfill", "jweixin", "weixin-js-sdk",
    "sensorsdata", "uview.ui",
)
_SKIP_ASSET_NAMES = (
    "androidmanifest.xml", "public.xml", "ids.xml",
    "keyword.txt", "bad_domains.txt", "t-rex.html",
    "geosite.dat", "geoip.dat", "geoip.metadb",
)
_SKIP_LIST_FILES = frozenset({
    "keyword.txt", "bad_domains.txt", "t-rex.html",
    "geosite.dat", "geoip.dat", "geoip.metadb",
})
_MAX_ASSET_BYTES = 12 * 1024 * 1024
# 全包二进制回扫：单文件上限（避免把超大 so/视频整读）
_MAX_BINARY_SCAN_BYTES = 24 * 1024 * 1024
_MAX_TOTAL_READ_BYTES = 512 * 1024 * 1024
_MAX_MEMBER_READS = 20_000
_MAX_COMPRESSION_RATIO = 200
_BINARY_ALWAYS_SUFFIX = (
    ".dex", ".so", ".arsc", ".bin", ".dat", ".cfg", ".json", ".js",
    ".properties", ".xml", ".txt", ".bundle",
)


def _new_scan_budget() -> dict:
    return {"read_bytes": 0, "member_reads": 0}


def _record_source_error(stats: dict | None, source: str, file: str, exc) -> None:
    entry = {"source": source, "file": file, "error": str(exc)[:500]}
    if stats is not None:
        stats.setdefault("source_errors", []).append(entry)
    logger.warning("URL source scan failed: {source}/{file}: {error}", **entry)


def _record_skip(stats: dict | None, source: str, file: str, reason: str) -> None:
    if stats is None:
        return
    bucket = stats.setdefault("source_skipped", [])
    if len(bucket) < 500:
        bucket.append({"source": source, "file": file, "reason": reason})


def _read_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    source: str,
    max_bytes: int,
    stats: dict | None,
    budget: dict | None,
) -> bytes | None:
    if info.file_size > max_bytes:
        _record_skip(stats, source, info.filename, "member_too_large")
        return None
    ratio = info.file_size / max(info.compress_size, 1)
    if ratio > _MAX_COMPRESSION_RATIO:
        _record_skip(stats, source, info.filename, "compression_ratio_exceeded")
        return None
    if budget is not None:
        if budget["member_reads"] >= _MAX_MEMBER_READS:
            _record_skip(stats, source, info.filename, "member_read_budget_exhausted")
            return None
        if budget["read_bytes"] + info.file_size > _MAX_TOTAL_READ_BYTES:
            _record_skip(stats, source, info.filename, "byte_budget_exhausted")
            return None
        budget["member_reads"] += 1
        budget["read_bytes"] += info.file_size
    try:
        return zf.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, source, info.filename, exc)
        return None


def _has_relevant_url(urls) -> bool:
    for u in urls or []:
        raw = u.get("value") or u.get("url") if isinstance(u, dict) else str(u)
        if raw and url_rank(raw) in ("biz", "weak"):
            return True
    return False


def _is_junk_list_file(base: str) -> bool:
    if base in _SKIP_LIST_FILES:
        return True
    if "emoji" in base and base.endswith((".xml", ".json")):
        return True
    # v2ray/xray 路由词表（coterie geosite.dat 一次灌 24 万裸域名）
    return base.startswith(("geosite.", "geoip.")) and base.endswith(
        (".dat", ".db", ".metadb")
    )


def _should_binary_scan_entry(name: str, size: int, deep: bool) -> bool:
    if size < 32 or size > _MAX_BINARY_SCAN_BYTES:
        return False
    low = name.replace("\\", "/").lower()
    base = low.rsplit("/", 1)[-1]
    if _is_junk_list_file(base):
        return False
    if base in ("resources.arsc", "androidmanifest.xml"):
        return True
    if any(low.endswith(suf) for suf in _BINARY_ALWAYS_SUFFIX):
        return True
    return deep and (low.startswith(("assets/", "res/", "lib/")) or "www/" in low)


_PRINTABLE = re.compile(rb"[\x20-\x7e]{12,}")
_PRINTABLE_WINDOW = 64 * 1024
_PRINTABLE_OVERLAP = 2048
_MAX_SO_BYTES = 32 * 1024 * 1024
_MAX_SO_FILES = 48


def _iter_printable_text(raw: bytes):
    """以有界窗口产出可打印区域，窗口间保留一个最大 URL 长度的重叠。"""
    for match in _PRINTABLE.finditer(raw):
        start, end = match.span()
        while start < end:
            window_end = min(start + _PRINTABLE_WINDOW, end)
            yield raw[start:window_end].decode("ascii", errors="ignore")
            if window_end == end:
                break
            start = window_end - _PRINTABLE_OVERLAP


def extract_native(
    apk_path: str,
    stats: dict | None = None,
    budget: dict | None = None,
) -> list[dict]:
    """从 APK 内 .so 扫可打印串里的 URL 和内嵌配置（"url": "host" 等）。不做解密。"""
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(apk_path)
    except (OSError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, "native", apk_path, exc)
        return out
    n_so = 0
    with zf:
        for info in zf.infolist():
            name = info.filename
            low = name.replace("\\", "/").lower()
            if not low.endswith(".so"):
                continue
            if info.file_size > _MAX_SO_BYTES or info.file_size < 64:
                _record_skip(stats, "native", name, "member_size_out_of_range")
                continue
            n_so += 1
            if n_so > _MAX_SO_FILES:
                _record_skip(stats, "native", name, "native_file_limit")
                continue
            raw = _read_member(
                zf, info, source="native", max_bytes=_MAX_SO_BYTES,
                stats=stats, budget=budget,
            )
            if raw is None:
                continue
            found: set[str] = set()
            for text in _iter_printable_text(raw):
                for u in _iter_urls(text):
                    found.add(u)
                # Go/Flutter 二进制里常内嵌 JSON 配置。
                harvested: set[str] = set()
                dummy: set[str] = set()
                _harvest_config(text, harvested, dummy)
                found.update(harvested)
            for u in found:
                ind = make_indicator(u, "native", name, "so_string")
                if ind:
                    out.append(ind)
    return out


def _decode_utf8_chunks(raw: bytes, min_len: int):
    """按 NUL 切开二进制，产出 (原始片段, UTF-8 文本)；解码失败的片段跳过。"""
    for chunk in raw.split(b"\x00"):
        if len(chunk) < min_len:
            continue
        try:
            yield chunk, chunk.decode("utf-8")
        except UnicodeDecodeError:
            continue


def _looks_binary(raw: bytes) -> bool:
    """开头就有密集 NUL 的成员按二进制跳过，不进文本解码。"""
    return b"\x00" in raw[:1024] and raw.count(b"\x00") > 8


def _extract_apk_binary_urls(
    apk_path: str,
    *,
    deep: bool = False,
    stats: dict | None = None,
    budget: dict | None = None,
) -> tuple[set[str], set[str]]:
    """按后缀/深度从 APK 成员二进制抠 URL。deep=True 时扩大到 assets/res/lib。"""
    urls: set[str] = set()
    endpoints: set[str] = set()
    try:
        zf = zipfile.ZipFile(apk_path)
    except (OSError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, "binary", apk_path, exc)
        return urls, endpoints
    with zf:
        for info in zf.infolist():
            name = info.filename
            if not _should_binary_scan_entry(name, info.file_size, deep):
                continue
            raw = _read_member(
                zf, info, source="binary", max_bytes=_MAX_BINARY_SCAN_BYTES,
                stats=stats, budget=budget,
            )
            if raw is None:
                continue
            for u in _scan_raw_for_urls(raw):
                urls.add(u)
            # 配置形态片段：NUL 切开再收割
            if b"baseUrl" in raw or b"apiUrl" in raw or b"domainList" in raw:
                for _chunk, text in _decode_utf8_chunks(raw, min_len=12):
                    _harvest_config(text, urls, endpoints)
    return urls, endpoints


def _skip_asset(low_path: str) -> bool:
    base = low_path.rsplit("/", 1)[-1]
    if base.startswith("__uniapp") or base in _SKIP_ASSET_NAMES:
        return True
    if _is_junk_list_file(base):
        return True
    return any(s in low_path for s in _SKIP_ASSET_SUBSTR)


def _extract_from_zip_assets(
    apk_path: str,
    stats: dict | None = None,
    budget: dict | None = None,
) -> tuple[set[str], set[str]]:
    """扫 APK 内文本资源。Uni-app 业务 API 在 www/*.js，不在 dex。"""
    urls: set[str] = set()
    endpoints: set[str] = set()
    try:
        zf = zipfile.ZipFile(apk_path)
    except (OSError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, "assets", apk_path, exc)
        return urls, endpoints
    with zf:
        for info in zf.infolist():
            name = info.filename
            low = name.replace("\\", "/").lower()
            if not low.endswith(_ASSET_EXTS):
                continue
            if _skip_asset(low):
                continue
            if info.file_size > _MAX_ASSET_BYTES:
                _record_skip(stats, "assets", name, "member_too_large")
                continue
            raw = _read_member(
                zf, info, source="assets", max_bytes=_MAX_ASSET_BYTES,
                stats=stats, budget=budget,
            )
            if raw is None:
                continue
            if _looks_binary(raw):
                continue
            text = raw.decode("utf-8", errors="ignore")
            if text:
                _harvest_text(text, urls, endpoints)
    return urls, endpoints


def _load_dex_files(path: Path, head: bytes, stats: dict | None = None) -> list[tuple[str, DEX]]:
    """加载 dex：裸 dex（dex\n / dey\n）直接修头；APK 走 parse_dexes（跳过非 ASCII 假 dex，不解析 Manifest）。"""
    if head in (b"dex\n", b"dey\n"):
        # 与 parse_dexes 保持一致：裸 dex 也先做廉价头校验，声明异常
        # （id 段越界）的诱饵不进 androguard，避免单文件几秒的解析空转。
        from ..dex_utils import dex_header_plausible

        data = path.read_bytes()
        if not dex_header_plausible(data):
            if stats is not None:
                stats.setdefault("malformed_dex", []).append(path.name)
            return []
        try:
            return [(path.name, DEX(fix_dex_header(data)))]
        except Exception as e:  # noqa: BLE001 - androguard exposes no stable exception base
            if stats is not None:
                stats.setdefault("parse_failed", []).append((path.name, str(e)))
            return []
    return parse_dexes(str(path), stats=stats)


def _extract_from_resources_arsc(
    apk_path: str,
    stats: dict | None = None,
    budget: dict | None = None,
) -> tuple[set[str], set[str]]:
    """扫 resources.arsc。部分样本把 API 只写在资源字符串池，不进 dex。"""
    urls: set[str] = set()
    endpoints: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path) as zf:
            info = zf.getinfo("resources.arsc")
            raw = _read_member(
                zf, info, source="resources", max_bytes=_MAX_ASSET_BYTES,
                stats=stats, budget=budget,
            )
    except KeyError:
        return urls, endpoints
    except (OSError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, "resources", apk_path, exc)
        return urls, endpoints
    if not raw:
        return urls, endpoints
    urls |= _scan_raw_for_urls(raw)
    # 再按 NUL 切开的 UTF-8 片段做配置键收割（端点等）
    for chunk, text in _decode_utf8_chunks(raw, min_len=8):
        if b"://" not in chunk and b"/" not in chunk:
            continue
        if not text.isprintable() and not any(c in text for c in "/:"):
            continue
        for u in _iter_urls(text):
            urls.add(u)
        _harvest_text(text, urls, endpoints)
    return urls, endpoints


def _extract_resources_arsc_traced(
    apk_path: str,
    stats: dict | None = None,
    budget: dict | None = None,
) -> tuple[list[dict], set[str]]:
    urls, endpoints = _extract_from_resources_arsc(apk_path, stats, budget)
    items = []
    for u in urls:
        ind = make_indicator(u, "resources", "resources.arsc", "string_pool")
        if ind:
            items.append(ind)
    return items, endpoints


def _merge_binary_into_indicators(
    apk_path: str,
    *,
    deep: bool,
    stats: dict | None = None,
    budget: dict | None = None,
) -> tuple[list[dict], set[str]]:
    urls, endpoints = _extract_apk_binary_urls(
        apk_path, deep=deep, stats=stats, budget=budget,
    )
    items = []
    method = "binary_deep" if deep else "binary"
    for u in urls:
        ind = make_indicator(u, "binary", "apk", method)
        if ind:
            items.append(ind)
    return items, endpoints


def extract(apk_path: str) -> tuple[set[str], set[str]]:
    """extract_indicators 的轻量视图：只要 URL 字符串集（丢出处）。

    保留作兼容入口；本模块 CLI 与各条产物链路已改用 extract_indicators（带出处）。
    """
    items, endpoints = extract_indicators(apk_path)
    return {i["url"] for i in items if i.get("url")}, endpoints


def extract_assets_traced(
    apk_path: str,
    stats: dict | None = None,
    budget: dict | None = None,
) -> tuple[list[dict], set[str]]:
    """扫 APK 文本资源，每条 URL 带 zip 内路径（脱壳后的裸 dex 没有 assets，用原包补）。"""
    items: list[dict] = []
    endpoints: set[str] = set()
    try:
        zf = zipfile.ZipFile(apk_path)
    except (OSError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, "assets", apk_path, exc)
        return items, endpoints
    with zf:
        for info in zf.infolist():
            name = info.filename
            low = name.replace("\\", "/").lower()
            if not low.endswith(_ASSET_EXTS):
                continue
            if _skip_asset(low):
                continue
            if info.file_size > _MAX_ASSET_BYTES:
                _record_skip(stats, "assets", name, "member_too_large")
                continue
            raw = _read_member(
                zf, info, source="assets", max_bytes=_MAX_ASSET_BYTES,
                stats=stats, budget=budget,
            )
            if raw is None:
                continue
            if _looks_binary(raw):
                continue
            text = raw.decode("utf-8", errors="ignore")
            if not text:
                continue
            urls: set[str] = set()
            _harvest_text(text, urls, endpoints)
            for u in urls:
                ind = make_indicator(u, "assets", name, "harvest")
                if ind:
                    items.append(ind)
    return items, endpoints


def _extract_manifest_indicators(
    apk_path: str,
    stats: dict | None = None,
    budget: dict | None = None,
) -> list[dict]:
    """从 AndroidManifest.xml 抽 URL（二进制 AXML 转 XML 后再扫字符串）。"""
    items: list[dict] = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            info = z.getinfo("AndroidManifest.xml")
            raw = _read_member(
                z, info, source="manifest", max_bytes=_MAX_ASSET_BYTES,
                stats=stats, budget=budget,
            )
    except KeyError:
        return items
    except (OSError, zipfile.BadZipFile) as exc:
        _record_source_error(stats, "manifest", apk_path, exc)
        return items
    if raw is None:
        return items
    chunks: list[str] = []
    try:
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(raw)
        xml = printer.get_xml() if printer.is_valid() else None
        if isinstance(xml, bytes):
            xml = xml.decode("utf-8", errors="replace")
        if xml:
            chunks.append(xml)
    except Exception as exc:  # noqa: BLE001 - androguard exceptions vary by version
        _record_source_error(stats, "manifest_axml", "AndroidManifest.xml", exc)
    chunks.append(raw.decode("utf-8", errors="ignore"))
    chunks.append(raw.decode("utf-16le", errors="ignore"))
    text = "\n".join(chunks)
    harvested: set[str] = set()
    dummy: set[str] = set()
    _harvest_text(text, harvested, dummy)
    for u in _iter_urls(text):
        harvested.add(u)
    for u in harvested:
        ind = make_indicator(u, "manifest", "AndroidManifest.xml", "regex")
        if ind:
            items.append(ind)
    return items


def _extract_dex_string_indicators(dex_files, items: list[dict], endpoints: set[str],
                                   stats: dict | None = None) -> None:
    """遍历 dex 字符串池提取 URL + 端点（items/endpoints 就地追加）。"""
    for name, dex in dex_files:
        try:
            strings = dex.get_strings()
        except Exception as e:  # noqa: BLE001 - androguard exceptions vary by version
            if stats is not None:
                stats.setdefault("strings_failed", []).append((name, str(e)))
            continue
        for s in strings:
            if not isinstance(s, str):
                continue
            for u in _iter_urls(s):
                ind = make_indicator(u, "dex", name, "string_pool")
                if ind:
                    items.append(ind)
            _collect_endpoint(s, endpoints)
            harvested: set[str] = set()
            _maybe_harvest_dex_string(s, harvested, endpoints)
            for u in harvested:
                ind = make_indicator(u, "dex", name, "harvest")
                if ind:
                    items.append(ind)
            decoded: set[str] = set()
            _harvest_encoded(s, decoded, endpoints)
            for u in decoded:
                ind = make_indicator(u, "dex", name, "decoded")
                if ind:
                    items.append(ind)


def _extract_bare_dex_indicators(
    path: Path,
    items: list[dict],
    endpoints: set[str],
    stats: dict | None = None,
) -> None:
    """裸 dex：字符串池之外再扫原始字节。"""
    try:
        for u in _scan_raw_for_urls(path.read_bytes()):
            ind = make_indicator(u, "dex", path.name, "raw_bytes")
            if ind:
                items.append(ind)
    except OSError as exc:
        _record_source_error(stats, "dex_raw", path.name, exc)


def _extract_apk_indicators(
    path: Path,
    items: list[dict],
    endpoints: set[str],
    stats: dict | None = None,
) -> list[dict]:
    """ZIP APK：专用解析与确定性的全覆盖二进制扫描，覆盖度不依赖已有命中。"""
    budget = _new_scan_budget()
    traced, ae = extract_assets_traced(str(path), stats, budget)
    items.extend(traced)
    endpoints |= ae
    arsc_items, arsc_ep = _extract_resources_arsc_traced(str(path), stats, budget)
    items.extend(arsc_items)
    endpoints |= arsc_ep
    items.extend(extract_native(str(path), stats, budget))
    items.extend(_extract_manifest_indicators(str(path), stats, budget))
    # 始终覆盖 assets/res/lib/无扩展配置；不能因先发现一条 URL 就缩小扫描面。
    bin_items, bin_ep = _merge_binary_into_indicators(
        str(path), deep=True, stats=stats, budget=budget,
    )
    items.extend(bin_items)
    endpoints |= bin_ep
    if stats is not None:
        stats["scan_budget"] = dict(budget)
    return merge_indicators(items)


def extract_apk_non_dex_sources(
    apk_path: str,
    stats: dict | None = None,
) -> tuple[list[dict], set[str]]:
    """扫 APK 中 dex 字符串池之外的来源：assets/arsc/native/manifest/binary（全覆盖补扫）。

    与 extract_indicators 的区别：不解析 APK 内 dex 字符串池（壳样本里那只是
    stub，无业务价值）。供脱壳产物补扫使用——dump 出的 payload dex 走裸 dex
    路径单独提字符串池，原包里 dpt 壳通常不加密的资源类来源由本函数补上。
    """
    endpoints: set[str] = set()
    items = _extract_apk_indicators(Path(apk_path), [], endpoints, stats)
    return items, endpoints


def _finalize_indicators(
    items: list[dict],
    *,
    validate_network: bool,
    check_http: bool,
    network_timeout: float,
    allow_private_http: bool,
) -> list[dict]:
    merged = merge_indicators(items)
    if validate_network or check_http:
        from .validation import validate_indicators_network

        validate_indicators_network(
            merged,
            check_http=check_http,
            timeout=network_timeout,
            allow_private_http=allow_private_http,
        )
    return merged


def extract_indicators(
    apk_path: str,
    stats: dict | None = None,
    *,
    validate_network: bool = False,
    check_http: bool = False,
    network_timeout: float = 3.0,
    allow_private_http: bool = False,
) -> tuple[list[dict], set[str]]:
    """提取 URL 指标（含出处）。裸 DEX 扫字符串池及原始字节。

    stats 可选，收集解析层失败信号（parse_failed / encrypted_dex /
    malformed_dex / strings_failed），供上层判断结果是否可能不完整。
    """
    path = Path(apk_path)
    with open(path, "rb") as fh:
        head = fh.read(4)

    items: list[dict] = []
    endpoints: set[str] = set()
    dex_files = _load_dex_files(path, head, stats)
    _extract_dex_string_indicators(dex_files, items, endpoints, stats)

    if head in (b"dex\n", b"dey\n"):
        _extract_bare_dex_indicators(path, items, endpoints, stats)
        return _finalize_indicators(
            items,
            validate_network=validate_network,
            check_http=check_http,
            network_timeout=network_timeout,
            allow_private_http=allow_private_http,
        ), endpoints

    items = _extract_apk_indicators(path, items, endpoints, stats)
    return _finalize_indicators(
        items,
        validate_network=validate_network,
        check_http=check_http,
        network_timeout=network_timeout,
        allow_private_http=allow_private_http,
    ), endpoints


_ENC_NAME_HINTS = ("config", "dconfig", "version", "cfg", "appconfig", "setting")
_ENC_SUFFIXES = (".json", ".txt", ".dat", ".cfg", ".properties")
_PLACEHOLDER_HOSTS = (
    "ceshi.com", "example.com", "example.org", "test.com",
    "localhost", "127.0.0.1",
)


def _looks_encrypted_blob(data: bytes) -> bool:
    """配置文件看起来是密文：不是 JSON/XML，开头是长字母数字块。"""
    head = (data or b"").lstrip()[:200]
    if not head or len(head) < 24:
        return False
    if head[:1] in (b"{", b"[", b"<", b"#") or head[:2] in (b"/*", b"//"):
        return False
    if head.lower().startswith((b"http", b"www.")):
        return False
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return bool(re.match(r"^[A-Za-z0-9+/=]{24,}", text))


def _url_hosts(urls) -> set[str]:
    hosts: set[str] = set()
    for u in urls or []:
        if isinstance(u, dict):
            h = (u.get("host") or "").lower()
            if not h:
                raw = u.get("value") or u.get("url") or ""
                h = _host_of(raw)
        else:
            h = _host_of(str(u))
        if h:
            hosts.add(h)
    return hosts


def _has_biz_url(urls) -> bool:
    for u in urls or []:
        if isinstance(u, dict):
            if u.get("rank") == "biz":
                return True
            raw = u.get("value") or u.get("url") or ""
        else:
            raw = str(u)
        if raw and url_rank(raw) == "biz":
            return True
    return False


def scan_extraction_warnings(apk_path: str, urls=None) -> list[str]:
    """抽空或仅占位 URL 时标 encrypted_config / runtime_h5。不改 route、不 spawn。"""
    warns: list[str] = []
    encrypted = False
    uni_www = False
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = z.namelist()
            for name in names:
                low = name.replace("\\", "/").lower()
                if "/www/" in low and low.startswith("assets/") and low.endswith(
                    (".js", ".html", ".json")
                ):
                    uni_www = True
                base = low.rsplit("/", 1)[-1]
                stem = base.rsplit(".", 1)[0]
                if not (low.startswith("assets/") and base.endswith(_ENC_SUFFIXES)):
                    continue
                if not any(h in stem for h in _ENC_NAME_HINTS):
                    continue
                try:
                    info = z.getinfo(name)
                except KeyError:
                    continue
                if info.file_size > 512 * 1024 or info.file_size < 24:
                    continue
                try:
                    raw = z.read(name)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    logger.warning("Encrypted-config probe failed for {}: {}", name, exc)
                    continue
                if _looks_encrypted_blob(raw):
                    encrypted = True
    except (OSError, zipfile.BadZipFile) as exc:
        logger.warning("Extraction-warning scan failed for {}: {}", apk_path, exc)
        return warns

    biz = _has_biz_url(urls)
    hosts = _url_hosts(urls)
    only_placeholder = bool(hosts) and all(
        any(h == p or h.endswith("." + p) for p in _PLACEHOLDER_HOSTS)
        for h in hosts
    )
    emptyish = not biz and (not hosts or only_placeholder)

    if encrypted and emptyish:
        warns.append("encrypted_config: assets 配置像密文，静态抽空不等于有壳")
    if uni_www and emptyish:
        warns.append("runtime_h5: uni-app/H5 运行时拼 URL，静态可能漏报")
    elif uni_www and not biz:
        warns.append("runtime_h5: uni-app www 无业务 URL，host 可能运行时拼接")
    return warns


def build_source_index(indicators: list[dict] | None) -> dict[str, list[dict]]:
    """URL -> 来源列表（按 (type, file, method) 去重，保留首次出现顺序）。

    只按 URL 原文建索引：所有调用点传入的 urls 与 indicators 同源（都来自
    task.urls），实测原文命中率 100%，不需要额外的合并键兜底。
    """
    idx: dict[str, list[dict]] = {}
    for it in indicators or []:
        url = it.get("url") or it.get("value")
        if not url:
            continue
        bucket = idx.setdefault(url, [])
        seen = {(s.get("type"), s.get("file"), s.get("method")) for s in bucket}
        for s in it.get("sources") or []:
            sig = (s.get("type"), s.get("file"), s.get("method"))
            if sig not in seen:
                bucket.append(dict(s))
                seen.add(sig)
    return idx


def _source_index_of(url: str, idx: dict[str, list[dict]]) -> list[dict]:
    return idx.get(url) or []


_RULE = "─" * 76
# 来源列对齐宽度上限：再长的 URL 不再把整表撑开
_SRC_COL_MAX = 68


def _header_lines(name: str, biz: int, weak: int, noise: int,
                  endpoints: int, *, bare_weak: int = 0) -> list[str]:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
    listed = biz + weak
    # 全部非 URL 行都以 # 开头：文件里「不以 # 开头的行 = URL」，可直接 grep 抽取
    lines = [
        f"# {_RULE}",
        f"#   URL 提取结果 · {name}",
        f"#   生成时间 {stamp}    静态字面量层（不含运行时观测 / 解密还原）",
        f"# {_RULE}",
        "#",
        f"#   写入     {listed} 条    biz {biz}    weak {weak}",
        f"#   未写入   noise {noise}    weak 裸域名 {bare_weak}    端点路径 {endpoints}",
        "#",
        "#   行格式   来源为注释，下一条非注释行是未经协议猜测的原始网络指标",
        "#   图例",
    ]
    for tag, label in sorted(
        (f"{t}/{m}", lab) for (t, m), lab in SOURCE_LABELS.items()
    ):
        lines.append(f"#     {tag:<24} {label}")
    lines.extend([f"# {_RULE}", "#"])
    return lines


def _render_url_lines(urls: set[str], idx: dict[str, list[dict]]) -> list[str]:
    """来源写在注释行；所有非注释行保持为纯指标值，便于下游直接读取。"""
    if not urls:
        return ["# （无）"]
    lines: list[str] = []
    for url in sorted(urls):
        lines.append(f"# source: {format_sources(_source_index_of(url, idx))}")
        lines.append(url)
    return lines


def format_url_line(url: str, sources: list[dict] | None = None) -> str:
    """控制台/额外产物用的单行渲染（固定 68 列对齐）。"""
    return render_url_line(url, sources, width=_SRC_COL_MAX)


def write_url_files(directory: Path, urls: set[str], endpoints: set[str],
                    indicators: list[dict] | None = None) -> set[str]:
    """写出分级清单与 JSONL。urls_by_rank.txt 只写 biz 和有信号的 weak。

    noise / 裸域名 weak 只计个数，不进清单。无协议 host 不写进 urls.txt。
    """
    directory.mkdir(parents=True, exist_ok=True)
    folded = {u for u in fold_related_urls(urls) if is_syntax_valid_candidate(u)}
    rank_by: dict[str, str] = {}
    for it in indicators or []:
        raw = it.get("url") or it.get("value") or ""
        if not raw:
            continue
        r = it.get("rank") or url_rank(raw)
        prev = rank_by.get(raw)
        if prev is None or {"biz": 2, "weak": 1, "noise": 0}.get(r, 0) > {
            "biz": 2, "weak": 1, "noise": 0,
        }.get(prev, 0):
            rank_by[raw] = r

    def _rank(u: str) -> str:
        return rank_by.get(u) or url_rank(u)

    biz = {u for u in folded if u and _rank(u) == "biz"}
    all_weak = {u for u in folded if u and _rank(u) == "weak"}
    weak = {u for u in all_weak if _weak_has_signal(u)}
    noise = {u for u in folded if u and _rank(u) == "noise"}
    idx = build_source_index(indicators)

    lines = _header_lines(
        directory.name, len(biz), len(weak), len(noise), len(endpoints),
        bare_weak=len(all_weak) - len(weak),
    )
    lines.append(f"## biz（业务）  {len(biz)}")
    lines.extend(_render_url_lines(biz, idx))
    lines.append("")
    lines.append(f"## weak（弱信号）  {len(weak)}")
    lines.extend(_render_url_lines(weak, idx))
    lines.append("")
    (directory / "urls_by_rank.txt").write_text("\n".join(lines), encoding="utf-8")

    absolute_urls = sorted(u for u in folded if re.match(r"^(?:https?|wss?)://", u, re.IGNORECASE))
    (directory / "urls.txt").write_text(
        "\n".join(absolute_urls) + ("\n" if absolute_urls else ""),
        encoding="utf-8",
    )
    source_rows = indicators or [
        item for u in sorted(folded)
        if (item := make_indicator(u, "unknown", "", "unknown")) is not None
    ]
    rows = [
        item for item in source_rows
        if is_syntax_valid_candidate(
            item.get("canonical") or item.get("url") or item.get("value") or ""
        )
    ]
    (directory / "indicators.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in rows),
        encoding="utf-8",
    )

    for legacy in ("urls_biz.txt", "urls_weak.txt", "endpoints.txt"):
        old = directory / legacy
        if old.is_file():
            try:
                old.unlink()
            except OSError:
                pass
    return biz


def _print_results(urls: set[str], endpoints: set[str],
                   idx: dict[str, list[dict]] | None = None) -> None:
    idx = idx or {}
    biz = business_urls(urls)
    print("=== 业务 URL ===")
    for u in sorted(biz):
        print("  " + format_url_line(u, _source_index_of(u, idx)))
    print("\n=== 全部 URL（含 SDK） ===")
    for u in sorted(urls):
        print("  " + format_url_line(u, _source_index_of(u, idx)))
    print("\n=== 端点路径 ===")
    for e in sorted(endpoints):
        print("  " + e)


def main() -> int:
    parser = argparse.ArgumentParser(description="静态分析 APK/裸 dex，提取 URL 和端点路径")
    parser.add_argument("apk", help="APK 或裸 dex 文件路径")
    parser.add_argument("-o", "--out", help="输出文件路径（URL 写到这里，端点写到 <name>_endpoints<ext>）")
    parser.add_argument("--validate-dns", action="store_true", help="对 host 做 DNS 解析并记录状态")
    parser.add_argument("--validate-http", action="store_true", help="显式发起 HTTP HEAD（同时启用 DNS）")
    parser.add_argument("--allow-private-http", action="store_true",
                        help="允许 HTTP 探测私有/保留地址；默认阻止")
    parser.add_argument("--validation-timeout", type=float, default=3.0,
                        help="单个 HTTP 连接/响应超时秒数（默认 3；DNS 由系统解析器控制）")
    args = parser.parse_args()

    apk = Path(args.apk)
    if not apk.exists():
        print(f"[错误] 文件不存在: {apk}", file=sys.stderr)
        return 2

    print(f"[*] 分析: {apk}")
    try:
        items, endpoints = extract_indicators(
            str(apk),
            validate_network=args.validate_dns or args.validate_http,
            check_http=args.validate_http,
            network_timeout=max(0.2, args.validation_timeout),
            allow_private_http=args.allow_private_http,
        )
    except Exception as e:  # noqa: BLE001 - CLI boundary reports unexpected failures
        print(f"[错误] 分析失败: {e}", file=sys.stderr)
        return 2

    urls = {i["url"] for i in items if i.get("url")}
    idx = build_source_index(items)
    biz = business_urls(urls)
    print(f"[*] 完整 URL: {len(urls)} 个  业务 URL: {len(biz)} 个  端点路径: {len(endpoints)} 个")
    print("    行格式 <URL>    · <来源类型>/<提取方式>@<文件>\n")

    if args.out:
        out_path = Path(args.out)
        ep_path = out_path.with_name(out_path.stem + "_endpoints" + out_path.suffix)
        biz_path = out_path.with_name(out_path.stem + "_biz" + out_path.suffix)
        jsonl_path = out_path.with_name(out_path.stem + "_indicators.jsonl")
        try:
            out_path.write_text(
                "\n".join(sorted(urls)) + ("\n" if urls else ""),
                encoding="utf-8")
            biz_path.write_text(
                "\n".join(sorted(biz)) + ("\n" if biz else ""),
                encoding="utf-8")
            ep_path.write_text("\n".join(sorted(endpoints)) + "\n", encoding="utf-8")
            jsonl_path.write_text(
                "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n"
                        for item in items),
                encoding="utf-8",
            )
            print(f"[+] 完整 URL -> {out_path} ({len(urls)} 条)")
            print(f"[+] 业务 URL -> {biz_path} ({len(biz)} 条)")
            print(f"[+] 端点路径 -> {ep_path} ({len(endpoints)} 条)")
            print(f"[+] 结构化指标 -> {jsonl_path} ({len(items)} 条)")
            print("\n=== 业务 URL ===")
            for u in sorted(biz):
                print("  " + format_url_line(u, _source_index_of(u, idx)))
        except OSError as e:
            print(f"[警告] 写入文件失败: {e}，改在屏幕输出", file=sys.stderr)
            _print_results(urls, endpoints, idx)
    else:
        _print_results(urls, endpoints, idx)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
