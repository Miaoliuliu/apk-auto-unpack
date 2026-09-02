#!/usr/bin/env python3
"""静态分析 APK / 裸 dex，提取 URL 清单和 API 端点路径。

用法:
    py -3.10 analyze.py <app.apk | classes.dex> [-o urls.txt]

原理:
    1. DEX 字符串池：完整 URL + 以 "/" 开头的端点路径
    2. APK 文本资源（Uni-app www/*.js、json、bundle、配置等）
    3. resources.arsc / 原生 .so / 二进制残留（ASCII + UTF-16LE + 裸 IP:port）
    4. 相关 URL（biz/weak）仍为空时，扩大扫 assets/res/lib 做兜底
    5. URL 分三档：noise / weak / biz；urls_by_rank.txt 只写 biz → weak

    业务 URL 漏报时优先改 indicators.py 的「业务提取规则」表（规则全部在那里）。
    裸 dex（文件头 `dex\\n` / `dey\\n`）扫字符串池 + 原始字节；assets 需对原 APK 再扫一遍。
"""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

from androguard.core.dex import DEX

from ..dex_utils import fix_dex_header, parse_dexes
from .indicators import (
    _collect_endpoint,
    _harvest_config,
    _harvest_text,
    _iter_urls,
    _maybe_harvest_dex_string,
    _scan_raw_for_urls,
    business_urls,
    fold_related_urls,
    make_indicator,
    merge_indicators,
    url_rank,
    weak_worth_listing,
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
_SKIP_ASSET_NAMES = ("androidmanifest.xml", "public.xml", "ids.xml")
_MAX_ASSET_BYTES = 12 * 1024 * 1024
# 全包二进制回扫：单文件上限（避免把超大 so/视频整读）
_MAX_BINARY_SCAN_BYTES = 24 * 1024 * 1024
_BINARY_ALWAYS_SUFFIX = (
    ".dex", ".so", ".arsc", ".bin", ".dat", ".cfg", ".json", ".js",
    ".properties", ".xml", ".txt", ".bundle",
)


def _has_relevant_url(urls) -> bool:
    for u in urls or []:
        raw = u.get("value") or u.get("url") if isinstance(u, dict) else str(u)
        if raw and url_rank(raw) in ("biz", "weak"):
            return True
    return False


def _should_binary_scan_entry(name: str, size: int, deep: bool) -> bool:
    if size < 32 or size > _MAX_BINARY_SCAN_BYTES:
        return False
    low = name.replace("\\", "/").lower()
    base = low.rsplit("/", 1)[-1]
    if base in ("resources.arsc", "androidmanifest.xml"):
        return True
    if any(low.endswith(suf) for suf in _BINARY_ALWAYS_SUFFIX):
        return True
    if deep and (low.startswith("assets/") or low.startswith("res/")
                 or low.startswith("lib/") or "www/" in low):
        return True
    return False


_PRINTABLE = re.compile(rb"[\x20-\x7e]{12,512}")
_MAX_SO_BYTES = 32 * 1024 * 1024
_MAX_SO_FILES = 48


def extract_native(apk_path: str) -> list[dict]:
    """从 APK 内 .so 扫可打印串里的 URL 和内嵌配置（"url": "host" 等）。不做解密。"""
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception:
        return out
    n_so = 0
    with zf:
        for name in zf.namelist():
            low = name.replace("\\", "/").lower()
            if not low.endswith(".so"):
                continue
            n_so += 1
            if n_so > _MAX_SO_FILES:
                break
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if info.file_size > _MAX_SO_BYTES or info.file_size < 64:
                continue
            try:
                raw = zf.read(name)
            except Exception:
                continue
            text = "\n".join(
                m.group(0).decode("ascii", errors="ignore")
                for m in _PRINTABLE.finditer(raw)
            )
            if not text:
                continue
            found: set[str] = set()
            for u in _iter_urls(text):
                found.add(u)
            # Go/Flutter 二进制里常内嵌 JSON 配置（"url": "im.xxx.com"），值本身没有
            # scheme，靠配置收割规则还原；噪音由 _normalize_base/is_noise_url 过滤
            harvested: set[str] = set()
            dummy: set[str] = set()
            _harvest_config(text, harvested, dummy)
            for u in harvested:
                found.add(u)
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


def _extract_apk_binary_urls(apk_path: str, *, deep: bool = False
                             ) -> tuple[set[str], set[str]]:
    """按后缀/深度从 APK 成员二进制抠 URL。deep=True 时扩大到 assets/res/lib。"""
    urls: set[str] = set()
    endpoints: set[str] = set()
    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception:
        return urls, endpoints
    with zf:
        for name in zf.namelist():
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if not _should_binary_scan_entry(name, info.file_size, deep):
                continue
            # 文本资源已由 _extract_from_zip_assets 覆盖；浅扫时跳过纯文本后缀
            low = name.replace("\\", "/").lower()
            if (not deep and low.endswith(_ASSET_EXTS)
                    and not low.endswith((".xml", ".dat", ".cfg", ".bin"))):
                continue
            try:
                raw = zf.read(name)
            except Exception:
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
    return any(s in low_path for s in _SKIP_ASSET_SUBSTR)


def _extract_from_zip_assets(apk_path: str) -> tuple[set[str], set[str]]:
    """扫 APK 内文本资源。Uni-app 业务 API 在 www/*.js，不在 dex。"""
    urls: set[str] = set()
    endpoints: set[str] = set()
    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception:
        return urls, endpoints
    with zf:
        for name in zf.namelist():
            low = name.replace("\\", "/").lower()
            if not low.endswith(_ASSET_EXTS):
                continue
            if _skip_asset(low):
                continue
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if info.file_size > _MAX_ASSET_BYTES:
                continue
            try:
                raw = zf.read(name)
            except Exception:
                continue
            if _looks_binary(raw):
                continue
            text = raw.decode("utf-8", errors="ignore")
            if text:
                _harvest_text(text, urls, endpoints)
    return urls, endpoints


def _load_dex_files(path: Path, head: bytes) -> list[tuple[str, DEX]]:
    """加载 dex：裸 dex（dex\n / dey\n）直接修头；APK 走 parse_dexes（跳过非 ASCII 假 dex，不解析 Manifest）。"""
    if head in (b"dex\n", b"dey\n"):
        # 与 parse_dexes 保持一致：裸 dex 也先做廉价头校验，声明异常
        # （id 段越界）的诱饵不进 androguard，避免单文件几秒的解析空转。
        from ..dex_utils import dex_header_plausible

        data = path.read_bytes()
        if not dex_header_plausible(data):
            return []
        try:
            return [(path.name, DEX(fix_dex_header(data)))]
        except Exception:
            return []
    return parse_dexes(str(path))


def _extract_from_resources_arsc(apk_path: str) -> tuple[set[str], set[str]]:
    """扫 resources.arsc。部分样本把 API 只写在资源字符串池，不进 dex。"""
    urls: set[str] = set()
    endpoints: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path) as zf:
            raw = zf.read("resources.arsc")
    except Exception:
        return urls, endpoints
    if not raw or len(raw) > _MAX_ASSET_BYTES:
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


def _extract_resources_arsc_traced(apk_path: str) -> tuple[list[dict], set[str]]:
    urls, endpoints = _extract_from_resources_arsc(apk_path)
    items = []
    for u in urls:
        ind = make_indicator(u, "resources", "resources.arsc", "string_pool")
        if ind:
            items.append(ind)
    return items, endpoints


def _merge_binary_into_indicators(apk_path: str, *, deep: bool) -> tuple[list[dict], set[str]]:
    urls, endpoints = _extract_apk_binary_urls(apk_path, deep=deep)
    items = []
    method = "binary_deep" if deep else "binary"
    for u in urls:
        ind = make_indicator(u, "binary", "apk", method)
        if ind:
            items.append(ind)
    return items, endpoints


def extract(apk_path: str) -> tuple[set[str], set[str]]:
    """extract_indicators 的轻量视图：只要 URL 字符串集（丢出处），独立 CLI 用。"""
    items, endpoints = extract_indicators(apk_path)
    return {i["url"] for i in items if i.get("url")}, endpoints


def extract_assets_traced(apk_path: str) -> tuple[list[dict], set[str]]:
    """扫 APK 文本资源，每条 URL 带 zip 内路径（脱壳后的裸 dex 没有 assets，用原包补）。"""
    items: list[dict] = []
    endpoints: set[str] = set()
    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception:
        return items, endpoints
    with zf:
        for name in zf.namelist():
            low = name.replace("\\", "/").lower()
            if not low.endswith(_ASSET_EXTS):
                continue
            if _skip_asset(low):
                continue
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if info.file_size > _MAX_ASSET_BYTES:
                continue
            try:
                raw = zf.read(name)
            except Exception:
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


def _extract_manifest_indicators(apk_path: str) -> list[dict]:
    """从 AndroidManifest.xml 抽 URL（二进制 AXML 转 XML 后再扫字符串）。"""
    items: list[dict] = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            raw = z.read("AndroidManifest.xml")
    except Exception:
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
    except Exception:
        pass
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


def _extract_dex_string_indicators(dex_files, items: list[dict], endpoints: set[str]) -> None:
    """遍历 dex 字符串池提取 URL + 端点（items/endpoints 就地追加）。"""
    for name, dex in dex_files:
        try:
            strings = dex.get_strings()
        except Exception:
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


def _extract_bare_dex_indicators(path: Path, items: list[dict], endpoints: set[str]) -> None:
    """裸 dex：字符串池之外再扫原始字节。"""
    try:
        for u in _scan_raw_for_urls(path.read_bytes()):
            ind = make_indicator(u, "dex", path.name, "raw_bytes")
            if ind:
                items.append(ind)
    except OSError:
        pass


def _extract_apk_indicators(path: Path, items: list[dict], endpoints: set[str]) -> list[dict]:
    """zip APK：assets/arsc/native/manifest + 二进制浅扫；无相关 URL 时 deep 回扫。"""
    traced, ae = extract_assets_traced(str(path))
    items.extend(traced)
    endpoints |= ae
    arsc_items, arsc_ep = _extract_resources_arsc_traced(str(path))
    items.extend(arsc_items)
    endpoints |= arsc_ep
    items.extend(extract_native(str(path)))
    items.extend(_extract_manifest_indicators(str(path)))
    # 浅扫二进制（dex/so 等），与字符串池互补
    bin_items, bin_ep = _merge_binary_into_indicators(str(path), deep=False)
    items.extend(bin_items)
    endpoints |= bin_ep
    merged = merge_indicators(items)
    if not _has_relevant_url(merged):
        deep_items, deep_ep = _merge_binary_into_indicators(str(path), deep=True)
        items.extend(deep_items)
        endpoints |= deep_ep
        merged = merge_indicators(items)
    return merged


def extract_indicators(apk_path: str) -> tuple[list[dict], set[str]]:
    """提取 URL 指标（含出处）。裸 dex 只扫字符串池。"""
    path = Path(apk_path)
    with open(path, "rb") as fh:
        head = fh.read(4)

    items: list[dict] = []
    endpoints: set[str] = set()
    dex_files = _load_dex_files(path, head)
    _extract_dex_string_indicators(dex_files, items, endpoints)

    if head in (b"dex\n", b"dey\n"):
        _extract_bare_dex_indicators(path, items, endpoints)
        return merge_indicators(items), endpoints

    return _extract_apk_indicators(path, items, endpoints), endpoints


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
                except Exception:
                    continue
                if _looks_encrypted_blob(raw):
                    encrypted = True
    except Exception:
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


def write_url_files(directory: Path, urls: set[str], endpoints: set[str]) -> set[str]:
    """写出 urls_by_rank.txt（只含相关 URL），返回业务 URL 集合。

    只写 biz（业务）→ 有信号的 weak；noise / 裸域名 weak / endpoints 不进文件。
    http 与 https、utm locale 变体会折叠。
    """
    directory.mkdir(parents=True, exist_ok=True)
    folded = fold_related_urls(urls)
    biz = {u for u in folded if u and url_rank(u) == "biz"}
    weak = {u for u in folded if u and weak_worth_listing(u)}
    weak_all = sum(1 for u in folded if u and url_rank(u) == "weak")
    noise_n = sum(1 for u in folded if u and url_rank(u) == "noise")
    lines = [
        "# URL 提取结果（仅相关：biz / weak）",
        f"# 写入 biz={len(biz)}  weak={len(weak)}  "
        f"（未写入 noise={noise_n} weak_bare={weak_all - len(weak)} "
        f"endpoints={len(endpoints)}）",
        "",
        f"## biz（业务）  {len(biz)}",
    ]
    lines.extend(sorted(biz) if biz else ["（无）"])
    lines.append("")
    lines.append(f"## weak（弱信号）  {len(weak)}")
    lines.extend(sorted(weak) if weak else ["（无）"])
    lines.append("")
    (directory / "urls_by_rank.txt").write_text("\n".join(lines), encoding="utf-8")
    # 旧分文件不再写；若目录里残留则删掉，避免和单文件重复
    for legacy in ("urls.txt", "urls_biz.txt", "urls_weak.txt", "endpoints.txt"):
        old = directory / legacy
        if old.is_file():
            try:
                old.unlink()
            except OSError:
                pass
    return biz


def _print_results(urls: set[str], endpoints: set[str]) -> None:
    biz = business_urls(urls)
    print("=== 业务 URL ===")
    for u in sorted(biz):
        print(u)
    print("\n=== 全部 URL（含 SDK） ===")
    for u in sorted(urls):
        print(u)
    print("\n=== 端点路径 ===")
    for e in sorted(endpoints):
        print(e)


def main() -> int:
    parser = argparse.ArgumentParser(description="静态分析 APK/裸 dex，提取 URL 和端点路径")
    parser.add_argument("apk", help="APK 或裸 dex 文件路径")
    parser.add_argument("-o", "--out", help="输出文件路径（URL 写到这里，端点写到 <name>_endpoints<ext>）")
    args = parser.parse_args()

    apk = Path(args.apk)
    if not apk.exists():
        print(f"[错误] 文件不存在: {apk}", file=sys.stderr)
        return 2

    print(f"[*] 分析: {apk}")
    try:
        urls, endpoints = extract(str(apk))
    except Exception as e:
        print(f"[错误] 分析失败: {e}", file=sys.stderr)
        return 2

    biz = business_urls(urls)
    print(f"[*] 完整 URL: {len(urls)} 个  业务 URL: {len(biz)} 个  端点路径: {len(endpoints)} 个\n")

    if args.out:
        out_path = Path(args.out)
        ep_path = out_path.with_name(out_path.stem + "_endpoints" + out_path.suffix)
        biz_path = out_path.with_name(out_path.stem + "_biz" + out_path.suffix)
        try:
            out_path.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")
            biz_path.write_text("\n".join(sorted(biz)) + "\n", encoding="utf-8")
            ep_path.write_text("\n".join(sorted(endpoints)) + "\n", encoding="utf-8")
            print(f"[+] 完整 URL -> {out_path} ({len(urls)} 条)")
            print(f"[+] 业务 URL -> {biz_path} ({len(biz)} 条)")
            print(f"[+] 端点路径 -> {ep_path} ({len(endpoints)} 条)")
            print("\n=== 业务 URL ===")
            for u in sorted(biz):
                print(u)
        except OSError as e:
            print(f"[警告] 写入文件失败: {e}，改在屏幕输出", file=sys.stderr)
            _print_results(urls, endpoints)
    else:
        _print_results(urls, endpoints)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
