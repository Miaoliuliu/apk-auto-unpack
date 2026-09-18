#!/usr/bin/env python3
"""脱壳产物验证：业务 dex 判定、方法体完整性、产物 URL 提取编排。

补齐 adapters.py 合同里的 validate 环节（probe / execute 在 adapters，
validate 在这里，collect 由 flow/pipeline 完成）。
产物目录布局与归档在 runtime/product.py。
"""

from __future__ import annotations

from pathlib import Path

# 与 脱壳方案_dpt-shell.md 一致：业务 dex 的 shell_ratio < 10% 视为完整
COMPLETE_THRESHOLD = 0.1
PAYLOAD_MIN_BYTES = 24 * 1024
PAYLOAD_MIN_CLASSES = 30
PAYLOAD_MIN_CONCRETE = 20
PAYLOAD_ALWAYS_BYTES = 100 * 1024
FRAMEWORK_NAME_BYTES = 200 * 1024

_FW_PREFIX = (
    "Landroid/", "Lcom/android/", "Lcom/google/android/",
    "Ldalvik/", "Ljava/", "Ljavax/", "Llibcore/",
)


def framework_ratio(class_names) -> float:
    if not class_names:
        return 0.0
    sample = list(class_names)[:80]
    hit = sum(1 for n in sample if str(n).startswith(_FW_PREFIX))
    return hit / len(sample) if sample else 0.0


def is_payload_dex(path: Path, stats: dict | None = None) -> bool:
    """是否像业务 dex（排除 360 stub / 系统 hidden API 小文件）。"""
    stats = stats or {}
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    classes = int(stats.get("classes") or 0)
    concrete = int(stats.get("concrete") or 0)
    fw = float(stats.get("framework_ratio") or 0.0)
    if fw >= 0.85:
        return False
    # 体积达标即视为业务 dex。
    #
    # 曾改为「条目数与体积相称」（entries/size 密度）以拦下 ADIA/classes08.dex
    # （17.9MB / 4 个类）这类体积伪装，实测**严重误伤**：绘本 252 个 dex 中
    # 体积最大的那些（25MB / classes 192~251 / 方法 1000+）密度仅 0.05~0.07
    # 每 KB，全被判为非业务 dex。原因是这批 dump 产物的 file_size 天然包含
    # 内存邻近区块，体积/内容比本就偏低，密度不是可靠判据。
    # 结论：只保留 `entries > 0` 这一极保守保护（挡纯填充），体积伪装交给
    # dedupe_dumped_dex（同源去重）与告警（warn_suspect_dumped_dex）处理。
    if size >= PAYLOAD_ALWAYS_BYTES:
        return (classes + concrete) > 0
    if classes >= PAYLOAD_MIN_CLASSES and concrete >= PAYLOAD_MIN_CONCRETE:
        return True
    if size >= PAYLOAD_MIN_BYTES and classes >= 10:
        return True
    return False


def summarize_completeness(rows: list[dict]) -> dict:
    """按业务 dex 加权。rows 项含 name/payload/concrete/empty/empty_shell/shell_ratio/extraction。"""
    payload = [r for r in rows if r.get("payload")]
    skipped = [r.get("name") for r in rows if not r.get("payload")]
    if not payload:
        return {
            "complete": False,
            "complete_threshold": COMPLETE_THRESHOLD,
            "weighted_shell_ratio": 1.0,
            "max_shell_ratio": 1.0,
            "payload_dex_count": 0,
            "skipped_stub_dex": skipped,
            "complete_note": "没有达到体积/类数门槛的业务 dex",
        }
    conc = sum(int(r.get("concrete") or 0) for r in payload)
    empty = sum(int(r.get("empty") or 0) + int(r.get("empty_shell") or 0) for r in payload)
    max_ratio = max(float(r.get("shell_ratio") or r.get("ratio") or 0.0) for r in payload)
    if not conc:
        return {
            "complete": False,
            "complete_threshold": COMPLETE_THRESHOLD,
            "weighted_shell_ratio": 1.0,
            "max_shell_ratio": max_ratio,
            "payload_dex_count": len(payload),
            "skipped_stub_dex": skipped,
            "complete_note": "业务 dex 没有可统计的具体方法",
        }
    weighted = empty / conc
    complete = max_ratio < COMPLETE_THRESHOLD
    return {
        "complete": complete,
        "complete_threshold": COMPLETE_THRESHOLD,
        "weighted_shell_ratio": weighted,
        "max_shell_ratio": max_ratio,
        "payload_dex_count": len(payload),
        "skipped_stub_dex": skipped,
        "complete_note": (
            f"业务 dex shell_ratio < {COMPLETE_THRESHOLD:.0%}"
            if complete
            else f"业务 dex 最大 shell_ratio {max_ratio:.1%} >= {COMPLETE_THRESHOLD:.0%}"
        ),
    }


def _analyze_one_dumped_dex(dp: Path, items: list[dict], endpoints: set[str],
                            dex_analyze, extract_indicators) -> dict:
    """分析单个 dump 出的 dex：结构 + payload 判定 + URL 提取，返回 row。"""
    print(f"[*] 分析脱出的 dex: {dp.name}")
    stats: dict = {}
    try:
        size_now = dp.stat().st_size
    except OSError:
        size_now = 0
    try:
        info = dex_analyze(str(dp), collect_names=size_now < FRAMEWORK_NAME_BYTES)
        if info.get("dex"):
            stats = dict(info["dex"][0])
        if info.get("class_names"):
            stats["framework_ratio"] = framework_ratio(info["class_names"])
    except Exception as ex:
        print(f"      [警告] 结构分析失败: {ex}")

    payload = is_payload_dex(dp, stats)
    ratio = float(stats.get("shell_ratio") if stats.get("shell_ratio") is not None
                  else stats.get("ratio") or 0.0)
    empty = int(stats.get("empty") or 0) + int(stats.get("empty_shell") or 0)
    concrete = int(stats.get("concrete") or 0)
    extraction = stats.get("extraction") or "none"
    try:
        size = dp.stat().st_size
    except OSError:
        size = 0
    print(f"      方法体空占比 {ratio:.1%} ({empty}/{concrete}) -> {extraction}"
          f"{'' if payload else '  [stub/框架，不计入完整性、不提 URL]'}")

    if payload:
        url_stats: dict = {}
        try:
            inds, e = extract_indicators(str(dp), stats=url_stats)
            items.extend(inds)
            endpoints |= e
        except Exception as ex:
            print(f"      [警告] URL 提取失败: {ex}")
            url_stats.setdefault("source_errors", []).append({
                "source": "dumped_dex", "file": dp.name, "error": str(ex),
            })
    else:
        url_stats = {}

    row = {
        "name": dp.name,
        "size": size,
        "classes": int(stats.get("classes") or 0),
        "concrete": concrete,
        "empty": int(stats.get("empty") or 0),
        "empty_shell": int(stats.get("empty_shell") or 0),
        "shell_ratio": ratio,
        "extraction": extraction,
        "payload": payload,
        "url_extraction_stats": url_stats,
    }
    if stats.get("framework_ratio"):
        row["framework_ratio"] = round(float(stats["framework_ratio"]), 3)
    return row


def analyze_dumped_dexes(dexes: list[Path], apk_path: str | None
                         ) -> tuple[set[str], list[dict], dict, list[dict]]:
    """分析 dump 出的 dex：业务包提 URL，全部记结构，完整性只看业务 dex。

    返回 (endpoints, rows, quality, indicators)。
    """
    from ..extraction.analyze import extract_apk_non_dex_sources, extract_indicators
    from ..extraction.indicators import merge_indicators
    from ..packer.packer_sigs import analyze_dex_structure as dex_analyze

    endpoints: set[str] = set()
    items: list[dict] = []
    rows: list[dict] = []
    apk_url_stats: dict = {}

    for dp in dexes:
        rows.append(_analyze_one_dumped_dex(dp, items, endpoints, dex_analyze, extract_indicators))

    if apk_path:
        try:
            extra, ae = extract_apk_non_dex_sources(apk_path, stats=apk_url_stats)
            items.extend(extra)
            endpoints |= ae
            print(f"[*] APK 资源补 URL: {len(extra)} 个  端点: {len(ae)} 个")
        except Exception as ex:
            print(f"[警告] APK 资源扫描失败: {ex}")

    quality = summarize_completeness(rows)
    combined_url_stats: dict[str, list] = {}
    for source_stats in [
        *(row.get("url_extraction_stats") or {} for row in rows),
        apk_url_stats,
    ]:
        for key, value in source_stats.items():
            if isinstance(value, list) and value:
                combined_url_stats.setdefault(key, []).extend(value)
    quality["extraction_stats"] = combined_url_stats
    if quality["complete"]:
        print(f"[*] 方法体完整性: 通过（{quality['complete_note']}，"
              f"业务 dex {quality['payload_dex_count']} 个，跳过 stub "
              f"{len(quality['skipped_stub_dex'])} 个）")
    else:
        print(f"[警告] 方法体完整性未通过：{quality['complete_note']}，"
              "可加大 --sleep 再跑")

    return endpoints, rows, quality, merge_indicators(items)


def warn_extraction(rows: list[dict]) -> None:
    """dump 之后看方法体是否完整，提示可能漏 URL。"""
    payload = [r.get("extraction") or "none" for r in (rows or []) if r.get("payload")]
    look = payload or [r.get("extraction") or "none" for r in (rows or [])]
    if "full" in look:
        print("[警告] 检测到函数抽取：dump 产物方法体为空，需主动调用脱壳，URL 可能不全")
    elif "partial" in look:
        print("[提示] 部分方法体缺失，可能需主动调用补充")
