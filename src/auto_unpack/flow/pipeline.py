#!/usr/bin/env python3
"""APK 分析流水线：纯后端状态机。

    python -m auto_unpack                    # 读取 APK/ 全部 .apk
    python -m auto_unpack analyze <app.apk> [-o 产物目录]
    python -m auto_unpack detect <app.apk>
    python -m auto_unpack <app.apk> --unpack [--package NAME]

阶段：RECEIVED → VALIDATED → DETECTING → (NO_PACKER|PACKER_*) →
      UNPACKING → UNPACKED → EXTRACTING → COMPLETED | NEEDS_REVIEW | FAILED

产物目录写 urls_by_rank.txt（URL 分级清单）以及 meta.json。
packer/apkid.py 是同一套流水线的壳识别口。

run() 已按阶段拆分为私有函数（_stage_*），本模块只保留编排骨架。
"""

from __future__ import annotations

import sys
from pathlib import Path

from .sample import SampleError, ingest
from .states import (
    COMPLETED,
    DETECTING,
    E_NO_MANIFEST,
    E_NOT_ZIP,
    EXTRACTING,
    FAILED,
    NEEDS_REVIEW,
    NO_PACKER,
    PACKER_IDENTIFIED,
    PACKER_SUSPECTED,
    UNPACKED,
    UNPACKING,
    UNPACK_CORRUPTED,
    UNPACK_NOT_INSTALLED,
    UNPACK_SKIPPED,
    UNPACK_UNSUPPORTED,
    UNPACK_MANUAL,
    VALIDATED,
    Task,
    classify_unpack,
)
from ..unpacker.adapters import execute as adapter_execute
from ..unpacker.adapters import select_adapter
from ..unpacker.validate import analyze_dumped_dexes, warn_extraction
from ..packer.packer_sigs import dex_unreadable, has_payload_dex
from ..extraction.report import exit_code, failed_report, packed_flag, packer_label


def _tool_versions() -> dict:
    import sys as _sys
    out = {"python": _sys.version.split()[0]}
    try:
        import androguard
        out["androguard"] = getattr(androguard, "__version__", "unknown")
    except Exception:
        pass
    return out


def _packer_confidence(sig: dict) -> tuple[str, float]:
    if sig.get("vmp"):
        return "high", 0.9
    if sig.get("custom_family") == "jdog_native_dex_loader":
        return "high", 0.93
    if sig.get("custom_family") == "packhub_shell":
        return "high", 0.9
    kind = sig.get("dpt_type")
    if kind == "standard":
        return "high", 0.95
    if kind in ("modified", "appended"):
        return "high", 0.88
    if kind == "suspected":
        return "low", 0.45
    matched = sig.get("matched") or []
    if len(matched) > 1:
        return "medium", 0.7
    if matched:
        return "high", 0.9
    if sig.get("custom_packer") or sig.get("dex_stub"):
        return "medium", 0.55
    return "low", 0.2


def _packer_status(route: str, sig: dict) -> str:
    if route == "static":
        return "NO_PACKER"
    if route == "unknown":
        return "PACKER_IDENTIFIED"
    if sig.get("vmp"):
        return "PACKER_IDENTIFIED"
    if sig.get("dpt_type") == "suspected":
        return "PACKER_SUSPECTED"
    matched = sig.get("matched") or []
    if len(matched) > 1 and not sig.get("dpt_shell"):
        return "AMBIGUOUS"
    if matched or sig.get("dpt_shell"):
        return "PACKER_IDENTIFIED"
    return "PACKER_SUSPECTED"


def _packer_name(sig: dict) -> str | None:
    matched = sig.get("matched") or []
    vendor = "+".join(m.get("vendor") or m.get("key") or "?" for m in matched) if matched else None
    if sig.get("vmp"):
        return f"{vendor}(VMP)" if vendor else "VMP/Dex2C"
    if sig.get("dpt_shell"):
        return "dpt-shell"
    if sig.get("custom_family") in ("jdog_native_dex_loader", "packhub_shell"):
        return "自研保护"
    if vendor:
        return vendor
    if dex_unreadable(sig) or sig.get("dex_stub") or sig.get("custom_family"):
        return "自研保护"
    return None


def _evidence(sig: dict) -> list[str]:
    ev: list[str] = []
    for m in sig.get("matched") or []:
        ev.extend(m.get("evidence") or [])
    ev.extend(sig.get("vmp_evidence") or [])
    ev.extend(sig.get("dpt_shell_files") or [])
    ev.extend(sig.get("dpt_suspect_evidence") or [])
    ev.extend(sig.get("edition_evidence") or [])
    if sig.get("dpt_shell"):
        if sig.get("dpt_type"):
            ev.append(f"dpt_type:{sig['dpt_type']}")
        for so in sig.get("dpt_shell_so") or []:
            ev.append(Path(so).name)
        if sig.get("appcomponentfactory"):
            ev.append("appComponentFactory")
        if sig.get("dex_stub"):
            ev.append(f"dex_stub:{list(sig.get('dex_classes') or [])}")
        elif sig.get("dex_classes"):
            ev.append(f"dex_classes:{list(sig.get('dex_classes'))}")
        if sig.get("malformed_manifest"):
            ev.append("malformed_manifest")
    if sig.get("custom_packer") or sig.get("custom_packer_strong"):
        if sig.get("custom_family"):
            ev.append(f"custom_family:{sig['custom_family']}")
        for so in sig.get("jdog_native_loader") or []:
            ev.append(f"native_loader:{Path(so).name}")
        for lib in (sig.get("random_libs") or [])[:8]:
            ev.append(f"random_lib:{lib}")
        n = sig.get("fake_dex_decoys_count") or 0
        if n:
            ev.append(f"fake_dex_decoys:{n}")
        ev.extend(sig.get("hex_packer_pairs") or [])
        if n or sig.get("hex_packer_pairs"):
            ev.append("zip_decoy")
        if sig.get("malformed_manifest"):
            ev.append("malformed_manifest")
        if sig.get("hex_packer_pairs") or sig.get("malformed_manifest") or n:
            ev.append("anti_analysis")
        if sig.get("custom_packer_strong"):
            ev.append("custom_packer_strong")
    for so in (sig.get("anti_analysis") or [])[:6]:
        ev.append(f"anti_so:{so}")
        ev.append("anti_analysis")
    if sig.get("custom_family"):
        tag = f"custom_family:{sig['custom_family']}"
        if tag not in ev:
            ev.append(tag)
    if sig.get("class_shortfall"):
        ev.append(f"class_shortfall:{list(sig.get('dex_classes') or [])}")
    n_fake = int(sig.get("fake_zip_encrypt_count") or 0)
    if n_fake:
        ev.append(f"fake_zip_encrypt:{n_fake}")
        ev.append("anti_analysis")
    n_enc = int(sig.get("zip_encrypted_dex_count") or 0)
    if n_enc:
        ev.append(f"zip_encrypted_dex:{n_enc}")
    if sig.get("dex_unreadable"):
        ev.append("dex_unreadable")
    if sig.get("dex_stub") and not sig.get("dpt_shell"):
        ev.append(f"dex_stub:{list(sig.get('dex_classes') or [])}")
    if sig.get("has_shell") and not ev:
        ev.append("has_shell")
    # 去重保序
    seen, out = set(), []
    for x in ev:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out[:24]


def _is_not_installed_err(msg: str) -> bool:
    low = (msg or "").lower()
    return "unable to find application" in low or (
        "identifier" in low and "find" in low
    )


def _extract_apk(task: Task) -> None:
    from ..extraction.analyze import extract_indicators, scan_extraction_warnings
    stats: dict = {}
    inds, eps = extract_indicators(task.apk_path, stats=stats)
    task.urls = inds
    task.endpoints = sorted(eps)
    task.extraction_stats = stats
    for w in scan_extraction_warnings(task.apk_path, inds):
        task.warn(w)
    failed = len(stats.get("parse_failed") or []) + len(stats.get("encrypted_dex") or [])
    failed += len(stats.get("strings_failed") or [])
    if failed and not inds:
        task.warn(f"dex 解析失败/加密 {failed} 个，URL 提取结果可能不完整")


def _extract_dump(task: Task, dexes: list[Path]) -> tuple[list[dict], dict]:
    endpoints, rows, quality, items = analyze_dumped_dexes(dexes, task.apk_path)
    task.urls = items
    task.endpoints = sorted(endpoints)
    return rows, quality


def _finish_files(task: Task, meta_extra: dict | None = None, *,
                  write_urls: bool = True) -> None:
    meta = {
        "package": task.sample.get("package_name"),
        "package_trusted": task.sample.get("package_trusted"),
        "package_source": task.sample.get("package_source"),
        "package_note": task.sample.get("package_note") or "",
        "task_id": task.task_id,
        "status": task.status,
        "route": task.route,
        "flow": (task.unpacking or {}).get("adapter"),
        "dex_count": len((task.unpacking or {}).get("artifacts") or []),
        "complete": (task.unpacking or {}).get("status") == "VALID",
        "protection": (task.packer or {}).get("protection"),
        "url_completeness": (task.packer or {}).get("url_completeness"),
        "url_confidence": (task.packer or {}).get("url_confidence"),
    }
    meta.update(task.unpacking.get("quality") or {})
    if meta_extra:
        meta.update(meta_extra)
    url_set = {u["url"] for u in task.urls if u.get("url")}
    ust = (task.unpacking or {}).get("status")
    if ust == UNPACK_MANUAL:
        meta["complete"] = False
        if not meta.get("complete_note"):
            meta["complete_note"] = (task.unpacking or {}).get("note") or "需人工"
    # quality.complete 只描述 dump 出的 dex；无壳任务 COMPLETED 时原包可扫
    elif task.status == COMPLETED and ust in (
        UNPACK_SKIPPED, UNPACK_NOT_INSTALLED, UNPACK_UNSUPPORTED,
    ):
        meta["complete"] = True
        if not meta.get("complete_note"):
            if task.route == "static":
                meta["complete_note"] = "无壳，未走动态脱壳"
            elif ust == UNPACK_NOT_INSTALLED:
                meta["complete_note"] = "设备未安装，原包已有业务 dex"
            else:
                meta["complete_note"] = "跳过动态脱壳"
    if not write_urls:
        return
    from ..extraction.analyze import write_url_files, url_rank
    url_dir = Path(task.sample.get("url_dir") or task.out_dir)
    # 传 task.urls，产物每条 URL 才能带「从哪来」的标注（人工复核用）
    biz = write_url_files(url_dir, url_set, set(task.endpoints), task.urls)
    ranks = {"noise": 0, "weak": 0, "biz": 0}
    for u in url_set:
        r = url_rank(u)
        ranks[r] = ranks.get(r, 0) + 1
    meta["url_count"] = len(url_set)
    meta["url_biz_count"] = len(biz)
    meta["url_weak_count"] = ranks.get("weak", 0)
    meta["url_rank"] = ranks
    meta["endpoint_count"] = len(task.endpoints)
    meta["url_dir"] = str(url_dir)
    print(f"[+] URL（相关）-> {url_dir / 'urls_by_rank.txt'} "
          f"(biz={len(biz)} weak={ranks.get('weak', 0)}；noise/endpoints 未写入文件)")
    task.sample["url_dir"] = str(url_dir)


def _fallback_static_or_review(task: Task, sig: dict, *, progress: str,
                               note: str, complete: bool) -> None:
    """动态脱壳走不通时的统一兜底：原包已有业务 dex 就降级静态提取，否则转人工。

    complete=True 表示原包提取即算完成（未安装/设备不可用），False 表示仍需人工复核。
    """
    if has_payload_dex(sig):
        task.advance(EXTRACTING, f"{progress}，原包已有业务 dex")
        try:
            _extract_apk(task)
        except Exception as ex:
            task.warn(f"原包提取失败: {ex}")
        if complete:
            task.advance(
                COMPLETED,
                f"原包已有业务 dex，biz={sum(1 for u in task.urls if u.get('rank')=='biz')}",
            )
        else:
            task.advance(NEEDS_REVIEW, note)
        _finish_files(task)
    else:
        task.urls = []
        task.endpoints = []
        task.advance(NEEDS_REVIEW, note)
        _finish_files(task, write_urls=False)


def _finish_protected_static(task: Task) -> None:
    """Static output from an APK with a known runtime DEX loader is partial."""
    biz_count = sum(1 for u in task.urls if u.get("rank") == "biz")
    if biz_count:
        task.packer["url_completeness"] = "partial_possible"
        task.packer["url_confidence"] = "medium"
        task.advance(COMPLETED, f"protected static extraction biz={biz_count}")
        return
    if task.urls:
        task.packer["url_completeness"] = "partial_possible"
        task.packer["url_confidence"] = "low"
        task.warn(
            "Only weak/SDK URLs found; runtime DEX may still contain business URLs"
        )
        task.advance(COMPLETED, "protected static extraction has only weak URLs")
        return
    task.packer["url_completeness"] = "unknown"
    task.packer["url_confidence"] = "none"
    task.unpacking = {
        "status": UNPACK_MANUAL,
        "adapter": "manual",
        "note": (
            f"{task.packer.get('name') or 'runtime DEX loader'}; "
            "no static URLs, manual dynamic analysis required"
        ),
        "artifacts": [],
    }
    task.advance(NEEDS_REVIEW, task.unpacking["note"])


def _stage_ingest(apk_s: str, out_dir: str | None,
                  package: str | None) -> Task | dict:
    """阶段 1：样本接入。失败时返回失败报告 dict。"""
    try:
        sample = ingest(apk_s, out_dir=out_dir, package=package, trusted=bool(package))
    except SampleError as e:
        print(f"[FAILED] {e.code}: {e.message}")
        return failed_report(apk=apk_s, code=e.code, message=e.message)

    task = Task(apk_s, sample["sha256"], sample["out_dir"])
    task.sample = sample
    task.tool_versions = _tool_versions()
    task.advance(VALIDATED, f"sha256={sample['sha256'][:16]}… {sample['size']}B")
    for w in sample.get("warnings") or []:
        task.warn(w)
    return task


def _build_packer_dict(task: Task, sig: dict, merged: dict, info: dict,
                       route: str, pstatus: str, conf_l: str, conf_s: float,
                       needs_package: bool) -> dict:
    """把识别结论组装成 packer 报告段（PRD 合同字段）。"""
    return {
        "status": pstatus,
        "name": _packer_name(sig),
        "route": route,
        "confidence": conf_l,
        "score": conf_s,
        "generation": merged["generation"],
        "edition": sig.get("edition"),
        "edition_evidence": list(sig.get("edition_evidence") or []),
        "custom_family": sig.get("custom_family"),
        "custom_family_confidence": sig.get("custom_family_confidence"),
        "protection": sig.get("custom_family"),
        "runtime_dex_loader": bool(sig.get("runtime_dex_loader")),
        "url_completeness": (
            "none" if route in ("unknown", "manual") else "complete"
        ),
        "url_confidence": (
            "none" if route in ("unknown", "manual") else "high"
        ),
        "vmp": bool(merged.get("vmp")),
        "vmp_source": merged.get("vmp_source"),
        "vmp_conflict": bool(merged.get("vmp_conflict")),
        "evidence": _evidence(sig),
        "dpt_type": sig.get("dpt_type"),
        "package_trusted": task.sample.get("package_trusted"),
        "needs_package": needs_package,
        "apkid": {
            "packers": merged.get("apkid_packers") or [],
            "suspicious": bool(merged.get("suspicious")),
            "has_protector": bool(merged.get("has_protector")),
            "has_anti_hook": bool(merged.get("has_anti_hook")),
            "nested_dex": info.get("nested_dex") or 0,
        },
        "dex_classes": sig.get("dex_classes") or [],
        "dex_unreadable": bool(sig.get("dex_unreadable") or dex_unreadable(sig)),
    }


def _stage_detect(task: Task, apk_s: str, *, package: str | None,
                  skip_apkid: bool, force_apkid: bool,
                  apkid_exe: str | None,
                  archive_detect: bool | None) -> bool:
    """阶段 2：壳识别 + APKiD 合并 + packer 组装 + 归档。返回是否继续。"""
    task.advance(DETECTING)
    from ..packer.packer_sigs import detect as sig_detect
    from ..packer.apkid import (
        EMPTY_APKID,
        classify,
        decide_route,
        merge_apkid,
        resolve_apkid_exe,
        run_apkid,
        should_run_apkid,
    )

    try:
        sig = sig_detect(apk_s)
    except Exception as e:
        task.fail("E_DETECT", str(e))
        return False

    run_ext = should_run_apkid(sig, force=force_apkid, skip=skip_apkid)
    info = dict(EMPTY_APKID)
    if run_ext:
        exe, exe_err = resolve_apkid_exe(apkid_exe)
        if exe_err:
            task.warn(exe_err)
        else:
            data, err = run_apkid(exe, Path(apk_s))
            if err:
                task.warn(f"APKiD 失败: {err}")
            elif data:
                info = classify(data)
    merged = merge_apkid(sig, info)
    sig = dict(sig)
    sig["generation"] = merged["generation"]
    sig["vmp"] = merged["vmp"]
    sig["has_shell"] = merged.get("has_shell")
    sig["apkid_packers"] = merged.get("apkid_packers") or []
    route = decide_route(sig, has_shell=bool(merged.get("has_shell")))
    if run_ext and (info.get("packers") or info.get("nested_dex") or info.get("tags")):
        print(
            f"[*] APKiD packers={info.get('packers') or []} "
            f"nested_dex={info.get('nested_dex') or 0} "
            f"tags={list((info.get('tags') or {}).keys())}",
            flush=True,
        )
    print(
        f"[*] dex_classes={sig.get('dex_classes')} stub={sig.get('dex_stub')} "
        f"has_shell={merged.get('has_shell')} route={route}",
        flush=True,
    )
    if merged.get("has_shell") and route == "static":
        task.warn("APKiD 疑似有壳，但原包 dex 类数已完整，改走静态提取")
    task.sig = sig
    task.route = route
    if package:
        task.sample["package_name"] = package
        task.sample["package_trusted"] = True
        task.sample["package_source"] = "cli"
    else:
        task.sample["package_name"] = sig.get("package")
        task.sample["package_trusted"] = sig.get("package_trusted")
        task.sample["package_source"] = sig.get("package_source")
        task.sample["package_note"] = sig.get("package_note") or ""
    needs_package = not bool(task.sample.get("package_trusted"))
    if needs_package:
        note = task.sample.get("package_note") or "包名不可信或未能解析"
        task.warn(f"NEEDS_PACKAGE: {note}；脱壳前请用 --package 指定")
    conf_l, conf_s = _packer_confidence(sig)
    if route == "static":
        conf_l, conf_s = "high", 0.85
    pstatus = _packer_status(route, sig)
    task.packer = _build_packer_dict(
        task, sig, merged, info, route, pstatus, conf_l, conf_s, needs_package)
    packed = packed_flag(route, pstatus)
    task.packer["packed"] = packed
    task.packer["packer"] = packer_label(packed, task.packer.get("name"))
    do_archive = archive_detect
    if do_archive is None:
        from ..runtime.product import archive_enabled
        do_archive = archive_enabled()
    if do_archive:
        try:
            from ..runtime.product import archive_detected_apk
            archived = archive_detected_apk(
                apk_s, task.packer.get("packer") or task.packer.get("name"),
            )
            task.sample["detect_archive"] = str(archived)
            print(f"[+] 壳识别归档 -> {archived}")
        except Exception as e:
            task.warn(f"壳识别归档失败: {e}")
    return True


def _stage_route(task: Task, sig: dict, *, device: str | None,
                 sleep: int | None, install: str | None,
                 unpack: bool | None, skip_unpack: bool, timeout: int | None,
                 detect_only: bool, force_unpack: bool) -> tuple[str, bool, dict]:
    """阶段 3：adapter 选择 + 环境解析 + 是否动态脱壳。返回 (adapter, want_dyn, cfg)。"""
    adapter = select_adapter(
        task.route, sig, task.packer.get("apkid", {}).get("packers") or [])
    task.packer["adapter"] = adapter
    task.packer["automatic_unpack"] = adapter in ("dpt-shell", "dpt")
    if task.route == "vendor" and adapter == "unsupported":
        task.packer["automatic_unpack"] = False
        task.packer["support_status"] = "unsupported_packer"
    else:
        task.packer["support_status"] = (
            "automatic" if task.packer["automatic_unpack"] else "manual_or_static"
        )
    from ..runtime.env import resolve
    cfg = resolve(
        device=device, sleep=sleep, install=install,
        unpack=False if skip_unpack else unpack, timeout=timeout,
    )
    packed = task.packer.get("packed")
    want_dyn = bool(cfg.get("unpack")) and packed is not False
    if packed == "unknown" and not force_unpack:
        want_dyn = False
    if adapter in ("unsupported", "manual", "skip"):
        want_dyn = False
    if task.route == "unknown":
        want_dyn = False
    if detect_only:
        want_dyn = False
    return adapter, want_dyn, cfg


def _stage_static(task: Task, detect_only: bool) -> dict:
    """阶段 4：无壳静态提取。"""
    task.advance(NO_PACKER, "无壳，静态提取")
    task.unpacking = {"status": UNPACK_SKIPPED, "adapter": "static", "artifacts": []}
    if detect_only:
        return task.to_report()
    task.advance(EXTRACTING, "原包 DEX/资源/native")
    try:
        _extract_apk(task)
    except Exception as e:
        task.fail("E_EXTRACT", str(e))
        return task.to_report()
    task.advance(COMPLETED, f"biz={sum(1 for u in task.urls if u.get('rank')=='biz')}")
    _finish_files(task)
    return task.to_report()


def _stage_manual(task: Task, sig: dict, adapter: str) -> dict | None:
    """阶段 6：付费壳 / VMP / 自研保护 → 转人工。不适用返回 None 继续往下。"""
    if sig.get("edition") == "paid":
        why = "360付费版，需人工"
        uadapter = "manual"
    elif sig.get("vmp") or task.route == "manual" or adapter == "manual":
        why = "VMP，需人工"
        uadapter = "manual"
    elif task.route == "unknown" or adapter == "skip":
        why = "自研保护，转人工分析"
        uadapter = "skip"
    else:
        return None
    task.unpacking = {
        "status": UNPACK_MANUAL, "adapter": uadapter, "note": why, "artifacts": [],
    }
    task.urls = []
    task.endpoints = []
    task.advance(NEEDS_REVIEW, why)
    _finish_files(task, write_urls=False)
    return task.to_report()


def _stage_no_dyn(task: Task, adapter: str, packed) -> dict:
    """阶段 7：动态脱壳未启用 / 厂商不支持。"""
    if adapter == "unsupported":
        why = "unsupported_packer"
        ustatus = UNPACK_UNSUPPORTED
    elif packed == "unknown":
        why = "packed=unknown，禁止强行脱壳"
        ustatus = UNPACK_SKIPPED
    else:
        why = "动态脱壳未启用（需要 --unpack）"
        ustatus = UNPACK_SKIPPED
    task.urls = []
    task.endpoints = []
    task.unpacking = {
        "status": ustatus, "adapter": adapter, "note": why, "artifacts": [],
    }
    task.advance(NEEDS_REVIEW, why)
    _finish_files(task, write_urls=False)
    return task.to_report()


def _resolve_pkg_on_device(task: Task, apk_s: str, package: str | None,
                           cfg: dict, sig: dict, adapter: str) -> str | None:
    """解析动态脱壳目标包名（adb install / --package / 静态解析）。

    无法确定时走 fallback 兜底并返回 None（主函数直接 return）。
    """
    from ..runtime.adb import list_packages, maybe_install
    from ..runtime.pkg_name import resolve_spawn_package_info

    # 动态脱壳：先 adb install，用设备上的真实包名再 Frida spawn。
    # 不要拿畸形 Manifest 猜的名字（Kcom.google...）去 spawn。
    # 仅 CLI --package 可在安装前使用（when_needed 判断设备上是否已有）。
    pkg: str | None = package
    pinfo: dict | None = None
    if pkg:
        pinfo = resolve_spawn_package_info(apk_s, package, None)
        pkg = pinfo["package"]

    try:
        installed = maybe_install(
            apk_s, cfg["device"], package=pkg, install=cfg["install"],
        )
    except Exception as e:
        task.warn(f"adb install 失败: {e}")
        installed = None
    task.sample["installed_pkg"] = installed

    on_device = list_packages(cfg["device"])
    if installed:
        pinfo = resolve_spawn_package_info(apk_s, None, installed)
        pkg = pinfo["package"]
        print(f"[*] 包名来自 adb install: {pkg}")
    elif pkg and pkg in on_device:
        print(f"[*] 包名来自 --package，设备已有: {pkg}")
    else:
        pkg = None
        pinfo = None
        try:
            static = resolve_spawn_package_info(apk_s, None, None)
        except Exception:
            static = None
        if (
            static
            and static.get("package_trusted")
            and static.get("package") in on_device
        ):
            pinfo = static
            pkg = static["package"]
            print(f"[*] 包名来自 APK 解析且已在设备上: {pkg}")
        else:
            why = (
                "无法从设备得到真实包名：请检查 adb install 是否成功，"
                "或用 --package 指定"
            )
            if static and static.get("package"):
                why += (
                    f"（Manifest 解析到 {static['package']}，"
                    f"来源={static.get('package_source')}，不可用于 spawn）"
                )
            task.warn(why)
            task.unpacking = {
                "status": UNPACK_SKIPPED, "adapter": adapter, "error": why,
            }
            _fallback_static_or_review(
                task, sig, progress="无法 spawn", note="E_BAD_PACKAGE", complete=False)
            return None

    if pinfo:
        task.sample["package_name"] = pkg
        task.sample["package_trusted"] = bool(pinfo.get("package_trusted"))
        task.sample["package_source"] = pinfo.get("package_source")
        task.sample["package_note"] = pinfo.get("package_note") or ""
    else:
        task.sample["package_name"] = pkg
        task.sample["package_trusted"] = True
        task.sample["package_source"] = "adb_install" if installed else "cli"

    if pkg not in on_device:
        task.warn(
            f"设备未安装 {pkg}（install={cfg['install']}）"
        )
        task.unpacking = {
            "status": UNPACK_NOT_INSTALLED,
            "adapter": adapter,
            "error": f"设备上没有 {pkg}",
            "artifacts": [],
        }
        _fallback_static_or_review(
            task, sig, progress="未安装", note="E_NOT_INSTALLED", complete=True)
        return None
    return pkg


def _maybe_uninstall(task: Task, cfg: dict) -> None:
    """脱壳完成后卸载本次 adb install 装的 app（env.json uninstall=true 时）。

    只卸载本次安装的包（installed_pkg），设备上原本就有的包不碰。
    """
    if not cfg.get("uninstall", True):
        return
    installed = task.sample.get("installed_pkg")
    if not installed:
        return
    from ..runtime.adb import uninstall
    try:
        ok = uninstall(installed, cfg.get("device"))
        print(f"[*] 卸载 {'成功' if ok else '失败'}: {installed}")
    except Exception as e:
        task.warn(f"卸载失败: {e}")


def _stage_dyn_unpack(task: Task, apk_s: str, package: str | None,
                      adapter: str, cfg: dict, deep: bool, sig: dict) -> dict:
    """阶段 8：动态脱壳全流程（包名解析 → 安装 → dump → 提取 → 验证）。"""
    task.advance(UNPACKING, f"adapter={adapter}")
    from ..runtime.env import describe
    print(f"[*] 环境: {describe(cfg)}")

    pkg = _resolve_pkg_on_device(task, apk_s, package, cfg, sig, adapter)
    if pkg is None:
        return task.to_report()

    work = Path(task.sample.get("dex_dir") or "")
    if not work.parts:
        from ..runtime.product import default_dex_dir
        work = default_dex_dir(
            apk_s,
            task.sample.get("package_name"),
            bool(task.sample.get("package_trusted")),
        )
        task.sample["dex_dir"] = str(work)
    work.mkdir(parents=True, exist_ok=True)
    try:
        dexes = adapter_execute(
            adapter, apk_path=apk_s, package=pkg, out_dir=work,
            device=cfg["device"], sleep=cfg["sleep"], deep=deep,
            timeout=cfg.get("timeout"),
        )
    except Exception as e:
        err = str(e)
        task.warn(f"脱壳失败: {err}")
        missing = _is_not_installed_err(err)
        task.unpacking = {
            "status": UNPACK_NOT_INSTALLED if missing else UNPACK_CORRUPTED,
            "adapter": adapter, "error": err,
            "artifacts": [],
            "stage": "start" if missing else "dump",
        }
        _fallback_static_or_review(
            task, sig, progress="dump 失败", note="E_UNPACK", complete=not missing)
        return task.to_report()
    finally:
        _maybe_uninstall(task, cfg)

    task.advance(UNPACKED, f"{len(dexes)} 个 dex")
    task.advance(EXTRACTING)
    try:
        rows, quality = _extract_dump(task, dexes)
    except Exception as e:
        task.fail("E_EXTRACT", str(e))
        return task.to_report()

    ustatus = classify_unpack(quality, rows)
    task.unpacking = {
        "status": ustatus,
        "adapter": adapter,
        "artifacts": rows,
        "quality": quality,
        "complete_threshold": quality.get("complete_threshold"),
    }
    warn_extraction(rows)

    if ustatus == "VALID":
        task.advance(COMPLETED, f"biz={sum(1 for u in task.urls if u.get('rank')=='biz')}")
    else:
        task.advance(NEEDS_REVIEW, f"产物 {ustatus}")
    _finish_files(task, {"flow": adapter, "dex": rows})
    return task.to_report()


def _cleanup_inbox_source(apk_s: str, task: Task | dict | None) -> None:
    """清理默认 APK 输入目录里已经处理完的源文件（避免重复跑 + 目录堆积）。

    仅完整 analyze 流程（非 detect_only）结束时调用；detect 只识别不清理源文件。
    正常 APK 必须先成功归档；接入阶段已明确判定为非 APK/缺少 Manifest 的
    无效输入没有归档价值，也应从默认收件箱移除。I/O、体积和 ZIP bomb 等
    其它校验错误仍保留，以免误删可能需要人工处理的样本。
    """
    if task is None:
        return
    src = Path(apk_s)
    rejected = False
    if isinstance(task, dict):
        code = (task.get("error") or {}).get("code")
        rejected = code in {E_NOT_ZIP, E_NO_MANIFEST}
        if not rejected:
            return
    else:
        archived = task.sample.get("detect_archive")
        if not archived:
            return
        arch = Path(archived)
        # 归档被禁用时 archive_detected_apk 返回源路径（未复制），不能删
        if arch.resolve() == src.resolve():
            return
    try:
        from ..runtime.product import default_apk_inbox
        inbox = default_apk_inbox().resolve()
        if src.resolve().parent == inbox:
            src.unlink(missing_ok=True)
            reason = "无效输入" if rejected else "已归档"
            print(f"[*] 已清理输入目录源文件: {src.name}（{reason}）")
    except OSError as e:
        print(f"[警告] 清理源文件失败: {e}")


def run(
    apk: str | Path,
    *,
    out_dir: str | None = None,
    package: str | None = None,
    device: str | None = None,
    sleep: int | None = None,
    deep: bool = False,
    skip_apkid: bool = False,
    force_apkid: bool = False,
    apkid_exe: str | None = None,
    skip_unpack: bool = False,
    unpack: bool | None = None,
    force_unpack: bool = False,
    timeout: int | None = None,
    install: str | None = None,
    detect_only: bool = False,
    archive_detect: bool | None = None,
) -> dict:
    """跑完整状态机，返回 report 字典（供 CLI 展示与退出码判断）。

    各阶段实现在 _stage_* 私有函数（本文件下方），此处只做编排。
    archive_detect：是否把样本归档到 packer_detection/（标签变了会清掉其它目录的旧拷贝）。
    None 时看环境变量 AUTO_UNPACK_DISABLE_ARCHIVE（测试应设为 1）。
    """
    apk_s = str(Path(apk))
    task: Task | dict | None = None
    try:
        # 阶段 1：接入（失败返回已写盘的 stub report）
        task = _stage_ingest(apk_s, out_dir, package)
        if isinstance(task, dict):
            return task

        # 阶段 2：识别 + APKiD 合并 + packer 组装 + 归档
        if not _stage_detect(
            task, apk_s, package=package, skip_apkid=skip_apkid,
            force_apkid=force_apkid, apkid_exe=apkid_exe,
            archive_detect=archive_detect,
        ):
            return task.to_report()

        sig = task.sig
        # 阶段 3：adapter 选择 + 环境解析 + 是否动态脱壳
        adapter, want_dyn, cfg = _stage_route(
            task, sig, device=device, sleep=sleep, install=install,
            unpack=unpack, skip_unpack=skip_unpack, timeout=timeout,
            detect_only=detect_only, force_unpack=force_unpack,
        )

        # 阶段 4：无壳 → 静态提取
        if task.route == "static":
            return _stage_static(task, detect_only)

        # 阶段 5：有壳 / 疑似 / VMP → 推进状态
        packed = task.packer.get("packed")
        pstatus = task.packer.get("status")
        if packed == "unknown" or pstatus in ("PACKER_SUSPECTED", "AMBIGUOUS"):
            task.advance(PACKER_SUSPECTED, task.packer.get("name") or task.route)
        else:
            task.advance(PACKER_IDENTIFIED, task.packer.get("name") or task.route)
        if detect_only:
            return task.to_report()

        # 阶段 6：付费 / VMP / 自研保护 → 转人工
        r = _stage_manual(task, sig, adapter)
        if r is not None:
            return r

        # 阶段 7：动态未启用 / 厂商不支持
        if not want_dyn:
            return _stage_no_dyn(task, adapter, packed)

        # 阶段 8：动态脱壳全流程
        return _stage_dyn_unpack(task, apk_s, package, adapter, cfg, deep, sig)
    finally:
        # 仅完整 analyze 流程跑完后清理源文件；detect（只识别）保留源文件，供后续再跑全流程
        if not detect_only:
            _cleanup_inbox_source(apk_s, task)


def print_cli_report(report: dict, extra_out: str | None = None) -> None:
    """命令行收尾：任务状态 + 业务 URL。文件清单已由 _finish_files 写出。"""
    packer = report.get("packer_detection") or report.get("packer") or {}
    unpacking = report.get("unpack") or report.get("unpacking") or {}
    extraction = report.get("extraction") or {}
    print(f"[*] 任务状态: {report.get('status')}  packed={packer.get('packed')}  "
          f"packer={packer.get('packer') or packer.get('name') or ''}  "
          f"路由: {report.get('route')}")
    sample = report.get("sample") or {}
    pkg = sample.get("package_name") or sample.get("package")
    if pkg:
        trust = "可信" if sample.get("package_trusted") else "NEEDS_PACKAGE，需要 --package"
        print(f"[*] 包名: {pkg}  来源={sample.get('package_source') or '-'}  {trust}")
        if sample.get("package_note") and not sample.get("package_trusted"):
            print(f"    {sample['package_note']}")
    elif sample.get("package_trusted") is False:
        print("[*] 包名: NEEDS_PACKAGE，未能解析，脱壳前请用 --package 指定")
    print(f"[*] 脱壳: {unpacking.get('status')}  adapter={unpacking.get('adapter')}")
    print(f"[*] 提取: {extraction.get('status')}  url_count={extraction.get('url_count')}")
    url_dir = (report.get("sample") or {}).get("url_dir")
    if url_dir and (Path(url_dir) / "urls_by_rank.txt").is_file():
        print(f"[+] URL -> {url_dir}/urls_by_rank.txt")
    dex_dir = (report.get("sample") or {}).get("dex_dir")
    if dex_dir:
        print(f"[+] dex -> {dex_dir}")
    from ..extraction.analyze import business_urls, format_url_line
    urls = report.get("urls") or []
    biz = [(u.get("value") or u.get("url"), u.get("sources") or [])
           for u in urls if u.get("rank") == "biz"]
    print("\n=== 业务 URL ===")
    if not biz:
        print("  （无）")
    for u, srcs in biz:
        print("  " + format_url_line(u, srcs))
    if not extra_out:
        return
    url_set = {u.get("value") or u.get("url") for u in urls if u.get("value") or u.get("url")}
    src_of = {u.get("value") or u.get("url"): (u.get("sources") or []) for u in urls}
    eps = report.get("endpoints") or []
    biz_set = business_urls(url_set)
    out_path = Path(extra_out)
    ep_path = out_path.with_name(out_path.stem + "_endpoints" + out_path.suffix)
    biz_path = out_path.with_name(out_path.stem + "_biz" + out_path.suffix)
    try:
        out_path.write_text(
            "\n".join(format_url_line(u, src_of.get(u)) for u in sorted(url_set)) + "\n",
            encoding="utf-8")
        biz_path.write_text(
            "\n".join(format_url_line(u, src_of.get(u)) for u in sorted(biz_set)) + "\n",
            encoding="utf-8")
        ep_path.write_text("\n".join(sorted(eps)) + "\n", encoding="utf-8")
        print(f"[+] 额外完整 URL -> {out_path} ({len(url_set)} 条)")
        print(f"[+] 额外业务 URL -> {biz_path} ({len(biz_set)} 条)")
        print(f"[+] 额外端点路径 -> {ep_path} ({len(eps)} 条)")
    except OSError as e:
        print(f"[警告] 额外输出写入失败: {e}", file=sys.stderr)


def main() -> int:
    from .cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
