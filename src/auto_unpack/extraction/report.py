"""PRD 报告合同：sample / packer_detection / unpack / extraction / urls / errors。

内部状态机字段（status、history、packer、unpacking）一并保留，方便对照。
报告里的路径只留文件名，避免带出本机目录。
"""

from __future__ import annotations

import re
from pathlib import Path

from ..constants import (
    COMPLETED,
    E_DETECT,
    E_EXTRACT,
    E_NO_MANIFEST,
    E_NOT_FOUND,
    E_NOT_ZIP,
    E_TOO_LARGE,
    E_UNPACK,
    E_VALIDATE,
    E_ZIP_BOMB,
    FAILED,
    NEEDS_REVIEW,
    UNPACK_CORRUPTED,
    UNPACK_MANUAL,
    UNPACK_NOT_INSTALLED,
    UNPACK_UNSUPPORTED,
    now_iso,
)
from .indicators import RANK_SCORE as _RANK_SCORE

EXIT_OK = 0
EXIT_NO_URL = 1
EXIT_BAD_INPUT = 2
EXIT_DETECT = 3
EXIT_UNPACK = 4
EXIT_FAILED = 5

INPUT_CODES = {
    E_NOT_FOUND, E_TOO_LARGE, E_NOT_ZIP, E_ZIP_BOMB, E_NO_MANIFEST, E_VALIDATE,
}

_WIN_PATH = re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')


def public_name(path: str | Path | None) -> str | None:
    if not path:
        return None
    return Path(str(path)).name


def public_out_dir(path: str | Path | None) -> str | None:
    """产物目录只保留末两级，避免带出用户主目录。"""
    if not path:
        return None
    p = Path(str(path))
    if p.parent and p.parent.name:
        return str(Path(p.parent.name) / p.name)
    return p.name


def redact_text(text: str | None) -> str:
    if not text:
        return ""
    return _WIN_PATH.sub(lambda m: Path(m.group(0)).name, str(text))


def packed_flag(route: str | None, pstatus: str | None) -> bool | str:
    """PRD: packed=false | true | unknown。未知壳已识别为有壳，只是厂商不明。"""
    if route == "static" or pstatus == "NO_PACKER":
        return False
    if route == "unknown":
        return True
    if pstatus in ("PACKER_SUSPECTED", "AMBIGUOUS"):
        return "unknown"
    return True


def packer_label(packed: bool | str, name: str | None) -> str:
    if packed is False:
        return "none"
    return name or "unknown"


def business_likelihood(item: dict) -> float:
    if item.get("business_likelihood") is not None:
        try:
            return float(item["business_likelihood"])
        except (TypeError, ValueError):
            pass
    return _RANK_SCORE.get(item.get("rank") or "", 0.4)


def url_confidence(item: dict) -> float:
    """兼容旧调用方；该值仅表示业务相关性，不代表 URL 有效或可达。"""
    return business_likelihood(item)


def project_url(item: dict) -> dict:
    """投影网络指标，明确区分业务相关性与语法/DNS/HTTP 验证。"""
    sources = item.get("sources") or []
    src = sources[0] if sources else {}
    value = item.get("value") or item.get("url") or ""
    return {
        "value": value,
        "type": item.get("type") or "url",
        "source_file": public_name(src.get("file")) or src.get("file"),
        "source_kind": src.get("type") or item.get("source_kind") or "unknown",
        "business_likelihood": business_likelihood(item),
        "url": item.get("url") or value,
        "rank": item.get("rank"),
        "host": item.get("host"),
        "canonical": item.get("canonical"),
        "observed_value": item.get("observed_value") or value,
        "scheme": item.get("scheme"),
        "port": item.get("port"),
        "path": item.get("path"),
        "validation": dict(item.get("validation") or {"syntax": "unknown"}),
        "sources": [
            {
                "type": s.get("type"),
                "file": public_name(s.get("file")) or s.get("file"),
                "method": s.get("method"),
            }
            for s in sources
        ],
    }


def classify_unpack_stage(err: str | None) -> str | None:
    if not err:
        return None
    low = err.lower()
    if any(x in low for x in ("找不到 frida", "frida 设备", "adb", "环境")):
        return "environment"
    if any(x in low for x in ("spawn", "package", "包名", "not found", "未安装")):
        return "start"
    if any(x in low for x in ("repair", "checksum", "修复")):
        return "repair"
    if any(x in low for x in ("stub", "valid", "完整", "verify")):
        return "verify"
    if any(x in low for x in ("dump", "脱壳")):
        return "dump"
    return "dump"


def public_sample(sample: dict | None) -> dict:
    sample = dict(sample or {})
    path = sample.get("path") or sample.get("filename")
    out = {
        "filename": sample.get("filename") or public_name(path),
        "sha256": sample.get("sha256"),
        "sha1": sample.get("sha1"),
        "md5": sample.get("md5"),
        "size": sample.get("size"),
        "package_name": sample.get("package_name"),
        "version_name": sample.get("version_name"),
        "version_code": sample.get("version_code"),
        "min_sdk": sample.get("min_sdk"),
        "target_sdk": sample.get("target_sdk"),
        "app_name": sample.get("app_name"),
        "has_dex": sample.get("has_dex"),
        "entry_count": sample.get("entry_count"),
        "package_trusted": sample.get("package_trusted"),
        "package_source": sample.get("package_source"),
        "package_note": sample.get("package_note") or "",
        "url_dir": public_out_dir(sample.get("url_dir")),
        "dex_dir": public_out_dir(sample.get("dex_dir")),
        "detect_archive": public_out_dir(sample.get("detect_archive")),
    }
    return out


def public_history(history: list | None) -> list[dict]:
    out = []
    for h in history or []:
        e = dict(h)
        if e.get("note"):
            e["note"] = redact_text(str(e["note"]))
        out.append(e)
    return out


def _collect_packer_candidates(task, packed: bool | str) -> list[str]:
    """packed=unknown 时收集可能的壳厂商名（供人工复核）。"""
    if packed != "unknown":
        return []
    candidates = []
    for m in (task.sig or {}).get("matched") or []:
        label = m.get("vendor") or m.get("key")
        if label and label not in candidates:
            candidates.append(label)
    if (task.packer or {}).get("name") and task.packer["name"] not in candidates:
        candidates.append(task.packer["name"])
    return candidates


def _has_runtime_warning(task) -> bool:
    """空结果但有 encrypted_config / runtime_h5 提示：静态盲区，标记 needs_review。"""
    return any(
        (w or "").startswith(("encrypted_config", "runtime_h5"))
        for w in (task.warnings or [])
    )


def _project_urls(task) -> tuple[list[dict], dict, str]:
    """URL 投影 + 类型计数 + 提取状态（failed / empty / needs_review / partial / ok）。"""
    urls = [project_url(u) for u in (task.urls or [])]
    types = {"url": 0, "domain": 0, "ip": 0}
    for u in urls:
        t = u.get("type") or "url"
        types[t] = types.get(t, 0) + 1
    extract_err = (task.error or {}).get("code") == E_EXTRACT
    stats = getattr(task, "extraction_stats", {}) or {}
    failed_sources = any(stats.get(key) for key in (
        "parse_failed", "encrypted_dex", "malformed_dex", "strings_failed",
        "source_errors", "source_skipped",
    ))
    runtime_warning = _has_runtime_warning(task)
    if extract_err:
        extraction_status = "failed"
    elif not urls:
        extraction_status = "needs_review" if runtime_warning or failed_sources else "empty"
    elif runtime_warning or failed_sources:
        extraction_status = "partial"
    else:
        extraction_status = "ok"
    return urls, types, extraction_status


def _validation_summary(urls: list[dict]) -> dict:
    summary: dict[str, dict[str, int]] = {"syntax": {}, "dns": {}, "http": {}}
    for item in urls:
        validation = item.get("validation") or {}
        for dimension, counts in summary.items():
            status = validation.get(dimension) or "unknown"
            counts[status] = counts.get(status, 0) + 1
    return summary


def _build_packer_detection(task, packed: bool | str, name: str | None, candidates: list[str]) -> dict:
    p = task.packer or {}
    sig = task.sig or {}
    return {
        "packed": packed,
        "packer": name,
        "confidence": p.get("confidence"),
        "score": p.get("score"),
        "status": p.get("status"),
        "evidence": list(p.get("evidence") or []),
        "candidates": candidates,
        "generation": p.get("generation"),
        "edition": p.get("edition"),
        "edition_evidence": list(p.get("edition_evidence") or []),
        "vmp": bool(p.get("vmp") or sig.get("vmp")),
        "protection": p.get("protection"),
        "custom_family": p.get("custom_family"),
        "custom_family_confidence": p.get("custom_family_confidence"),
        "runtime_dex_loader": bool(p.get("runtime_dex_loader")),
        "route": task.route,
        "apkid": p.get("apkid") or {},
        "package_trusted": (task.sample or {}).get("package_trusted"),
        "package_source": (task.sample or {}).get("package_source"),
        "package_note": (task.sample or {}).get("package_note") or "",
        "needs_package": bool(p.get("needs_package")),
        "dpt_type": p.get("dpt_type") or sig.get("dpt_type"),
        "dex_classes": list(p.get("dex_classes") or sig.get("dex_classes") or []),
        "url_completeness": p.get("url_completeness"),
        "url_confidence": p.get("url_confidence"),
    }


def build_report(task) -> dict:
    packed = packed_flag(task.route, (task.packer or {}).get("status"))
    name = packer_label(packed, (task.packer or {}).get("name"))
    candidates = _collect_packer_candidates(task, packed)
    urls, types, extraction_status = _project_urls(task)

    unpacking = dict(task.unpacking or {})
    if unpacking.get("error"):
        unpacking["error"] = redact_text(str(unpacking["error"]))
        unpacking.setdefault("stage", classify_unpack_stage(unpacking.get("error")))
    errors = []
    if task.error:
        errors.append({
            "code": task.error.get("code"),
            "message": redact_text(task.error.get("message") or ""),
            "stage": _error_stage(task.error.get("code")),
        })

    packer_detection = _build_packer_detection(task, packed, name, candidates)

    biz = [u for u in urls if u.get("rank") == "biz"]
    weak = [u for u in urls if u.get("rank") == "weak"]
    noise = [u for u in urls if u.get("rank") == "noise"]
    return {
        "task_id": task.task_id,
        "status": task.status,
        "history": public_history(task.history),
        "sample": public_sample(task.sample),
        "packer_detection": packer_detection,
        "packer": dict(task.packer or {}),
        "unpack": dict(unpacking),
        "unpacking": dict(unpacking),
        "extraction": {
            "status": extraction_status,
            "url_count": len(urls),
            "url_type": types,
            "url_completeness": (task.packer or {}).get("url_completeness"),
            "completeness_confidence": (task.packer or {}).get("url_confidence"),
            "validation": _validation_summary(urls),
            "stats": dict(getattr(task, "extraction_stats", {}) or {}),
        },
        "urls": urls,
        "url_summary": {
            "total": len(urls),
            "biz": len(biz),
            "weak": len(weak),
            "noise": len(noise),
            "endpoints": len(task.endpoints or []),
        },
        "endpoints": list(task.endpoints or []),
        "errors": errors,
        "warnings": [redact_text(w) for w in (task.warnings or [])],
        "error": (
            {
                "code": task.error.get("code"),
                "message": redact_text(task.error.get("message") or ""),
            }
            if task.error else None
        ),
        "tool_versions": dict(task.tool_versions or {}),
        "route": task.route,
    }


def failed_report(*, apk: str, code: str, message: str) -> dict:
    msg = redact_text(message)
    sample = {"filename": public_name(apk), "path": public_name(apk)}
    return {
        "task_id": None,
        "status": FAILED,
        "sample": sample,
        "packer_detection": {
            "packed": "unknown",
            "packer": "none",
            "confidence": None,
            "evidence": [],
            "candidates": [],
        },
        "packer": {},
        "unpack": {},
        "unpacking": {},
        "extraction": {"status": "failed", "url_count": 0, "url_type": {}},
        "urls": [],
        "url_summary": {"total": 0, "biz": 0, "weak": 0, "noise": 0, "endpoints": 0},
        "endpoints": [],
        "errors": [{"code": code, "message": msg, "stage": _error_stage(code)}],
        "warnings": [],
        "error": {"code": code, "message": msg},
        "tool_versions": {},
        "route": None,
        "history": [
            {"status": "RECEIVED", "at": now_iso(), "note": public_name(apk)},
            {"status": FAILED, "at": now_iso(), "note": f"{code}: {msg}"},
        ],
    }


def _error_stage(code: str | None) -> str:
    if code in INPUT_CODES:
        return "validate"
    if code == E_DETECT:
        return "detect"
    if code == E_UNPACK:
        return "unpack"
    if code == E_EXTRACT:
        return "extract"
    return "unknown"


def exit_code(report: dict) -> int:
    """成功 / 无 URL / 识别失败 / 脱壳失败 / 输入非法。"""
    status = report.get("status")
    err = report.get("error") or {}
    code = err.get("code")
    if status == FAILED:
        if code in INPUT_CODES:
            return EXIT_BAD_INPUT
        if code == E_DETECT:
            return EXIT_DETECT
        if code == E_UNPACK:
            return EXIT_UNPACK
        if code == E_EXTRACT:
            return EXIT_FAILED
        return EXIT_FAILED
    unpack = report.get("unpack") or report.get("unpacking") or {}
    ust = unpack.get("status")
    urls = report.get("urls") or []
    if status == NEEDS_REVIEW and ust == UNPACK_MANUAL:
        return EXIT_OK if urls else EXIT_NO_URL
    if status == NEEDS_REVIEW and ust in (UNPACK_CORRUPTED, UNPACK_NOT_INSTALLED):
        return EXIT_UNPACK
    if not urls:
        return EXIT_NO_URL
    if status in (COMPLETED, NEEDS_REVIEW) and ust == UNPACK_UNSUPPORTED:
        return EXIT_OK if urls else EXIT_NO_URL
    return EXIT_OK
