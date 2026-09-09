"""extraction/report.py + analyze.py 编排层 · 行为锁定测试。

覆盖：
- P2-⑤ warning 联动：空结果但有 encrypted_config/runtime_h5 时 status=needs_review
- P1-④ 静默异常统计：畸形 dex 触发 stats 收集，不再无声变空

analyze 层测试依赖 androguard（局部 import），report 层纯 stdlib。
"""
from __future__ import annotations

import struct
from types import SimpleNamespace

from auto_unpack.extraction import report as rp


# ---------------------------------------------------------------------------
# _project_urls：extraction.status 四态（failed / empty / needs_review / ok）
# ---------------------------------------------------------------------------
def test_extraction_status_needs_review_on_runtime_h5():
    task = SimpleNamespace(
        urls=[], error=None,
        warnings=["runtime_h5: uni-app 运行时拼 URL，静态可能漏报"],
    )
    _, _, status = rp._project_urls(task)
    assert status == "needs_review"


def test_extraction_status_needs_review_on_encrypted_config():
    task = SimpleNamespace(
        urls=[], error=None,
        warnings=["encrypted_config: assets 配置像密文，静态抽空不等于有壳"],
    )
    _, _, status = rp._project_urls(task)
    assert status == "needs_review"


def test_extraction_status_empty_without_warning():
    task = SimpleNamespace(urls=[], error=None, warnings=[])
    _, _, status = rp._project_urls(task)
    assert status == "empty"


def test_extraction_status_partial_when_result_has_runtime_warning():
    task = SimpleNamespace(
        urls=[{"value": "https://api.myservice.com", "type": "url",
               "rank": "biz", "host": "api.myservice.com",
               "canonical": "https://api.myservice.com",
               "source_kind": "dex", "sources": []}],
        error=None,
        warnings=["runtime_h5: uni-app 运行时拼 URL"],
    )
    _, _, status = rp._project_urls(task)
    assert status == "partial"


def test_project_url_separates_business_likelihood_from_validation():
    item = {
        "value": "https://api.myservice.com",
        "type": "url",
        "rank": "biz",
        "business_likelihood": 0.9,
        "validation": {"syntax": "valid", "dns": "unresolved", "http": "not_checked"},
        "sources": [],
    }
    projected = rp.project_url(item)
    assert "confidence" not in projected
    assert projected["business_likelihood"] == 0.9
    assert projected["validation"]["dns"] == "unresolved"


# ---------------------------------------------------------------------------
# extract_indicators：stats 收集（P1-④ 静默异常显性化）
# ---------------------------------------------------------------------------
def test_extract_indicators_stats_malformed_dex(tmp_path):
    """畸形裸 dex（id 段越界）进 stats.malformed_dex，结果为空但不再无声。"""
    from auto_unpack.extraction import analyze as az

    p = tmp_path / "bad.dex"
    b = bytearray(0x70)
    b[:4] = b"dex\n"
    struct.pack_into("<I", b, 0x38, 0xFFFFFFFF)  # string_ids_size 声明巨大
    struct.pack_into("<I", b, 0x3C, 0x70)        # string_ids_off
    p.write_bytes(bytes(b))

    stats: dict = {}
    items, eps = az.extract_indicators(str(p), stats=stats)
    assert items == []
    assert eps == set()
    assert stats.get("malformed_dex") == [p.name]
