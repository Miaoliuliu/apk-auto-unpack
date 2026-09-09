"""脱壳后二次提取 · 行为锁定测试。

锁定两件事：
1. extract_apk_non_dex_sources 覆盖原 APK 里 dex 字符串池之外的来源
   （assets 文本 / resources.arsc / native .so / AndroidManifest），
   其中 arsc + manifest 是脱壳成功路径此前漏掉的两路。
2. analyze_dumped_dexes 已接线到完整补扫（而非仅 assets + so）。

构造合成 zip 样本（不依赖真机/androguard 解析真实 arsc/axml，只靠字节正则抠 URL），
离线可跑：与 test_packer_sigs 同环境。
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from auto_unpack.extraction.analyze import extract_apk_non_dex_sources
from auto_unpack.unpacker.validate import analyze_dumped_dexes


def test_parse_zip_dexes_does_not_read_whole_apk(monkeypatch, tmp_path: Path):
    from auto_unpack.dex_utils import parse_dexes

    apk = tmp_path / "empty.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")

    def fail_read_bytes(self):
        raise AssertionError(f"unexpected whole-file read: {self}")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)
    assert parse_dexes(str(apk)) == []


def test_parse_zip_dexes_blocks_extreme_compression_ratio(tmp_path: Path):
    from auto_unpack.dex_utils import parse_dexes

    apk = tmp_path / "bomb.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", b"\0" * (1024 * 1024))

    stats: dict = {}
    assert parse_dexes(str(apk), stats=stats) == []
    assert any(
        row.get("reason") == "compression_ratio_exceeded"
        for row in stats.get("source_skipped", [])
    )


def _hosts(items) -> set[str]:
    return {it.get("host") for it in items if it.get("host")}


def _build_apk(tmp_path):
    """合成 APK：四种来源各放一个可辨识 URL。

    域名用非噪音 TLD 前缀，host 段唯一，便于逐路断言。
    """
    arsc = b"\x00" * 16 + b"https://arsc.unpacktest7.com/v1/check"
    axml = b"<manifest>https://mfest.unpacktest7.com/x</manifest>"
    so = b"\x90" * 100 + b"https://sourc.so-mark.com/native/api" + b"\x00"
    assets_js = b"const base = 'https://web.assetjs.com/a/b'; fetch(base)"
    p = tmp_path / "fake.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("resources.arsc", arsc)
        z.writestr("AndroidManifest.xml", axml)
        z.writestr("lib/arm64-v8a/libfake.so", so)
        z.writestr("assets/www/app.js", assets_js)
    return p


def test_non_dex_sources_covers_arsc_manifest_native_assets(tmp_path):
    apk = _build_apk(tmp_path)
    items, _endpoints = extract_apk_non_dex_sources(str(apk))
    hosts = _hosts(items)
    assert "arsc.unpacktest7.com" in hosts, f"arsc 来源缺失: {sorted(hosts)}"
    assert "mfest.unpacktest7.com" in hosts, f"manifest 来源缺失: {sorted(hosts)}"
    assert "sourc.so-mark.com" in hosts, f"native .so 来源缺失: {sorted(hosts)}"
    assert "web.assetjs.com" in hosts, f"assets 来源缺失: {sorted(hosts)}"


def test_analyze_dumped_dexes_wires_full_complement(tmp_path):
    """脱壳产物补扫已接入完整来源（空 dex 列表也走补扫）。"""
    apk = _build_apk(tmp_path)
    _endpoints, _rows, _quality, items = analyze_dumped_dexes([], str(apk))
    hosts = _hosts(items)
    # 此前只有 assets + so 会被补到；arsc 是本次加固新增的覆盖来源
    assert "arsc.unpacktest7.com" in hosts, f"arsc 未补扫: {sorted(hosts)}"
    assert "mfest.unpacktest7.com" in hosts, f"manifest 未补扫: {sorted(hosts)}"


def test_deep_coverage_does_not_depend_on_previous_url_hit(tmp_path):
    apk = tmp_path / "coverage.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/visible.txt", "https://api.visible-sample.net/api/seen")
        z.writestr("assets/configblob", "https://api.hidden-sample.net/api/found")
        z.writestr(
            "assets/chunk-vendors.js",
            "https://api.skipped-sample.net/api/found",
        )
    items, _ = extract_apk_non_dex_sources(str(apk))
    assert _hosts(items) >= {
        "api.visible-sample.net",
        "api.hidden-sample.net",
        "api.skipped-sample.net",
    }
