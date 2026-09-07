"""URL 产物（urls_by_rank.txt / 控制台行）的来源标注 · 行为锁定测试。

覆盖：
- 来源 tag/图例拼装（source_tag / format_sources / render_url_line）
- build_source_index 双索引（原文 + 合并键）能命中 http/https 折叠后的取值
- write_url_files 产物：非 `#` 开头的行都是 URL（可直接 grep 抽取）
- 老调用方不传 indicators 时来源列退化成 unknown，不报错
- 「判定通过即等价」：加来源标注不得改变 rank

依赖 androguard（经 analyze 局部 import），与项目其余 extraction 测试一致。
"""
from __future__ import annotations

from pathlib import Path

from auto_unpack.extraction.analyze import (
    build_source_index,
    format_url_line,
    write_url_files,
)
from auto_unpack.extraction.indicators import (
    display_width,
    format_sources,
    merge_indicators,
    render_url_line,
    source_tag,
    url_rank,
)


# ---------------------------------------------------------------------------
# 来源 tag 拼装
# ---------------------------------------------------------------------------
def test_source_tag_with_file():
    s = {"type": "dex", "method": "string_pool", "file": "classes.dex"}
    assert source_tag(s) == "dex/string_pool@classes.dex"


def test_source_tag_strips_dir_keeps_basename():
    # 产物不得带出本机目录：只保留文件名
    s = {"type": "assets", "method": "harvest", "file": "assets/apps/x/config.json"}
    assert source_tag(s) == "assets/harvest@config.json"


def test_source_tag_unknown_on_empty():
    assert source_tag(None) == "unknown/-"
    assert source_tag({}) == "unknown/-"


def test_format_sources_dedup_and_join():
    srcs = [
        {"type": "dex", "method": "string_pool", "file": "classes.dex"},
        {"type": "dex", "method": "string_pool", "file": "classes.dex"},  # 重复
        {"type": "binary", "method": "binary", "file": "apk"},
    ]
    assert format_sources(srcs) == "dex/string_pool@classes.dex, binary/binary@apk"


def test_format_sources_unknown_when_missing():
    assert format_sources(None) == "unknown"
    assert format_sources([]) == "unknown"


def test_format_sources_pushes_binary_last():
    """binary/* 是全包兜底，信息量最低，排最后（截断时优先被丢）。"""
    srcs = [
        {"type": "binary", "method": "binary", "file": "apk"},
        {"type": "assets", "method": "harvest", "file": "a.json"},
    ]
    assert format_sources(srcs).startswith("assets/harvest@a.json")


def test_format_sources_folds_overflow_with_plus_n():
    srcs = [
        {"type": "dex", "method": "string_pool", "file": f"classes{i}.dex"}
        for i in range(5)
    ]
    out = format_sources(srcs, limit=3)
    assert out.endswith(", +2")


def test_render_url_line_pads_to_width():
    line = render_url_line("http://a.cn/x", [{"type": "dex", "method": "string_pool",
                                              "file": "classes.dex"}],
                           width=30)
    url, _, tail = line.partition("· ")
    assert url.rstrip() == "http://a.cn/x"
    assert tail == "dex/string_pool@classes.dex"
    # 12 字符的 URL 补到 width=30，再加 gap=2
    assert len(url) == 32


def test_render_url_line_fixed_gap_without_width():
    line = render_url_line("http://a.cn/x", None, width=0)
    assert line == "http://a.cn/x  · unknown"


def test_render_url_line_aligns_by_display_width_not_char_count():
    """URL 尾巴偶有全角粘连（P3 遗留，如 `...guidelines)。`）。

    全角字符在终端占 2 列，按字符数补空格会让该行来源列整列右移，
    故 padding 必须按显示宽度算。
    """
    srcs = [{"type": "dex", "method": "string_pool", "file": "c.dex"}]
    plain = "https://a.cn/x"                    # 纯 ASCII
    wide = "https://Coze.net/ads/guidelines)。"  # 含全角括号
    assert len(plain) != len(wide)
    w = 40
    assert display_width(wide) == len(wide) + 1  # 全角括号多占 1 列

    def bullet_col(u: str) -> int:
        line = render_url_line(u, srcs, width=w)
        return display_width(line.partition("· ")[0])

    assert bullet_col(plain) == w + 2
    assert bullet_col(wide) == w + 2  # 与纯 ASCII 行同一列，不错位


# ---------------------------------------------------------------------------
# build_source_index
# ---------------------------------------------------------------------------
def test_source_index_hit_by_exact_url():
    items = [{"url": "https://a.cn/api", "sources": [
        {"type": "dex", "method": "string_pool", "file": "classes.dex"}]}]
    idx = build_source_index(items)
    assert _tags(idx["https://a.cn/api"]) == ["dex/string_pool@classes.dex"]


def test_source_index_merges_sources_of_http_https_variants():
    """http/https 两种形态经 merge_indicators 合并后，两条来源要都留在同一条 URL 下。

    注意：merge_indicators 保留 https 形态作为展示串，而索引只按 URL 原文建，
    所以这里断言的是「合并后产物取值」与「索引键」一致——若将来改成保留 http，
    这条测试会红，用于暴露取值漂移。
    """
    merged = merge_indicators([
        {"url": "http://a.cn/api", "canonical": "http://a.cn/api",
         "sources": [{"type": "dex", "method": "string_pool", "file": "c1.dex"}]},
        {"url": "https://a.cn/api", "canonical": "https://a.cn/api",
         "sources": [{"type": "assets", "method": "harvest", "file": "cfg.json"}]},
    ])
    assert len(merged) == 1
    idx = build_source_index(merged)
    kept = merged[0]["url"]
    assert kept == "https://a.cn/api"
    assert len(idx[kept]) == 2
    # 索引层保插入序，不做排序；排序是渲染层 format_sources 的职责
    assert _tags(idx[kept]) == ["dex/string_pool@c1.dex", "assets/harvest@cfg.json"]
    # 渲染时才按「具体来源优先、binary 兜底最后」重排
    assert format_sources(idx[kept]) == (
        "assets/harvest@cfg.json, dex/string_pool@c1.dex")


def test_source_index_dedup_same_signature():
    items = [
        {"url": "https://a.cn/api",
         "sources": [{"type": "dex", "method": "string_pool", "file": "c1.dex"}]},
        {"url": "https://a.cn/api",
         "sources": [{"type": "dex", "method": "string_pool", "file": "c1.dex"}]},
    ]
    idx = build_source_index(items)
    assert len(idx["https://a.cn/api"]) == 1


# ---------------------------------------------------------------------------
# write_url_files 产物格式
# ---------------------------------------------------------------------------
_BIZ = "https://api.mrwqfy.cn/mobile/index.php"
# 裸 IP 无路径无特殊端口 → weak；weak_worth_listing 对 IP 放行，会写进文件
_WEAK = "https://111.170.7.97"
_NOISE = "https://google.golang.org/protobuf"
# weak 但无路径、非 IP、非 api 前缀 → weak_worth_listing 为假，不写进文件
_BARE = "https://img.brandcdn.com"


def _items_with_sources():
    return [
        {"url": _BIZ, "sources": [
            {"type": "dex", "method": "string_pool", "file": "classes.dex"}]},
        {"url": _WEAK, "sources": [
            {"type": "dex", "method": "decoded", "file": "classes2.dex"}]},
        {"url": _NOISE, "sources": [
            {"type": "dex", "method": "string_pool", "file": "classes.dex"}]},
        {"url": _BARE, "sources": [
            {"type": "manifest", "method": "regex", "file": "AndroidManifest.xml"}]},
    ]


def test_write_url_files_annotates_source(tmp_path: Path):
    items = _items_with_sources()
    urls = {i["url"] for i in items}
    write_url_files(tmp_path, urls, {"/api/token"}, items)
    text = (tmp_path / "urls_by_rank.txt").read_text(encoding="utf-8")

    assert f"{_BIZ}" in text
    assert "dex/string_pool@classes.dex" in text
    assert "dex/decoded@classes2.dex" in text
    # noise / 裸域名 weak 不进文件
    assert _NOISE not in text
    assert _BARE not in text


def test_write_url_files_non_comment_lines_are_urls(tmp_path: Path):
    """文件约定：不以 # 开头的行 = URL，可直接 grep 抽取。"""
    items = _items_with_sources()
    write_url_files(tmp_path, {i["url"] for i in items}, set(), items)
    body = [ln for ln in (tmp_path / "urls_by_rank.txt").read_text(
        encoding="utf-8").splitlines() if ln.strip()]
    urls = [ln for ln in body if not ln.startswith("#")]
    assert urls
    for ln in urls:
        assert ln.split()[0].startswith(("http://", "https://", "ws://", "wss://"))


def test_write_url_files_header_reports_counts_and_legend(tmp_path: Path):
    items = _items_with_sources()
    write_url_files(tmp_path, {i["url"] for i in items}, {"/a", "/b"}, items)
    head_text = (tmp_path / "urls_by_rank.txt").read_text(encoding="utf-8")
    assert "biz 1" in head_text
    assert "weak 1" in head_text
    assert "noise 1" in head_text
    assert "端点路径 2" in head_text
    assert "来源类型>/<提取方式>@<文件>" in head_text
    assert "dex/string_pool" in head_text


def test_write_url_files_missing_sections_say_none(tmp_path: Path):
    write_url_files(tmp_path, set(), set(), None)
    text = (tmp_path / "urls_by_rank.txt").read_text(encoding="utf-8")
    assert "# （无）" in text


def test_write_url_files_without_indicators_still_works(tmp_path: Path):
    """老调用方不传 indicators：来源列退化成 unknown，不得报错。"""
    items = _items_with_sources()
    write_url_files(tmp_path, {i["url"] for i in items}, set())
    text = (tmp_path / "urls_by_rank.txt").read_text(encoding="utf-8")
    assert _BIZ in text
    assert "unknown" in text


def test_write_url_files_clears_legacy_files(tmp_path: Path):
    (tmp_path / "urls.txt").write_text("old", encoding="utf-8")
    write_url_files(tmp_path, {_BIZ}, set())
    assert not (tmp_path / "urls.txt").exists()


# ---------------------------------------------------------------------------
# 「判定通过即等价」原则：来源标注不得改变 rank
# ---------------------------------------------------------------------------
def test_source_annotation_does_not_change_rank():
    for u in (_BIZ, _WEAK, _NOISE):
        plain = url_rank(u)
        annotated = render_url_line(u, [
            {"type": "dex", "method": "decoded", "file": "classes.dex"}])
        assert url_rank(annotated.split()[0]) == plain


def test_decoded_url_is_not_downgraded():
    """base64 解码产出的 URL 走同一套判定器，不得因来源被降级。"""
    u = "https://api.mrwqfy.cn/v1/token"
    assert url_rank(u) == "biz"
    line = format_url_line(u, [{"type": "dex", "method": "decoded",
                                "file": "classes.dex"}])
    assert line.startswith(u)
    assert "dex/decoded@classes.dex" in line


# ---------------------------------------------------------------------------
def _tags(srcs: list[dict]) -> list[str]:
    return [source_tag(s) for s in srcs]
