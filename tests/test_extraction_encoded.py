"""编码还原（盲解 base64/hex → URL 判定器）· 行为锁定测试。

decode-then-validate：不「识别混淆」，把像编码的长 token 盲解后交给
URL 正则 + 域名合法性 + 噪音表判定。锁死三个性质：
1. 标准/去 padding/urlsafe base64 与 hex 编码的 URL 能被还原
2. 解码出非 URL 文本（普通字符串、类路径）不得误报
3. 明文 URL 不重复处理
"""
from __future__ import annotations

import base64

from auto_unpack.extraction.indicators import (
    _decode_b64_variants,
    _decode_hex_variants,
    _harvest_encoded,
)

_B64 = "https://api.samplegray.cn/v1/pull?cmd=list"
_HEX = "https://hex.samplegray.cn/x"


def _urls_from(s: str) -> set[str]:
    urls: set[str] = set()
    endpoints: set[str] = set()
    _harvest_encoded(s, urls, endpoints)
    return urls


def _b64(s: str, padding: bool = True) -> str:
    enc = base64.b64encode(s.encode()).decode()
    return enc if padding else enc.rstrip("=")


def test_harvest_standard_base64_padded():
    assert _b64(_B64) in _urls_from(_b64(_B64)) or any(
        _B64.startswith(u.split("/")[0] + "/") or _B64 in u for u in _urls_from(_b64(_B64))
    )


def test_decode_b64_variants_standard():
    out = _decode_b64_variants(_b64(_B64))
    assert _B64 in out


def test_decode_b64_variants_no_padding():
    out = _decode_b64_variants(_b64(_B64, padding=False))
    assert _B64 in out


def test_decode_b64_variants_urlsafe():
    raw = _b64(_HEX).replace("+", "-").replace("/", "_")
    out = _decode_b64_variants(raw)
    assert _HEX in out


def test_decode_hex_variants_url():
    out = _decode_hex_variants(_HEX.encode().hex())
    assert _HEX in out


def test_decode_hex_variants_garbage_not_texty():
    assert _decode_hex_variants("ff" * 40) == []


def test_decode_hex_variants_odd_length():
    assert _decode_hex_variants("abc") == []


def test_harvest_plain_text_no_url_no_false_positive():
    """base64 解出普通文本（hello world），没有 URL → 不产出。"""
    urls = _urls_from(_b64("hello world this is just a greeting message"))
    assert urls == set()


def test_harvest_class_path_no_false_positive():
    """类路径/描述符可能含 base64 字符集，但解不出 URL → 不产出。"""
    s = "Lcom/example/protected/internal/SecurityManagerImpl"
    assert _urls_from(s) == set()


def test_harvest_plaintext_url_skipped():
    """含 :// 的明文已由 _iter_urls 处理，编码还原不重复。"""
    assert _urls_from("https://plain.samplegray.cn/a") == set()


def test_harvest_short_string_skipped():
    assert _urls_from("abc") == set()


def test_harvest_hex_url_recovered():
    assert any("hex.samplegray.cn" in u for u in _urls_from(_HEX.encode().hex()))
