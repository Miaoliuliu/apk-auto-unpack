"""产物目录命名：safe_product_stem / detect_folder_name / sanitize_filename 行为锁定。"""
from __future__ import annotations

from auto_unpack.runtime.product import (
    detect_folder_name,
    safe_product_stem,
    sanitize_filename,
)


# ---------------------------------------------------------------------------
# safe_product_stem：原文件名优先，包名 / hash 仅兜底
# ---------------------------------------------------------------------------
def test_stem_plain_name():
    assert safe_product_stem("D:/APK/Hey.apk") == "Hey"


def test_stem_keeps_fullwidth_and_symbols():
    """全角问号 / 货币符号保留原名，不做可读性过滤。"""
    assert safe_product_stem("D:/APK/3？？D？？.apk") == "3？？D？？"
    assert safe_product_stem("D:/APK/钱包¥.apk") == "钱包¥"


def test_stem_single_fullwidth_char():
    assert safe_product_stem("D:/APK/？.apk") == "？"


def test_stem_underscore_only_falls_back_to_original():
    """纯下划线 sanitize 后为空：退回原 stem（而非降级成包名/hash）。"""
    assert safe_product_stem("D:/APK/__.apk") == "__"


def test_stem_dot_prefix_chinese_keeps_readable_part():
    """点开头中文名：strip 首尾点后保留可读部分。"""
    assert safe_product_stem("D:/APK/.企音通..apk") == "企音通"


def test_stem_pure_dots_hash_fallback():
    """纯点文件名 sanitize 后为空且无回退：落到 apk_<hash> 兜底。"""
    stem = safe_product_stem("D:/APK/....apk")
    assert stem.startswith("apk_")
    assert len(stem) == len("apk_") + 12


def test_stem_package_when_no_path():
    assert safe_product_stem(None, "com.example.app", True) == "com_example_app"


def test_stem_untrusted_package_still_used():
    """无路径时，即使包名不可信也用于命名（当前行为）。"""
    assert safe_product_stem(None, "com.example.app", False) == "com_example_app"


def test_stem_nothing():
    assert safe_product_stem(None) == "unpack"


# ---------------------------------------------------------------------------
# detect_folder_name：壳名 → 归档子目录
# ---------------------------------------------------------------------------
def test_folder_dpt():
    assert detect_folder_name("dpt-shell") == "dpt-shell"


def test_folder_custom_protection():
    assert detect_folder_name("packhub_shell") == "自研保护"
    assert detect_folder_name("jdog") == "自研保护"
    assert detect_folder_name("未知壳") == "自研保护"
    assert detect_folder_name("unknown") == "自研保护"


def test_folder_no_packer():
    assert detect_folder_name(None) == "无壳"
    assert detect_folder_name("none") == "无壳"


def test_folder_vendor():
    assert detect_folder_name("360加固") == "360加固"


# ---------------------------------------------------------------------------
# sanitize_filename：Windows 非法字符清理
# ---------------------------------------------------------------------------
def test_sanitize_replaces_bad_chars():
    assert sanitize_filename('a<b>c:d"e/f\\g|h?i*j') == "a_b_c_d_e_f_g_h_i_j"


def test_sanitize_trims_spaces_and_dots():
    assert sanitize_filename("  spaces  ") == "spaces"


def test_sanitize_underscore_only_becomes_empty():
    assert sanitize_filename("__") == ""


def test_sanitize_empty():
    assert sanitize_filename("") == ""
