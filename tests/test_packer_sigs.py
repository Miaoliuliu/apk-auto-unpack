"""壳识别核心判定函数 · 行为锁定测试（Characterization Tests）。

目的：不是证明"判定正确"，而是锁定"当前行为"——任何重构/阈值调整
导致行为变化时，测试立即变红，提示人工确认。

断言值来源：
  - 真实样本实测（packer_detection/ 归档库 + APKiD 交叉验证结论）
  - 源码判定链逐分支推导（suggest_route 短路顺序）

不依赖 androguard（dex_utils 顶层仅 stdlib），离线可跑：
    C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe -m pytest tests/ -v
"""
from __future__ import annotations

import pytest

from auto_unpack.packer import packer_sigs as ps


# ---------------------------------------------------------------------------
# suggest_route：分流决策链（短路顺序：paid/vmp → manual → dpt → unknown → vendor → static）
# ---------------------------------------------------------------------------
def test_route_manual_when_paid_edition():
    sig = {"edition": "paid", "vmp": False, "dpt_shell": False,
           "dpt_type": None, "custom_family": None, "matched": [],
           "dex_stub": False, "dex_classes": [5000]}
    assert ps.suggest_route(sig) == "manual"


def test_route_manual_when_vmp():
    sig = {"edition": None, "vmp": True, "dpt_shell": False,
           "dpt_type": None, "custom_family": None, "matched": [],
           "dex_stub": False, "dex_classes": [5000]}
    assert ps.suggest_route(sig) == "manual"


def test_route_dpt_standard():
    sig = {"edition": None, "vmp": False, "dpt_shell": True,
           "dpt_type": "standard", "custom_family": None, "matched": [],
           "dex_stub": True, "dex_classes": [1]}
    assert ps.suggest_route(sig) == "dpt"


def test_route_dpt_modified():
    """DUokHB.apk 实测：native 符号命中 dpt modified，走 dpt 脱壳。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": True,
           "dpt_type": "modified", "custom_family": None, "matched": [],
           "dex_stub": True, "dex_classes": [1]}
    assert ps.suggest_route(sig) == "dpt"


def test_route_dpt_appended():
    sig = {"edition": None, "vmp": False, "dpt_shell": True,
           "dpt_type": "appended", "custom_family": None, "matched": [],
           "dex_stub": True, "dex_classes": [1]}
    assert ps.suggest_route(sig) == "dpt"


def test_route_dpt_suspected():
    """suspected 是弱证据，但当前行为仍判 dpt（源码 L700 分支）。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": True,
           "dpt_type": "suspected", "custom_family": None, "matched": [],
           "dex_stub": True, "dex_classes": [1]}
    assert ps.suggest_route(sig) == "dpt"


def test_route_unknown_custom_family():
    """JDog/packhub 自研保护：优先于厂商特征，转人工。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": False,
           "dpt_type": None, "custom_family": "jdog_native_dex_loader",
           "matched": [], "dex_stub": False, "dex_classes": [2000]}
    assert ps.suggest_route(sig) == "unknown"


def test_route_vendor_when_matched():
    """360 加固实测：libjiagu 特征命中 → vendor。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": False,
           "dpt_type": None, "custom_family": None,
           "matched": [{"vendor": "360加固", "key": "qihoo360"}],
           "dex_stub": False, "dex_classes": [3000]}
    assert ps.suggest_route(sig) == "vendor"


def test_route_static_business_dex():
    """无壳业务包：类数足够 → static 直接提取 URL。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": False,
           "dpt_type": None, "custom_family": None, "matched": [],
           "dex_stub": False, "dex_classes": [5000]}
    assert ps.suggest_route(sig) == "static"


def test_route_unknown_stub_dex_only():
    """根 dex stub 且无厂商/dpt 特征：兜底转人工，不抽 URL。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": False,
           "dpt_type": None, "custom_family": None, "matched": [],
           "dex_stub": True, "dex_classes": [1]}
    assert ps.suggest_route(sig) == "unknown"


def test_route_static_fallback():
    """空 sig 兜底 static（无任何证据时不当壳处理）。"""
    assert ps.suggest_route({}) == "static"


# ---------------------------------------------------------------------------
# has_payload_dex / dex_unreadable / class_shortfall：业务 dex 判定
# ---------------------------------------------------------------------------
def test_has_payload_dex_true():
    assert ps.has_payload_dex({"dex_stub": False, "dex_classes": [5000]}) is True


def test_has_payload_dex_false_when_stub():
    assert ps.has_payload_dex({"dex_stub": True, "dex_classes": [5000]}) is False


def test_has_payload_dex_false_few_classes():
    assert ps.has_payload_dex({"dex_stub": False, "dex_classes": [1]}) is False


def test_dex_unreadable_encrypted():
    """ZIP 加密 dex 且解不出类：对抗信号，不是无壳。"""
    sig = {"dex_classes": [], "zip_encrypted_dex_count": 1,
           "zip_encrypted_dex": ["classes.dex"], "dex_stub": False}
    assert ps.dex_unreadable(sig) is True


def test_dex_unreadable_stub():
    assert ps.dex_unreadable({"dex_classes": [], "dex_stub": True}) is True


def test_dex_unreadable_false_business():
    assert ps.dex_unreadable({"dex_classes": [5000], "dex_stub": False}) is False


def test_class_shortfall_big_apk_few_classes():
    assert ps.class_shortfall([100], 30.0) is True


def test_class_shortfall_small_apk():
    assert ps.class_shortfall([100], 5.0) is False


def test_class_shortfall_zero_classes():
    """0 类不算 shortfall（解析失败走 stub_like 那条路）。"""
    assert ps.class_shortfall([0], 30.0) is False


def test_class_shortfall_full_business():
    assert ps.class_shortfall([5000], 30.0) is False


# ---------------------------------------------------------------------------
# _stub_like：根 dex stub 判定
# ---------------------------------------------------------------------------
def test_stub_like_explicit_stub():
    assert ps._stub_like({"stub": True, "dex": []}) is True


def test_stub_like_no_dex():
    assert ps._stub_like({"stub": False, "dex": []}) is True


def test_stub_like_tiny_root_dex():
    """根 dex 类数 < 50 且总类数 < 1000 → stub 样。"""
    dex_info = {"stub": False, "dex": [{"name": "classes.dex", "classes": 10}]}
    assert ps._stub_like(dex_info) is True


def test_stub_like_full_business():
    dex_info = {"stub": False, "dex": [{"name": "classes.dex", "classes": 5000}]}
    assert ps._stub_like(dex_info) is False


# ---------------------------------------------------------------------------
# _judge_dpt：dpt 系判定（返回 dpt_shell, dpt_type, evidence, generation）
# ---------------------------------------------------------------------------
def _mk_signals(**over):
    """构造 _judge_dpt 输入：默认全空，按测试覆盖所需键。"""
    signals = {
        "feats": {
            "dpt_primary_files": [],
            "dpt_shell_files": [],
            "asset_payloads": [],
            "application": None,
            "appcomponentfactory": False,
        },
        "dex_info": {"stub": False, "dex": [{"name": "classes.dex", "classes": 5000}]},
        "so_content": {"dpt_shell_so": []},
        "hidden_dex": [],
        "appended_zip": None,
        "malformed_manifest": False,
        "random_libs": [],
        "hex_packer_pairs": [],
        "fake_dex_decoys": [],
        "generation": 1,
    }
    signals.update(over)
    return signals


def test_judge_dpt_standard():
    """标准版：assets 特征文件 i11111i111.zip。"""
    sig = _mk_signals(feats={
        "dpt_primary_files": ["i11111i111.zip"],
        "dpt_shell_files": ["i11111i111.zip"],
        "asset_payloads": [], "application": None, "appcomponentfactory": False,
    })
    dpt_shell, dpt_type, evidence, gen = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "standard"
    assert "i11111i111.zip" in " ".join(evidence)


def test_judge_dpt_modified_native_symbol():
    """魔改版：native 符号命中（DUokHB 实测路径）。"""
    sig = _mk_signals(so_content={
        "dpt_shell_so": ["lib/armeabi-v7a/libajdkRhPKMfcNoss.so"],
    })
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "modified"
    assert "libajdkRhPKMfcNoss.so" in " ".join(evidence)


def test_judge_dpt_appended_zip():
    """内嵌 ZIP：classes.dex 尾部接 ZIP（dpt-unpack 机制）。"""
    sig = _mk_signals(appended_zip={"offset": 100, "zip_len": 512, "endian": "little"})
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "appended"


def test_judge_dpt_modified_java_stub():
    """Java stub 类名（luoyesiqiu 是 dpt-shell 作者）。"""
    sig = _mk_signals(feats={
        "dpt_primary_files": [], "dpt_shell_files": [],
        "asset_payloads": [], "application": "com.luoyesiqiu.shell.ProxyApplication",
        "appcomponentfactory": False,
    })
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "modified"
    assert "stub:com.luoyesiqiu.shell.ProxyApplication" in evidence


def test_judge_dpt_suspected_factory_stub_assets():
    """去符号疑似：appComponentFactory + stub + assets 大块。"""
    sig = _mk_signals(
        feats={
            "dpt_primary_files": [], "dpt_shell_files": [],
            "asset_payloads": ["assets/tmnbdwt/ctpseh"],
            "application": None, "appcomponentfactory": True,
        },
        dex_info={"stub": True, "dex": [{"name": "classes.dex", "classes": 1}]},
    )
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "suspected"


def test_judge_dpt_none_no_evidence():
    """无任何 dpt 证据 → 不判 dpt。"""
    dpt_shell, dpt_type, _, _ = ps._judge_dpt(_mk_signals())
    assert dpt_shell is False
    assert dpt_type is None


# ---------------------------------------------------------------------------
# _is_dpt_native：so 内容符号判定
# ---------------------------------------------------------------------------
def test_is_dpt_native_required_pair():
    data = b"xxx readAppComponentFactoryName yyy AppComponentFactory zzz"
    assert ps._is_dpt_native(data) is True


def test_is_dpt_native_single_string_false():
    assert ps._is_dpt_native(b"only AppComponentFactory here") is False


def test_is_dpt_native_empty_false():
    assert ps._is_dpt_native(b"") is False


# ---------------------------------------------------------------------------
# _looks_random_lib：随机名自定义库判定（实测校准）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,expected", [
    ("lib39285EFA.so", True),                # 纯大写+数字 8 位（强指纹）
    ("libGTlNLCpFsvbV.so", True),            # 大写 run>=4 且长度>=10（DUokHB 型）
    ("libverfjhivriufbhig.vrjkhfuvbirfgg.so", True),  # 点号假版本随机名
    ("libUVCCamera.so", False),              # allowlist 防误伤
    ("libreactnative.so", False),            # 无大写 run
    ("libNERtcAudio3D.so", False),           # camelCase+数字（正常 SDK）
    ("libGLESv2.so", False),                 # 长度不足
    ("libImSDK.so", False),                  # 短缩写
])
def test_looks_random_lib(name, expected):
    assert ps._looks_random_lib(name) is expected


# ---------------------------------------------------------------------------
# _find_hex_packer_pairs：8 位 hex 成对指纹（字幕网/绘本型）
# ---------------------------------------------------------------------------
def test_hex_packer_pairs_hit():
    hits = ps._find_hex_packer_pairs(
        {"lib39285EFA.so"}, {"39285EFA.dex"},
    )
    assert hits == ["lib39285EFA.so+39285EFA.dex"]


def test_hex_packer_pairs_no_dex_side():
    """只有随机 so 无配对 assets（绘本 lib39285EFA.so 场景）：不成对。"""
    assert ps._find_hex_packer_pairs({"lib39285EFA.so"}, set()) == []


def test_hex_packer_pairs_wrong_ext():
    assert ps._find_hex_packer_pairs(
        {"lib39285EFA.so"}, {"39285EFA.png"},
    ) == []
