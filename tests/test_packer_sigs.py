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

from auto_unpack.packer import apkid
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


def test_route_parse_failure_is_not_static():
    sig = {
        "matched": [], "vendor_candidates": [], "dex_stub": False,
        "dex_classes": [], "dex_status": "failed",
        "dex_parse_failed": [("classes.dex", "bad header")],
    }
    assert ps.suggest_route(sig) == "unknown"


def test_route_partial_dex_is_not_static():
    sig = {
        "matched": [], "vendor_candidates": [], "dex_stub": False,
        "dex_classes": [3000], "dex_status": "partial",
    }
    assert ps.suggest_route(sig) == "unknown"


def test_route_weak_vendor_candidate_is_not_static():
    sig = {
        "matched": [], "vendor_candidates": [{"key": "ijiami"}],
        "dex_stub": False, "dex_classes": [3000], "dex_status": "ok",
    }
    assert ps.suggest_route(sig) == "unknown"


def test_route_multiple_vendors_is_ambiguous():
    sig = {
        "matched": [{"key": "qihoo360"}, {"key": "legu"}],
        "dex_stub": False, "dex_classes": [3000], "dex_status": "ok",
    }
    assert ps.suggest_route(sig) == "ambiguous"


def test_apkid_vendor_is_not_static():
    sig = {
        "matched": [], "vendor_candidates": [], "apkid_packers": ["360 Jiagu"],
        "dex_stub": False, "dex_classes": [2000], "dex_status": "ok",
    }
    assert ps.suggest_route(sig) == "vendor"


# ---------------------------------------------------------------------------
# has_payload_dex / dex_unreadable / class_shortfall：业务 dex 判定
# ---------------------------------------------------------------------------
def test_has_payload_dex_true():
    assert ps.has_payload_dex({"dex_stub": False, "dex_classes": [5000]}) is True


def test_small_valid_dex_is_not_strong_stub():
    info = {
        "dex": [{"name": "classes.dex", "classes": 10}],
        "stub": False, "encrypted_dex": [], "parse_failed": [],
    }
    # The size heuristic remains available through _stub_like, but is not
    # exported as a definitive dex_stub signal.
    assert ps._stub_like(info) is True


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
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
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
    dpt_shell, dpt_type, _, _ = ps._judge_dpt(sig)
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
    dpt_shell, dpt_type, _, _ = ps._judge_dpt(sig)
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


# ---------------------------------------------------------------------------
# _is_jdog_native_loader：JDog native loader 符号判定
# ---------------------------------------------------------------------------
def test_is_jdog_native_loader_hit():
    data = b"com/jdog/JLibrary ... __LoadDexLow ..."
    assert ps._is_jdog_native_loader(data) is True


def test_is_jdog_native_loader_no_marker():
    assert ps._is_jdog_native_loader(b"com/jdog/JLibrary only") is False


def test_is_jdog_native_loader_empty():
    assert ps._is_jdog_native_loader(b"") is False


# ---------------------------------------------------------------------------
# _dpt_app_stub：dpt stub application 判定
# ---------------------------------------------------------------------------
def test_dpt_app_stub_hit():
    assert ps._dpt_app_stub("com.luoyesiqiu.shell.ProxyApplication") is True


def test_dpt_app_stub_miss():
    assert ps._dpt_app_stub("com.example.MainApplication") is False


def test_dpt_app_stub_none():
    assert ps._dpt_app_stub(None) is False


# ---------------------------------------------------------------------------
# _match_dpt_feature：dpt 主文件匹配（前缀误报防护）
# ---------------------------------------------------------------------------
def test_match_dpt_feature_exact():
    assert ps._match_dpt_feature("assets/i11111i111.zip", "i11111i111.zip") is True


def test_match_dpt_feature_prefix_false_positive():
    assert ps._match_dpt_feature("assets/i11111i111.zip.bak", "i11111i111.zip") is False


def test_match_dpt_feature_special_dir():
    assert ps._match_dpt_feature("assets/OoooooOooo/sub/x", "OoooooOooo") is True


# ---------------------------------------------------------------------------
# _classify_custom_family / _judge_custom_family：自研保护归类
# ---------------------------------------------------------------------------
def test_classify_custom_family_jdog():
    assert ps._classify_custom_family(
        ["libx.so"], True, {}) == ("jdog_native_dex_loader", "high")


def test_classify_custom_family_packhub():
    dex_info = {"class_names": ["com/packhub/shell/DexLoader"]}
    assert ps._classify_custom_family([], False, dex_info) == ("packhub_shell", "high")


def test_classify_custom_family_none():
    assert ps._classify_custom_family([], False, {}) == (None, None)


def _mk_custom_signals(**over):
    signals = {
        "feats": {"asset_payloads": [], "application": None,
                  "appcomponentfactory": False},
        "dex_info": {"stub": False,
                     "dex": [{"name": "classes.dex", "classes": 5000}],
                     "class_names": []},
        "so_content": {"jdog_native_loader": [], "non_elf": []},
        "hidden_dex": [],
        "malformed_manifest": False,
        "random_libs": [],
        "hex_packer_pairs": [],
        "fake_dex_decoys": [],
    }
    signals.update(over)
    return signals


def test_judge_custom_family_jdog_native():
    r = ps._judge_custom_family(_mk_custom_signals(
        so_content={"jdog_native_loader": ["libfoo.so"], "non_elf": []},
        dex_info={"stub": True, "dex": [], "class_names": []},
    ))
    assert r["custom_family"] == "jdog_native_dex_loader"
    assert r["custom_family_confidence"] == "high"


def test_judge_custom_family_packhub():
    r = ps._judge_custom_family(_mk_custom_signals(
        dex_info={"stub": False,
                  "dex": [{"name": "classes.dex", "classes": 100}],
                  "class_names": ["com/packhub/shell/DexLoader"]},
    ))
    assert r["custom_family"] == "packhub_shell"


def test_judge_custom_family_random_lib_malformed():
    r = ps._judge_custom_family(_mk_custom_signals(
        malformed_manifest=True,
        random_libs=["libGTlNLCpFsvbV.so"],
    ))
    assert r["custom_packer_strong"] is True
    assert r["custom_packer"] is True


def test_judge_custom_family_none():
    r = ps._judge_custom_family(_mk_custom_signals())
    assert r["custom_family"] is None
    assert r["custom_packer"] is False
    assert r["custom_packer_strong"] is False


# ---------------------------------------------------------------------------
# P1 修复：libexec*.so 与爱加密特征冲突 → so 内容 dpt 独有路径名复核
# ---------------------------------------------------------------------------
def test_judge_dpt_modified_conflict_so():
    """旧版 dpt 壳 so 与爱加密同名 libexec.so：so 含 dpt 独有路径名 → 魔改 dpt。"""
    sig = _mk_signals(so_content={
        "dpt_shell_so": [],
        "dpt_shell_so_weak": ["lib/armeabi-v7a/libexec.so"],
    })
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "modified"
    assert "libexec.so" in " ".join(evidence)


def test_route_dpt_conflict_beats_vendor():
    """冲突复核成立后，dpt 路由优先于爱加密 matched（不再落到 unsupported）。"""
    sig = {"edition": None, "vmp": False, "dpt_shell": True,
           "dpt_type": "modified", "custom_family": None,
           "matched": [{"vendor": "爱加密", "key": "ijiami"}],
           "dex_stub": True, "dex_classes": [1]}
    assert ps.suggest_route(sig) == "dpt"


class _FakeApkView:
    """最小 _ApkView 替身：_scan_so_content / _detect_dpt_files 只用 read/files。"""

    def __init__(self, files_map):
        self._files = files_map
        self.files = list(files_map)

    def read(self, name):
        return self._files[name]


def test_scan_so_content_conflict_string_hit():
    """so 内容含 OoooooOooo（dpt 独有）但不满足 REQUIRED → 记入 weak，不进强判定。"""
    so = b"\x7fELF" + b"...OoooooOooo/others..." + b"\x00" * 16
    view = _FakeApkView({"lib/armeabi-v7a/libexec.so": so})
    r = ps._scan_so_content(view, ["lib/armeabi-v7a/libexec.so"])
    assert r["dpt_shell_so"] == []
    assert r["dpt_shell_so_weak"] == ["lib/armeabi-v7a/libexec.so"]


def test_scan_so_content_no_conflict_string():
    so = b"\x7fELF" + b"plain business library" + b"\x00" * 16
    view = _FakeApkView({"lib/arm64-v8a/libbusiness.so": so})
    r = ps._scan_so_content(view, ["lib/arm64-v8a/libbusiness.so"])
    assert r["dpt_shell_so"] == []
    assert r["dpt_shell_so_weak"] == []


# ---------------------------------------------------------------------------
# P2 修复：stub 强弱分级（ProxyApplication 是插件化框架常用名）
# ---------------------------------------------------------------------------
def test_dpt_app_stub_levels():
    assert ps._dpt_app_stub_level("com.luoyesiqiu.shell.ProxyApplication") == "strong"
    assert ps._dpt_app_stub_level("com.nashsiqiu.shell.StubApp") == "strong"
    assert ps._dpt_app_stub_level("com.example.MainProxyApplication") == "weak"
    assert ps._dpt_app_stub_level("com.example.MyProxyComponentFactory") == "weak"
    assert ps._dpt_app_stub_level("com.example.MainApplication") == "none"
    assert ps._dpt_app_stub_level(None) == "none"


def test_judge_dpt_weak_stub_alone_false():
    """弱 stub 单独命中（无任何壳行为佐证）→ 不判 dpt，防插件化框架误报。"""
    sig = _mk_signals(feats={
        "dpt_primary_files": [], "dpt_shell_files": [],
        "asset_payloads": [],
        "application": "com.example.MainProxyApplication",
        "appcomponentfactory": False,
    })
    dpt_shell, dpt_type, _, _ = ps._judge_dpt(sig)
    assert dpt_shell is False
    assert dpt_type is None


def test_judge_dpt_weak_stub_with_factory_suspected():
    """弱 stub + appComponentFactory 声明 → suspected（保守，不抢 vendor 路由）。"""
    sig = _mk_signals(feats={
        "dpt_primary_files": [], "dpt_shell_files": [],
        "asset_payloads": [],
        "application": "com.example.MainProxyApplication",
        "appcomponentfactory": True,
    })
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "suspected"
    assert "appComponentFactory" in evidence


def test_judge_dpt_weak_stub_with_dex_stub_suspected():
    """弱 stub + 根 dex 是壳 → suspected。"""
    sig = _mk_signals(
        feats={
            "dpt_primary_files": [], "dpt_shell_files": [],
            "asset_payloads": [],
            "application": "com.example.ProxyApplication",
            "appcomponentfactory": False,
        },
        dex_info={"stub": True, "dex": [{"name": "classes.dex", "classes": 1}]},
    )
    dpt_shell, dpt_type, evidence, _ = ps._judge_dpt(sig)
    assert dpt_shell is True
    assert dpt_type == "suspected"
    assert any(str(e).startswith("dex_stub") for e in evidence)


# ---------------------------------------------------------------------------
# P3 修复：appComponentFactory 兼容 UTF-16LE 字符串池
# ---------------------------------------------------------------------------
def test_axml_string_present_utf8_and_utf16():
    assert ps._axml_string_present(b"xx appComponentFactory yy", "appComponentFactory") is True
    utf16 = "appComponentFactory".encode("utf-16-le")
    assert ps._axml_string_present(b"\x03\x00\x01\x00" + utf16 + b"\x00\x00", "appComponentFactory") is True
    assert ps._axml_string_present(b"nothing here", "appComponentFactory") is False
    assert ps._axml_string_present(b"", "appComponentFactory") is False


def test_detect_dpt_files_utf16_manifest():
    """UTF-16LE 字符串池的 manifest（灰产重打包常见）不再漏检 factory。"""
    manifest = b"\x03\x00" + "appComponentFactory".encode("utf-16-le") + b"\x00\x00"
    view = _FakeApkView({"AndroidManifest.xml": manifest})
    _, has = ps._detect_dpt_files(["AndroidManifest.xml"], view)
    assert has is True


def test_detect_dpt_files_utf8_manifest():
    manifest = b"prefix appComponentFactory suffix"
    view = _FakeApkView({"AndroidManifest.xml": manifest})
    _, has = ps._detect_dpt_files(["AndroidManifest.xml"], view)
    assert has is True


# ---------------------------------------------------------------------------
# P4 修复：内嵌 ZIP header fallback 需条目佐证（dpt 特征名或多条目）
# ---------------------------------------------------------------------------
def _mk_dex_with_trailing_zip(entries):
    """构造 file_size=0x70 的 dex 头 + 尾部合法 ZIP（模拟 header fallback 场景）。"""
    import io
    import zipfile as _zf
    buf = io.BytesIO()
    with _zf.ZipFile(buf, "w") as z:
        for n in entries:
            z.writestr(n, b"payload-data" * 8)
    dex = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    dex[32:36] = (0x70).to_bytes(4, "little")
    return bytes(dex) + buf.getvalue()


def test_appended_zip_header_single_foreign_entry_rejected():
    """尾部单条目无关 ZIP（对齐 padding 场景）→ 不再误判内嵌 ZIP。"""
    data = _mk_dex_with_trailing_zip(["readme.txt"])
    assert ps._appended_zip_in_dex_bytes(data) is None


def test_appended_zip_header_dpt_entry_hit():
    data = _mk_dex_with_trailing_zip(["i11111i111.zip"])
    hit = ps._appended_zip_in_dex_bytes(data)
    assert hit is not None
    assert hit["endian"] == "header"
    assert hit["offset"] == 0x70


def test_appended_zip_header_multi_entry_hit():
    data = _mk_dex_with_trailing_zip(["a.bin", "b.cfg"])
    hit = ps._appended_zip_in_dex_bytes(data)
    assert hit is not None
    assert hit["endian"] == "header"


def test_vendor_weak_filename_is_candidate_only():
    feats = {
        "lib_sos": {"libexecinfo.so"},
        "asset_so_names": set(),
        "asset_names": set(),
        "application": None,
    }
    assert ps._match_vendors(feats) == []
    candidates = ps._match_vendor_candidates(feats)
    assert candidates and candidates[0]["confirmed"] is False
    assert candidates[0]["evidence_strength"] == "weak"


def test_vendor_strong_filename_is_confirmed():
    feats = {
        "lib_sos": {"libjiagu.so"},
        "asset_so_names": set(),
        "asset_names": set(),
        "application": None,
    }
    assert [m["key"] for m in ps._match_vendors(feats)] == ["qihoo360"]


def test_path_matching_is_case_insensitive_and_rejects_traversal():
    assert ps._collect_file_names([
        "Lib/arm64-v8a/libjiagu.so",
        "Assets/libshellx.so",
        "../fake/lib/arm64-v8a/libjiagu.so",
    ]) == ({"libjiagu.so"}, {"libshellx.so"}, {"libshellx.so"})


@pytest.mark.parametrize("name,expected", [
    ("360 Jiagu", "unpacker/flow_360.py"),
    ("Alibaba", "unpacker/flow_ali.py"),
])
def test_apkid_alias_resolution(name, expected):
    assert apkid.resolve_flows([name]) == [expected]


@pytest.mark.parametrize("name", ["ali", "op", "sec"])
def test_apkid_short_name_does_not_resolve(name):
    assert apkid.resolve_flow([name]) is None


def test_apkid_multiple_packers_are_ambiguous():
    assert len(apkid.resolve_flows(["360", "tencent"])) == 2
