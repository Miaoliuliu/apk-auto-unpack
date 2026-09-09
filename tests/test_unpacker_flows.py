"""脱壳模块（flow_dpt_shell / validate / adapters）行为锁定测试。

与 test_packer_sigs.py 同思路：锁定当前行为，重构/调参导致行为变化立即变红。

不依赖真机/Frida：动态 dump 链路只测纯函数（协议组装、dex 校验、择优、
sleep 语义），frida 相关 I/O 不在覆盖范围。

    C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe -m pytest tests/test_unpacker_flows.py -v
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from auto_unpack.unpacker import adapters
from auto_unpack.unpacker import flow_dpt_shell as fd
from auto_unpack.unpacker import validate as vd


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def _mk_valid_dex(size: int = 0x80) -> bytes:
    """构造通过 is_valid_dumped_dex 的最小 dex 形状（magic/file_size/header_size 合法）。"""
    b = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", b, 0x20, size, 0x70)
    return bytes(b) + b"\x00" * (size - 0x70)


# ---------------------------------------------------------------------------
# U8：dex 硬校验（dey 一律拒收）
# ---------------------------------------------------------------------------
def test_is_valid_dumped_dex_ok():
    assert fd.is_valid_dumped_dex(_mk_valid_dex()) is True


def test_is_valid_dumped_dex_too_short():
    assert fd.is_valid_dumped_dex(b"dex\n035\x00") is False
    assert fd.is_valid_dumped_dex(b"") is False


def test_is_valid_dumped_dex_bad_magic():
    data = bytearray(_mk_valid_dex())
    data[0:4] = b"XXXX"
    assert fd.is_valid_dumped_dex(bytes(data)) is False


def test_is_valid_dumped_dex_rejects_dey():
    """dey/vdex 的 file_size 语义与 dex 不同，repair 也不处理 → 拒收（U8）。"""
    data = bytearray(_mk_valid_dex())
    data[0:4] = b"dey\n"
    assert fd.is_valid_dumped_dex(bytes(data)) is False


def test_is_valid_dumped_dex_header_size_mismatch():
    data = bytearray(_mk_valid_dex())
    struct.pack_into("<I", data, 0x24, 0x78)
    assert fd.is_valid_dumped_dex(bytes(data)) is False


def test_is_valid_dumped_dex_size_mismatch():
    data = bytearray(_mk_valid_dex())
    struct.pack_into("<I", data, 0x20, 0x1000)
    assert fd.is_valid_dumped_dex(bytes(data)) is False


# ---------------------------------------------------------------------------
# dex_file_arg_index：Itanium 符号 → DexFile 参数下标
# ---------------------------------------------------------------------------
def test_dex_arg_define_class():
    sig = "_ZNK3art11ClassLinker11DefineClassEPNS_6ThreadEPKcNS_6HandleINS_6mirror5ClassEEERKNS_7DexFileRKNS_9ClassDefE"
    assert fd.dex_file_arg_index(sig) == 5


def test_dex_arg_loadmethod_no_thread():
    assert fd.dex_file_arg_index(
        "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileRKNS_9ClassDefE") == 1


def test_dex_arg_loadmethod_with_thread():
    assert fd.dex_file_arg_index(
        "_ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFile") == 2


def test_dex_arg_unknown():
    assert fd.dex_file_arg_index("_ZN3art9SomethingEv") == -1


# ---------------------------------------------------------------------------
# _on_message / _ChunkAssembler：单块、截断、无效、分块重组（U9）
# ---------------------------------------------------------------------------
def _mk_handler(tmp_path: Path):
    counter = {"n": 0, "skip": 0}
    return fd._on_message(tmp_path, counter), counter


def test_handler_single_block_saved(tmp_path):
    handler, counter = _mk_handler(tmp_path)
    raw = _mk_valid_dex()
    handler({"type": "send",
             "payload": {"type": "dex", "begin": "0x7fabc", "size": len(raw), "round": 1}},
            raw)
    assert counter["n"] == 1
    assert (tmp_path / "dex_0x7fabc_80.dex").read_bytes() == raw


def test_handler_truncated_dropped(tmp_path):
    handler, counter = _mk_handler(tmp_path)
    raw = _mk_valid_dex()
    handler({"type": "send",
             "payload": {"type": "dex", "begin": "0x1", "size": len(raw) + 10, "round": 1}},
            raw)
    assert counter["n"] == 0 and counter["skip"] == 1
    assert list(tmp_path.glob("dex_*.dex")) == []


def test_handler_invalid_magic_dropped(tmp_path):
    handler, counter = _mk_handler(tmp_path)
    bad = b"XXXX" + _mk_valid_dex()[4:]
    handler({"type": "send",
             "payload": {"type": "dex", "begin": "0x2", "size": len(bad), "round": 1}},
            bad)
    assert counter["skip"] == 1 and list(tmp_path.glob("dex_*.dex")) == []


def test_handler_round2_filename(tmp_path):
    """重捞轮 round=2 → 文件名带 _r2，不覆盖首轮产物（U1）。"""
    handler, counter = _mk_handler(tmp_path)
    raw = _mk_valid_dex()
    handler({"type": "send",
             "payload": {"type": "dex", "begin": "0xaaa", "size": len(raw), "round": 2}},
            raw)
    assert counter["n"] == 1
    assert (tmp_path / "dex_0xaaa_80_r2.dex").exists()


def test_handler_chunked_reassembly(tmp_path):
    """大 dex 分块：dex-begin + N 个 dex-chunk，全部到齐后写盘（U9）。"""
    handler, counter = _mk_handler(tmp_path)
    begin = "0xfff"
    raw = _mk_valid_dex(200)          # 合法 dex 形状，能过 is_valid_dumped_dex
    chunk1, chunk2 = raw[:100], raw[100:]
    handler({"type": "send",
             "payload": {"type": "dex-begin", "begin": begin, "size": len(raw),
                         "round": 1, "chunks": 2}},
            None)
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 0}}, chunk1)
    assert counter["n"] == 0  # 未到齐不写盘
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 1}}, chunk2)
    assert counter["n"] == 1
    assert (tmp_path / f"dex_{begin}_{len(raw):x}.dex").read_bytes() == raw


def test_handler_chunk_incomplete_never_written(tmp_path):
    handler, counter = _mk_handler(tmp_path)
    begin = "0xeee"
    handler({"type": "send",
             "payload": {"type": "dex-begin", "begin": begin, "size": 300,
                         "round": 1, "chunks": 3}},
            None)
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 0}}, b"X" * 100)
    assert counter["n"] == 0 and list(tmp_path.glob("dex_*.dex")) == []


# ---------------------------------------------------------------------------
# U1：_keep_best_dumps 同 begin 多轮择优
# ---------------------------------------------------------------------------
def test_keep_best_dumps_keeps_lowest_ratio(monkeypatch, tmp_path):
    import auto_unpack.packer.packer_sigs as ps

    def fake_analyze(path, light=False, collect_names=False):
        # _r2 是回填态（空占比 0），首轮是抽取态（0.9）→ 淘汰首轮
        if "r2" in path:
            return {"dex": [{"shell_ratio": 0.0}], "stub": False}
        return {"dex": [{"shell_ratio": 0.9}], "stub": False}

    monkeypatch.setattr(ps, "analyze_dex_structure", fake_analyze)
    raw = _mk_valid_dex()
    (tmp_path / "dex_0xaaa_80.dex").write_bytes(raw)
    (tmp_path / "dex_0xaaa_80_r2.dex").write_bytes(raw)
    assert fd._keep_best_dumps(tmp_path) == 1
    assert (tmp_path / "dex_0xaaa_80_r2.dex").exists()
    assert not (tmp_path / "dex_0xaaa_80.dex").exists()
    assert (tmp_path / "_invalid_dex" / "dex_0xaaa_80.dex").exists()


def test_keep_best_dumps_unparsable_loses(monkeypatch, tmp_path):
    """解析失败的 dump 视作最差，让位给可解析副本。"""
    import auto_unpack.packer.packer_sigs as ps

    def fake_analyze(path, light=False, collect_names=False):
        raise RuntimeError("boom")

    monkeypatch.setattr(ps, "analyze_dex_structure", fake_analyze)
    raw = _mk_valid_dex()
    (tmp_path / "dex_0xbbb_80.dex").write_bytes(raw)
    (tmp_path / "dex_0xbbb_80_r2.dex").write_bytes(raw)
    assert fd._keep_best_dumps(tmp_path) == 1
    # 同 ratio(2.0)，按文件名排序保留 bbb_80.dex
    assert (tmp_path / "dex_0xbbb_80.dex").exists()


def test_keep_best_dumps_single_not_touched(monkeypatch, tmp_path):
    monkeypatch.setattr("auto_unpack.packer.packer_sigs.analyze_dex_structure",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("不应调用")))
    (tmp_path / "dex_0xccc_80.dex").write_bytes(_mk_valid_dex())
    assert fd._keep_best_dumps(tmp_path) == 0
    assert (tmp_path / "dex_0xccc_80.dex").exists()


# ---------------------------------------------------------------------------
# U7：adb 查找（XJB_ADB → ADB → PATH）
# ---------------------------------------------------------------------------
def test_find_adb_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "adb.exe"
    fake.write_bytes(b"x")
    monkeypatch.setenv("XJB_ADB", str(fake))
    monkeypatch.delenv("ADB", raising=False)
    monkeypatch.setattr(fd.shutil, "which", lambda _: None)
    assert fd._find_adb() == str(fake)


def test_find_adb_none(monkeypatch):
    monkeypatch.delenv("XJB_ADB", raising=False)
    monkeypatch.delenv("ADB", raising=False)
    monkeypatch.setattr(fd.shutil, "which", lambda _: None)
    assert fd._find_adb() is None


# ---------------------------------------------------------------------------
# U5：adapters.execute 的 sleep 语义（0 是合法值）
# ---------------------------------------------------------------------------
def test_execute_passes_sleep_zero(monkeypatch, tmp_path):
    captured = {}

    def fake_dump(package, out_dir, device=None, sleep=None, kill=True):
        captured["sleep"] = sleep
        return []

    monkeypatch.setattr(fd, "dump", fake_dump)
    adapters.execute("dpt-shell", apk_path=None, package="x",
                     out_dir=tmp_path, device=None, sleep=0)
    assert captured["sleep"] == 0


def test_execute_passes_sleep_none_defaults_20(monkeypatch, tmp_path):
    captured = {}

    def fake_dump(package, out_dir, device=None, sleep=None, kill=True):
        captured["sleep"] = sleep
        return []

    monkeypatch.setattr(fd, "dump", fake_dump)
    adapters.execute("dpt-shell", apk_path=None, package="x",
                     out_dir=tmp_path, device=None, sleep=None)
    assert captured["sleep"] == 20


def test_execute_unknown_adapter_raises():
    with pytest.raises(RuntimeError):
        adapters.execute("whatever", apk_path=None, package="x",
                         out_dir=Path("."), device=None, sleep=None)


def test_select_adapter_route_map():
    assert adapters.select_adapter("dpt", {}) == "dpt-shell"
    assert adapters.select_adapter("static", {}) == "static"
    assert adapters.select_adapter("manual", {}) == "manual"
    assert adapters.select_adapter("unknown", {}) == "skip"
    assert adapters.select_adapter("vendor", {"matched": []}) == "unsupported"


# ---------------------------------------------------------------------------
# validate.py：payload 判定与完整性汇总
# ---------------------------------------------------------------------------
def test_framework_ratio():
    assert vd.framework_ratio([]) == 0.0
    assert vd.framework_ratio(["Ljava/lang/String;", "Landroid/app/Activity;"]) == 1.0
    assert vd.framework_ratio(["Lcom/foo/Bar;", "Ljava/lang/String;"]) == 0.5


def test_is_payload_dex_always_by_size(tmp_path):
    """体积 ≥100KB 直接视为业务 dex（stat 真实存在才有 size）。"""
    big = tmp_path / "big.dex"
    big.write_bytes(b"\x00" * (100 * 1024 + 1))
    stats = {"classes": 0, "concrete": 0, "framework_ratio": 0.0}
    assert vd.is_payload_dex(big, stats) is True


def test_is_payload_dex_by_classes(tmp_path):
    small = tmp_path / "small.dex"
    small.write_bytes(b"\x00" * 1024)
    stats = {"classes": 50, "concrete": 40, "framework_ratio": 0.0}
    assert vd.is_payload_dex(small, stats) is True


def test_is_payload_dex_framework_filtered(tmp_path):
    """framework 占比 ≥0.85 的 dex 即使体积大也不是业务 dex。"""
    big = tmp_path / "fw.dex"
    big.write_bytes(b"\x00" * (150 * 1024))
    stats = {"classes": 5000, "concrete": 4000, "framework_ratio": 0.9}
    assert vd.is_payload_dex(big, stats) is False


def test_is_payload_dex_small_stub(tmp_path):
    tiny = tmp_path / "stub.dex"
    tiny.write_bytes(b"\x00" * 1024)
    stats = {"classes": 2, "concrete": 1, "framework_ratio": 0.0}
    assert vd.is_payload_dex(tiny, stats) is False


def test_summarize_completeness_pass():
    rows = [{"name": "classes2.dex", "payload": True, "concrete": 1000,
             "empty": 5, "empty_shell": 0, "shell_ratio": 0.005}]
    q = vd.summarize_completeness(rows)
    assert q["complete"] is True
    assert q["payload_dex_count"] == 1


def test_summarize_completeness_fail_on_max_ratio():
    rows = [{"name": "classes2.dex", "payload": True, "concrete": 1000,
             "empty": 300, "empty_shell": 0, "shell_ratio": 0.3}]
    q = vd.summarize_completeness(rows)
    assert q["complete"] is False


def test_summarize_completeness_no_payload():
    q = vd.summarize_completeness([{"name": "stub.dex", "payload": False}])
    assert q["complete"] is False
    assert q["skipped_stub_dex"] == ["stub.dex"]
