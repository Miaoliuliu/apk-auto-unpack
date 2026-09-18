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


def _mk_real_class_table_dex(*, ncls: int = 1, class_data_off: int,
                             data_off: int, data_size: int,
                             tail_pad: int = 0) -> bytes:
    """带真实 class_defs 表的最小 dex，用来测截断判定（不是 header-only 夹具）。"""
    cdef_off = 0x70
    body = bytearray(ncls * 32 + 16)
    for i in range(ncls):
        struct.pack_into("<I", body, i * 32 + 24, class_data_off)
    data = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    data.extend(body)
    if tail_pad:
        data.extend(b"\x00" * tail_pad)
    struct.pack_into("<II", data, 0x20, len(data), 0x70)
    struct.pack_into("<II", data, 0x60, ncls, cdef_off)
    struct.pack_into("<II", data, 0x68, data_size, data_off)
    return bytes(data)


def test_dex_class_data_truncated_detects_oob():
    """data 段 / class_data_off 越出文件 → 截断。"""
    n = 0x70 + 32 + 16
    data = _mk_real_class_table_dex(
        class_data_off=n + 100, data_off=0x90, data_size=16)
    assert fd.is_valid_dumped_dex(data) is True
    assert fd.dex_class_data_truncated(data) is True
    data2 = _mk_real_class_table_dex(
        class_data_off=0x90, data_off=0x90, data_size=0x10000)
    assert fd.dex_class_data_truncated(data2) is True


def test_dex_class_data_truncated_keeps_trailing_junk():
    """尾部冗余但指针仍在文件内 → 不是截断（绘本那种不能删）。"""
    data = _mk_real_class_table_dex(
        class_data_off=0x90, data_off=0x90, data_size=16, tail_pad=8192)
    assert fd.is_valid_dumped_dex(data) is True
    assert fd.dex_class_data_truncated(data) is False


def test_purge_truncated_dex_deletes_only_oob(tmp_path):
    good = _mk_real_class_table_dex(
        class_data_off=0x90, data_off=0x90, data_size=16, tail_pad=1024)
    bad = _mk_real_class_table_dex(
        class_data_off=0x90, data_off=0x90, data_size=0x10000)
    (tmp_path / "classes07.dex").write_bytes(good)
    (tmp_path / "classes03.dex").write_bytes(bad)
    moved = fd.purge_truncated_dex(tmp_path, pattern="classes*.dex")
    assert [p.name for p in moved] == ["classes03.dex"]
    assert (tmp_path / "classes07.dex").is_file()
    assert not (tmp_path / "classes03.dex").exists()


def test_header_only_fixture_is_not_truncated():
    """_mk_valid_dex / _mk_dumped_dex 没有真实 class_defs 表，不得被当成截断。"""
    assert fd.dex_class_data_truncated(_mk_valid_dex()) is False
    assert fd.dex_class_data_truncated(_mk_dumped_dex(body=4096, tail_pad=8192)) is False


# ---------------------------------------------------------------------------
# U8b：跨页边界污染判定（扩容副本 / 空壳伪装）
#
# 实测 ADIA 样本：frida-dexdump -d 在内存页边界多读一段，50 个 dex 两两成对
# （25 组），目录 63.7% 是重复副本。以下用真实样本的头部形状构造回归用例。
# ---------------------------------------------------------------------------
def _mk_dumped_dex(body: int, tail_pad: int = 0, class_defs: int = 100,
                   embed_marker: bool = False) -> bytes:
    """构造 dex 形状；tail_pad>0 模拟扩容副本的冗余尾部。

    语义：头部声明 file_size = 实际长度（通过 is_valid_dumped_dex），
    但 map_off 只覆盖 body 区（= 小副本的坐标系），故
    map_off + 16 = 0x70 + body，冗余 = tail_pad。
    """
    data = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    data.extend(b"\x11" * body)
    if embed_marker:
        data.extend(b"dex\n035\x00")
        if tail_pad > 8:
            data.extend(b"\x00" * (tail_pad - 8))
    elif tail_pad:
        data.extend(b"\x00" * tail_pad)
    struct.pack_into("<II", data, 0x20, len(data), 0x70)   # file_size / header_size
    struct.pack_into("<I", data, 0x60, class_defs)         # class_defs_size
    struct.pack_into("<I", data, 0x34, 0x70 + body - 16)   # map_off 只覆盖 body 区
    return bytes(data)


def test_is_valid_dumped_dex_still_accepts_expanded_copy():
    """扩容副本仍能过 is_valid_dumped_dex（magic/header/file_size 三条全过）。"""
    data = _mk_dumped_dex(body=4096, tail_pad=8192)
    assert fd.is_valid_dumped_dex(data) is True


def test_dex_redundant_bytes():
    """map_off 末项贴尾 → 冗余 0；带尾部追加 → 冗余即尾部量。"""
    assert fd.dex_redundant_bytes(_mk_dumped_dex(body=4096)) == 0
    assert fd.dex_redundant_bytes(_mk_dumped_dex(body=4096, tail_pad=8192)) == 8192


def test_redundant_bytes_must_not_be_used_to_remove(tmp_path):
    """回归防护：大冗余**不**构成剔除理由。

    实测教训：曾用「冗余量」在 quarantine 中主动移走文件，全样本 767 个有效
    dex 里误伤 126 个（绘本 252 个中 98 个），而这些 dex 的 class_defs 正常、
    jadx 可解析。冗余区是内存邻近区块残片，属 dump 产物通用形态，不是垃圾。
    因此正常 class_defs 的大冗余文件必须留在原地。
    """
    data = _mk_dumped_dex(body=9 * 1024 * 1024, tail_pad=9 * 1024 * 1024,
                          class_defs=200)
    assert fd.dex_redundant_bytes(data) > 1024 * 1024   # 确实有大冗余
    assert fd.is_suspect_dumped_dex(data) is False      # 但不算可疑（类数正常）
    (tmp_path / "classes158.dex").write_bytes(data)
    moved = fd.quarantine_invalid_dex(tmp_path)          # 也不该被移走
    assert moved == []
    assert (tmp_path / "classes158.dex").is_file()


def test_is_suspect_by_volume_disguise():
    """class_defs 极少而体积很大 → 体积与内容不相称（ADIA/classes08.dex 形态）。"""
    data = _mk_dumped_dex(body=8 * 1024 * 1024, tail_pad=0, class_defs=4)
    assert fd.is_valid_dumped_dex(data) is True
    assert fd.is_suspect_dumped_dex(data) is True


def test_suspect_does_not_remove_files(tmp_path):
    """可疑只告警、不移走 —— 避免误伤仍有价值的产物。"""
    (tmp_path / "classes08.dex").write_bytes(
        _mk_dumped_dex(body=8 * 1024 * 1024, class_defs=4))
    suspects = fd.warn_suspect_dumped_dex(tmp_path)
    assert len(suspects) == 1
    assert (tmp_path / "classes08.dex").is_file()        # 文件仍在
    assert not (tmp_path / "_invalid_dex").exists()      # 未创建隔离目录


def test_suspect_accepts_normal_dex():
    """正常 dex（类数充足）不算可疑。"""
    data = _mk_dumped_dex(body=0x10000, class_defs=500)
    assert fd.is_suspect_dumped_dex(data) is False


def test_has_embedded_dex_marker_as_diagnostic():
    """内嵌标记检测仅作诊断，不得用于剔除（正常产物也普遍含此标记）。"""
    with_marker = _mk_dumped_dex(body=0x10000, tail_pad=0x40000, embed_marker=True)
    assert fd.has_embedded_dex_marker(with_marker) is True
    # 但它不构成可疑判定
    assert fd.is_suspect_dumped_dex(with_marker) is False
    clean = _mk_dumped_dex(body=0x10000, class_defs=500)
    assert fd.has_embedded_dex_marker(clean) is False


def test_dedupe_dumped_dex_keeps_smallest(tmp_path):
    """同一头部元组的多个边界只保留体积最小者，其余删除。"""
    small = _mk_dumped_dex(body=4096, class_defs=100)
    big = _mk_dumped_dex(body=4096, tail_pad=8192, class_defs=100)
    # 两者头部元组一致（body 相同），仅物理长度不同 → 应归为一组
    (tmp_path / "dex_a_1000.dex").write_bytes(small)
    (tmp_path / "dex_b_1000.dex").write_bytes(big)
    moved = fd.dedupe_dumped_dex(tmp_path, pattern="dex_*.dex")
    assert len(moved) == 1
    assert (tmp_path / "dex_a_1000.dex").is_file()
    assert not (tmp_path / "dex_b_1000.dex").exists()
    assert not (tmp_path / "_invalid_dex").exists()


def test_dedupe_dumped_dex_classes_pattern(tmp_path):
    """flow_360（frida-dexdump）产出 classes*.dex，需按该命名匹配。"""
    small = _mk_dumped_dex(body=4096, class_defs=100)
    big = _mk_dumped_dex(body=4096, tail_pad=8192, class_defs=100)
    (tmp_path / "classes.dex").write_bytes(small)
    (tmp_path / "classes02.dex").write_bytes(big)
    moved = fd.dedupe_dumped_dex(tmp_path, pattern="classes*.dex")
    assert len(moved) == 1
    assert (tmp_path / "classes.dex").is_file()
    assert not (tmp_path / "classes02.dex").exists()


# ---------------------------------------------------------------------------
# Jiagu 类拼接壳：冗余区疑似加密源 dex → 不得去重
# ---------------------------------------------------------------------------
def _mk_jiagu_pair(shell_body: int = 64, payload_bytes: int = 2 * 1024 * 1024):
    """构造 Jiagu 形态的一对文件：小壳 dex + （壳+加密载荷）的大副本。

    两者的 (string/type/proto/field/method/class, data_size, data_off, map_off)
    完全一致（这正是现有去重的分组依据），差别只在物理长度与尾部载荷。
    map_off 只覆盖 body，故末尾 payload 即为「冗余区」。
    """
    meta = ((0x38, 194), (0x40, 64), (0x48, 45), (0x50, 5), (0x58, 95), (0x60, 4))

    def build(extra: bytes) -> bytes:
        b = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
        b.extend(b"\x11" * shell_body)
        b.extend(extra)
        struct.pack_into("<II", b, 0x20, len(b), 0x70)
        for off, val in meta:
            struct.pack_into("<I", b, off, val)
        struct.pack_into("<II", b, 0x68, 7272, 2612)
        struct.pack_into("<I", b, 0x34, 0x70 + shell_body - 16)
        return bytes(b)

    shell = build(b"")
    # 载荷：明文类描述符（模拟 512B 加密区之后的 type_ids 表），但**无 dex magic**
    payload = (b"Lcom/bobo/db/HistoryDatabase;\x00" * 64
               + b"\x11" * max(payload_bytes - 64 * 32, 0))
    return shell, build(payload)


def test_redundancy_holds_unique_data_detects_jiagu_splice():
    """无 dex 头且非全零的大冗余 → 疑加密源 dex。"""
    _shell, spliced = _mk_jiagu_pair()
    assert fd.redundancy_holds_unique_data(spliced) is True


def test_redundancy_holds_unique_data_allows_true_duplicate():
    """小冗余（真重复）不算含唯一数据。"""
    data = _mk_dumped_dex(body=4096, tail_pad=512)     # 冗余 512 < 64KB
    assert fd.redundancy_holds_unique_data(data) is False


def test_redundancy_holds_unique_data_allows_plain_splice():
    """冗余区含明文 dex 头 → 内嵌 dex 必有独立文件，可安全移走。"""
    inner = b"dex\n035\x00"
    body = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    body.extend(b"\x11" * 4096)
    body.extend(inner)
    body.extend(b"\x22" * (2 * 1024 * 1024))
    struct.pack_into("<II", body, 0x20, len(body), 0x70)
    struct.pack_into("<I", body, 0x60, 100)
    struct.pack_into("<I", body, 0x34, 0x70 + 4096 - 16)
    assert fd.redundancy_holds_unique_data(bytes(body)) is False


def test_dedupe_keeps_jiagu_spliced_copy(tmp_path):
    """回归防护：疑似含加密源 dex 的副本必须保留，不得移走。

    实证样本：民信贷 classes06.dex（9.67MB 冗余、无 dex 头、含业务类描述符）。
    移走等于丢失解密素材。
    """
    shell, spliced = _mk_jiagu_pair()
    (tmp_path / "classes05.dex").write_bytes(shell)
    (tmp_path / "classes06.dex").write_bytes(spliced)

    moved = fd.dedupe_dumped_dex(tmp_path, pattern="classes*.dex")
    assert (tmp_path / "classes06.dex").is_file(), "疑似加密源 dex 不应被移走"
    assert all(m.name != "classes06.dex" for m in moved)

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


def test_handler_chunk_out_of_order_still_reassembles(tmp_path):
    """chunk 乱序到达：按 seq 落位组装，不依赖到达顺序。"""
    handler, counter = _mk_handler(tmp_path)
    begin = "0xddd"
    raw = _mk_valid_dex(200)
    c0, c1 = raw[:90], raw[90:]
    handler({"type": "send",
             "payload": {"type": "dex-begin", "begin": begin, "size": len(raw),
                         "round": 1, "chunks": 2}},
            None)
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 1}}, c1)
    assert counter["n"] == 0                       # 只到 1 块，不写盘
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 0}}, c0)
    assert counter["n"] == 1
    assert (tmp_path / f"dex_{begin}_{len(raw):x}.dex").read_bytes() == raw


def test_handler_chunk_missing_seq_discarded(tmp_path):
    """缺块（seq 1 未到）拼不出合法 dex → 丢弃，不留半成品。"""
    handler, counter = _mk_handler(tmp_path)
    begin = "0xdde"
    raw = _mk_valid_dex(300)
    handler({"type": "send",
             "payload": {"type": "dex-begin", "begin": begin, "size": len(raw),
                         "round": 1, "chunks": 3}},
            None)
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 0}}, raw[:100])
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 2}}, raw[200:])
    assert counter["n"] == 0
    assert list(tmp_path.glob("dex_*.dex")) == []


def test_handler_chunk_none_data_discarded(tmp_path):
    """chunk 数据为空 → 就地丢弃该 begin，不写盘且不留常驻缓存。"""
    handler, counter = _mk_handler(tmp_path)
    begin = "0xddf"
    raw = _mk_valid_dex(200)
    handler({"type": "send",
             "payload": {"type": "dex-begin", "begin": begin, "size": len(raw),
                         "round": 1, "chunks": 2}},
            None)
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 0}}, None)
    assert counter["n"] == 0
    # 该 begin 已被丢弃，后续补块不应再被接受
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": begin, "seq": 1}}, raw[100:])
    assert counter["n"] == 0
    assert list(tmp_path.glob("dex_*.dex")) == []


def test_handler_chunk_without_begin_ignored(tmp_path):
    """未收到 dex-begin 就来的 chunk 应被忽略，不抛异常、不写盘。"""
    handler, counter = _mk_handler(tmp_path)
    handler({"type": "send",
             "payload": {"type": "dex-chunk", "begin": "0xzzz", "seq": 0}}, b"X" * 64)
    assert counter["n"] == 0
    assert list(tmp_path.glob("dex_*.dex")) == []


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
    assert not (tmp_path / "_invalid_dex").exists()


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


def test_keep_best_dumps_discards_loser(monkeypatch, tmp_path):
    """落选 dump 直接删除，不另建 sidecar 目录。"""
    import auto_unpack.packer.packer_sigs as ps

    monkeypatch.setattr(ps, "analyze_dex_structure",
                        lambda *a, **k: {"dex": [{"shell_ratio": 0.9}], "stub": False})
    raw = _mk_valid_dex()
    (tmp_path / "dex_0xeee_80.dex").write_bytes(raw)
    (tmp_path / "dex_0xeee_80_r2.dex").write_bytes(raw)

    assert fd._keep_best_dumps(tmp_path) == 1
    remaining = list(tmp_path.glob("dex_*.dex"))
    assert len(remaining) == 1
    assert not (tmp_path / "_invalid_dex").exists()


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


def test_execute_passes_sleep_none_defaults_10(monkeypatch, tmp_path):
    captured = {}

    def fake_dump(package, out_dir, device=None, sleep=None, kill=True):
        captured["sleep"] = sleep
        return []

    monkeypatch.setattr(fd, "dump", fake_dump)
    adapters.execute("dpt-shell", apk_path=None, package="x",
                     out_dir=tmp_path, device=None, sleep=None)
    assert captured["sleep"] == 10


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


def test_select_adapter_360_is_automatic():
    sig = {"matched": [{"vendor": "360加固", "key": "qihoo360"}]}
    assert adapters.select_adapter("vendor", sig) == "360"


def test_select_adapter_legu_is_automatic():
    sig = {"matched": [{"vendor": "腾讯乐固", "key": "legu"}]}
    assert adapters.select_adapter("vendor", sig) == "legu"


def test_select_adapter_yidun_is_automatic():
    sig = {"matched": [{"vendor": "网易易盾", "key": "yidun"}]}
    assert adapters.select_adapter("vendor", sig) == "yidun"


def test_select_adapter_other_vendor_still_unsupported():
    sig = {"matched": [{"vendor": "爱加密", "key": "ijiami"}]}
    assert adapters.select_adapter("vendor", sig) == "unsupported"


# ---------------------------------------------------------------------------
# validate.py：payload 判定与完整性汇总
# ---------------------------------------------------------------------------
def test_framework_ratio():
    assert vd.framework_ratio([]) == 0.0
    assert vd.framework_ratio(["Ljava/lang/String;", "Landroid/app/Activity;"]) == 1.0
    assert vd.framework_ratio(["Lcom/foo/Bar;", "Ljava/lang/String;"]) == 0.5


def test_is_payload_dex_always_by_size(tmp_path):
    """体积 ≥100KB 且有条目 → 业务 dex（stat 真实存在才有 size）。"""
    big = tmp_path / "big.dex"
    big.write_bytes(b"\x00" * (100 * 1024 + 1))
    stats = {"classes": 500, "concrete": 400, "framework_ratio": 0.0}
    assert vd.is_payload_dex(big, stats) is True


def test_is_payload_dex_low_density_still_payload(tmp_path):
    """回归防护：低「密度」的大 dex 仍是业务 dex。

    实测教训：曾用 entries/size 密度判据拦体积伪装，结果把绘本 252 个 dex 中
    体积最大的那些（25MB / classes 192~251 / 方法 1000+）全判为非业务 dex。
    这批 dump 产物的 file_size 天然含内存邻近区块，密度本就偏低，不是可靠判据。
    """
    f = tmp_path / "low_density.dex"
    f.write_bytes(b"\x00" * (25 * 1024 * 1024))
    stats = {"classes": 233, "concrete": 1319, "framework_ratio": 0.0}
    assert vd.is_payload_dex(f, stats) is True


def test_is_payload_dex_rejects_pure_padding(tmp_path):
    """零内容的纯填充文件不是业务 dex（极保守保护，仅挡 entries == 0）。"""
    f = tmp_path / "pad.dex"
    f.write_bytes(b"\x00" * (200 * 1024))
    stats = {"classes": 0, "concrete": 0, "framework_ratio": 0.0}
    assert vd.is_payload_dex(f, stats) is False


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


# ---------------------------------------------------------------------------
# 360：frida-dexdump -d（深度搜索），不是 -p（attach-pid）
# ---------------------------------------------------------------------------
def test_build_dexdump_cmd_usb_deep_spawn(tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    cmd = f360.build_dexdump_cmd(
        exe="frida-dexdump", package="com.foo", out_dir=tmp_path,
        device=None, sleep=20,
    )
    assert cmd[:2] == ["frida-dexdump", "-U"]
    assert "-f" in cmd and "com.foo" in cmd
    assert "-d" in cmd
    assert "-p" not in cmd
    assert "--attach-pid" not in cmd
    assert "-o" in cmd and str(tmp_path) in cmd
    assert cmd[cmd.index("--sleep") + 1] == "20"


def test_build_dexdump_cmd_device_id(tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    cmd = f360.build_dexdump_cmd(
        exe="frida-dexdump", package="com.foo", out_dir=tmp_path,
        device="ABCD1234", sleep=0,
    )
    assert "-U" not in cmd
    assert cmd[cmd.index("-D") + 1] == "ABCD1234"
    assert "-d" in cmd
    assert cmd[cmd.index("--sleep") + 1] == "0"


def test_find_frida_dexdump_env_override(monkeypatch, tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    fake = tmp_path / "frida-dexdump.exe"
    fake.write_bytes(b"x")
    monkeypatch.setenv("AUTO_UNPACK_FRIDA_DEXDUMP", str(fake))
    monkeypatch.delenv("FRIDA_DEXDUMP", raising=False)
    monkeypatch.setattr(f360.shutil, "which", lambda _: None)
    assert f360.find_frida_dexdump() == str(fake)


def test_find_frida_dexdump_missing(monkeypatch):
    from auto_unpack.unpacker import flow_360 as f360
    monkeypatch.delenv("AUTO_UNPACK_FRIDA_DEXDUMP", raising=False)
    monkeypatch.delenv("FRIDA_DEXDUMP", raising=False)
    monkeypatch.setattr(f360.shutil, "which", lambda _: None)
    monkeypatch.setattr(f360.sys, "executable", str(Path("C:/missing/python.exe")))
    with pytest.raises(RuntimeError, match="找不到 frida-dexdump"):
        f360.find_frida_dexdump()


def test_list_dumped_dex_classes_names(tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    raw = _mk_valid_dex()
    (tmp_path / "classes.dex").write_bytes(raw)
    (tmp_path / "classes02.dex").write_bytes(raw)
    (tmp_path / "junk.txt").write_text("nope", encoding="utf-8")
    names = [p.name for p in f360.list_dumped_dex(tmp_path)]
    assert names == ["classes.dex", "classes02.dex"]


def test_dump_360_invokes_dexdump(monkeypatch, tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    captured = {}
    exe = tmp_path / "frida-dexdump.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(f360, "find_frida_dexdump", lambda: str(exe))
    monkeypatch.setattr(f360, "_force_stop", lambda *a, **k: None)

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["timeout"] = kw.get("timeout")
        (tmp_path / "classes.dex").write_bytes(_mk_valid_dex())
        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr(f360, "proc_run", fake_run)
    paths = f360.dump("com.foo", tmp_path, device=None, sleep=8, timeout=90)
    assert [p.name for p in paths] == ["classes.dex"]
    assert "-d" in captured["cmd"]
    assert "-f" in captured["cmd"] and "com.foo" in captured["cmd"]
    assert "-p" not in captured["cmd"]
    assert captured["timeout"] == 90
    assert not (tmp_path / "raw").exists()
    assert not (tmp_path / "_invalid_dex").exists()


def test_repair_dumped_dexes_deletes_sidecars(tmp_path):
    """修好的 dex 留在样本目录；raw / _invalid_dex 删除。"""
    from auto_unpack.dex_utils import repair_dumped_dexes

    data = bytearray(_mk_valid_dex())
    data[8:12] = b"\x00\x00\x00\x00"
    (tmp_path / "classes.dex").write_bytes(bytes(data))
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "old.dex").write_bytes(b"x")
    (tmp_path / "_invalid_dex").mkdir()
    (tmp_path / "_invalid_dex" / "junk.dex").write_bytes(b"y")
    assert repair_dumped_dexes(tmp_path) == 1
    assert not (tmp_path / "raw").exists()
    assert not (tmp_path / "_invalid_dex").exists()
    assert list(tmp_path.glob("*.dex")) == [tmp_path / "classes.dex"]


def test_dump_360_raises_when_no_dex(monkeypatch, tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    monkeypatch.setattr(f360, "find_frida_dexdump", lambda: "frida-dexdump")
    monkeypatch.setattr(f360, "_force_stop", lambda *a, **k: None)

    class _R:
        returncode = 0

    monkeypatch.setattr(f360, "proc_run", lambda *a, **k: _R())
    with pytest.raises(RuntimeError, match="未产出有效 dex"):
        f360.dump("com.foo", tmp_path, sleep=1, timeout=5)


def test_execute_360_passes_sleep_zero(monkeypatch, tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    captured = {}

    def fake_dump(package, out_dir, device=None, sleep=None, timeout=None):
        captured["sleep"] = sleep
        captured["timeout"] = timeout
        return []

    monkeypatch.setattr(f360, "dump", fake_dump)
    adapters.execute(
        "360", apk_path=None, package="x", out_dir=tmp_path,
        device=None, sleep=0, timeout=12,
    )
    assert captured["sleep"] == 0
    assert captured["timeout"] == 12


# ---------------------------------------------------------------------------
# 乐固 / 易盾：与 360 相同，frida-dexdump -f -d --sleep
# ---------------------------------------------------------------------------
def test_legu_and_yidun_dump_use_360_spawn(monkeypatch, tmp_path):
    from auto_unpack.unpacker import flow_360 as f360
    from auto_unpack.unpacker import flow_legu as fl
    from auto_unpack.unpacker import flow_netease as fy
    captured = []

    def fake_dump(package, out_dir, device=None, sleep=10, timeout=None,
                  vendor="360"):
        captured.append((package, sleep, timeout, vendor))
        return []

    monkeypatch.setattr(f360, "dump", fake_dump)
    fl.dump("com.legu", tmp_path, device=None, sleep=8, timeout=90)
    fy.dump("com.yidun", tmp_path, device=None, sleep=3, timeout=12)
    assert captured == [
        ("com.legu", 8, 90, "腾讯乐固"),
        ("com.yidun", 3, 12, "网易易盾"),
    ]


def test_execute_legu_and_yidun(monkeypatch, tmp_path):
    from auto_unpack.unpacker import flow_legu as fl
    from auto_unpack.unpacker import flow_netease as fy
    captured = []

    def fake_dump(package, out_dir, device=None, sleep=None, timeout=None):
        captured.append((package, sleep, timeout))
        return []

    monkeypatch.setattr(fl, "dump", fake_dump)
    monkeypatch.setattr(fy, "dump", fake_dump)
    adapters.execute(
        "legu", apk_path=None, package="a", out_dir=tmp_path,
        device=None, sleep=0, timeout=11,
    )
    adapters.execute(
        "yidun", apk_path=None, package="b", out_dir=tmp_path,
        device=None, sleep=3, timeout=12,
    )
    assert captured == [("a", 0, 11), ("b", 3, 12)]
