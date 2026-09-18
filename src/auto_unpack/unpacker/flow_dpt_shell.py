#!/usr/bin/env python3
"""dpt-shell 脱壳 flow：frida spawn + 加载 dpt_shell_dump.js + 接收 dex 写盘。

用法:
    py -3.10 -m auto_unpack.unpacker.flow_dpt_shell <包名> [-o 输出目录]

协议要点（与 dpt_shell_dump.js 保持一致）:
  - payload type=dex            单块完整 dex（小文件直发）
  - payload type=dex-begin/chunk  大 dex 分块发送（4MB/块），Python 端按 begin 重组
  - payload round               dump 轮次：1=hook onEnter 首轮，2=主动重扫补捞
    dpt 的指令回填发生在 LoadMethod 过程中，首轮可能抓到未回填的抽取态；
    重扫轮允许对同一 DexFile 再 dump 一次，Python 端按方法体空占比择优保留。
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
import time
from pathlib import Path

from ..runtime.proc import run as proc_run

MIN_DEX = 0x70

# 与 dpt_shell_dump.js dexFileArgIndex 一致：C++ this 占 args[0]
_DEFINE_CLASS_DEX_ARG = 5
_LOADMETHOD_WITH_THREAD_DEX_ARG = 2
_LOADMETHOD_NO_THREAD_DEX_ARG = 1


def dex_file_arg_index(mangled: str) -> int:
    """由 Itanium 符号名得到 ARM64 上 DexFile 参数下标。扫错会把 ArtMethod* 写成假 dex。"""
    if "DefineClass" in mangled:
        return _DEFINE_CLASS_DEX_ARG
    if "LoadMethod" in mangled:
        if "LoadMethodERKNS_7DexFile" in mangled:
            return _LOADMETHOD_NO_THREAD_DEX_ARG
        return _LOADMETHOD_WITH_THREAD_DEX_ARG
    return -1


def is_valid_dumped_dex(data: bytes) -> bool:
    """写出/分析前的硬校验：magic + header_size + file_size 与字节数一致。

    hook 曾把 DefineClass/LoadMethod 的非 DexFile 参数误当成结构体读。
    现只读符号对应的 DexFile 参数，并校验 magic + header。
    dey/vdex 不收：其 file_size 语义与 dex 不同，repair_dumped_dexes 也不处理，
    放行只会产出永远修不好的文件。
    """
    if not data or len(data) < MIN_DEX:
        return False
    if data[:4] != b"dex\n":
        return False
    file_size, header_size = struct.unpack_from("<II", data, 0x20)
    if header_size != MIN_DEX:
        return False
    if file_size != len(data):
        return False
    return True


def dex_class_data_truncated(data: bytes) -> bool:
    """class_defs / data 段已经读穿 EOF（截断 dump）。无法判定则 False。

    和「尾部多一截内存」不是一回事：绘本那种 map 后面有邻近区块残片、
    但指针仍在文件内，本函数返回 False，不能当剔除条件。
    只拦 class_data_off 或 data_off+data_size 已经越出文件的——JADX-GUI
    1.5.5 对这种文件建包树会 NPE（ClassNode 为 null）。
    """
    if not data or len(data) < MIN_DEX:
        return False
    n = len(data)
    ncls, cdef_off = struct.unpack_from("<II", data, 0x60)
    data_size, data_off = struct.unpack_from("<II", data, 0x68)
    # 测试夹具 / 空表：class_defs 不在 header 之后，不能按真实 dex 判定
    if ncls <= 0 or cdef_off < MIN_DEX:
        return False
    if cdef_off + ncls * 32 > n:
        return True
    if data_size and data_off + data_size > n:
        return True
    for i in range(ncls):
        cd = struct.unpack_from("<I", data, cdef_off + i * 32 + 24)[0]
        if cd != 0 and cd >= n:
            return True
    return False


def purge_truncated_dex(out_dir: Path, pattern: str = "*.dex") -> list[Path]:
    """删除 class_data 越界的截断 dump，返回被删路径。"""
    discarded: list[Path] = []
    for p in sorted(Path(out_dir).glob(pattern)):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if not dex_class_data_truncated(data):
            continue
        p.unlink(missing_ok=True)
        discarded.append(p)
    return discarded


# 可疑 dump 的告警阈值（仅用于提示，不作为移走依据）。
#
# 重要：曾用「map_off 与 file_size 不一致算出的冗余量」作为污染判据并在
# quarantine 中主动移走文件，实测证明**会严重误伤**：
#   全样本 767 个有效 dex 中命中 126 个（16.4%），其中绘本 252 个里 98 个
#   （38.9%）被错判，而这些 dex 的 class_defs 完全正常（88~331）、jadx 可解析。
#   根因：这批 dump 产物的「冗余区」并非零填充，而是内存中邻近 dex 结构的
#   残片（含大量 dex\n035 标记）。它是 frida-dexdump 深度搜索的**通用形态**，
#   不是可安全剔除的垃圾 —— 移走等于丢产物。
# 结论：冗余量只能作诊断信息，主动移除只依赖相对判定（参见 dedupe_dumped_dex）。
_SMALL_CLASS_DEFS = 10          # class_defs 少于此值…
_LARGE_FILE_BYTES = 100 * 1024  # …而体积超过此值 → 体积与内容不相称，可疑


def dex_redundant_bytes(data: bytes) -> int | None:
    """返回 dex 末尾冗余字节数（头部 map_list 未覆盖的尾部），无法判定则 None。

    依据：干净 dex 的 map_off 指向 map_list，其末项紧邻文件尾。
    注意：实测大量**正常可用**的 dump 产物也带大冗余（内存邻近区块残片），
    因此本函数的返回值**只能作诊断**，不可据此判定文件无用或移走。
    """
    if len(data) < MIN_DEX or data[:4] != b"dex\n":
        return None
    file_size, header_size = struct.unpack_from("<II", data, 0x20)
    if header_size != MIN_DEX or file_size != len(data):
        return None
    map_off = struct.unpack_from("<I", data, 0x34)[0]
    if map_off == 0 or map_off + 16 > file_size:
        return None
    return file_size - (map_off + 16)


def has_embedded_dex_marker(data: bytes) -> bool:
    """尾部冗余区是否含内嵌 'dex\\n035/036' 标记（内存邻近 dex 的头部残片）。

    仅作诊断：实测正常产物也普遍含此标记（绘本 classes158 含 21 处），
    不构成「文件无用」的证据。
    """
    if len(data) < MIN_DEX or data[:4] != b"dex\n":
        return False
    map_off = struct.unpack_from("<I", data, 0x34)[0]
    start = max(map_off + 16, MIN_DEX)
    return data.find(b"dex\n035\x00", start) != -1 or data.find(b"dex\n036\x00", start) != -1


def is_suspect_dumped_dex(data: bytes) -> bool:
    """体积与内容不相称的**可疑** dump（空壳靠体积伪装），仅用于告警。

    判据：class_defs < 10 且体积 > 100KB。典型如 ADIA/classes08.dex
    （17.9MB / 4 个类，内容等同 9884B 的 classes07.dex）。

    本函数**不参与主动移除**：它会命中少量可能仍有价值的产物
    （实测全样本 19 个，如绘本 classes48.dex 20.5MB / 1 个类），
    故只输出提示，由人去判断。主动移除只走 dedupe_dumped_dex 的相对判定。
    """
    if not is_valid_dumped_dex(data):
        return False
    class_defs = struct.unpack_from("<I", data, 0x60)[0]
    return class_defs < _SMALL_CLASS_DEFS and len(data) > _LARGE_FILE_BYTES


def warn_suspect_dumped_dex(out_dir: Path, pattern: str = "*.dex") -> list[Path]:
    """扫描体积与内容不相称的 dump 并打印告警，返回命中路径（不移走任何文件）。"""
    suspects: list[Path] = []
    for p in sorted(out_dir.glob(pattern)):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if is_suspect_dumped_dex(data):
            suspects.append(p)
    if suspects:
        print(f"[提示] {len(suspects)} 个体积与内容不相称的 dump"
              f"（class_defs < {_SMALL_CLASS_DEFS} 而体积 > "
              f"{_LARGE_FILE_BYTES // 1024}KB），建议人工确认是否空壳伪装：")
        for p in suspects[:5]:
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            print(f"        {p.name}  {size / 1048576:.1f}MB")
        if len(suspects) > 5:
            print(f"        ... 其余 {len(suspects) - 5} 个")
    return suspects


_DEX_MAGICS = tuple(b"dex\n%03d\x00" % v for v in range(35, 41))
_MIN_REDUNDANCY_BYTES = 64 * 1024   # 冗余小于此值视为真重复（无独立数据）


def redundancy_holds_unique_data(data: bytes) -> bool:
    """冗余区是否可能含**别处拿不到**的数据（不得移走）。

    实测两类 dump 形态（全样本 278 个待去重副本统计）：
      A. 真重复/小冗余（冗余 < 64KB）        —— 149 个，移走安全
      B. 拼接体（冗余区含明文 dex 头）        —— 106 个，内嵌 dex 必有独立文件，移走安全
      C. 冗余区无 dex 头且非全零              —— 23 个，**疑为加密源 dex，移走即丢数据**

    形态 C 的实证：民信贷 classes06.dex 的 9.67MB 冗余区无任何 dex\\n 标记，
    却含 1405 个明文类描述符（含 com/bobo/db/HistoryDatabase 等 18 个业务类）。
    这与 Frezrik/Jiagu 加固方案吻合 —— 壳dex + 源dex 拼接，源 dex 前 512 字节
    被 AES 加密（因此 magic 不可见），其后 type_ids 表仍为明文。
    该加密源 dex 是**唯一副本**，移走等于丢失解密素材。
    """
    if not is_valid_dumped_dex(data):
        return False
    file_size, map_off = struct.unpack_from("<I", data, 0x20)[0], \
        struct.unpack_from("<I", data, 0x34)[0]
    if not map_off or map_off + 16 >= file_size:
        return False
    tail = data[map_off + 16:]
    if len(tail) < _MIN_REDUNDANCY_BYTES:
        return False                      # 小冗余 → 真重复
    if tail.count(0) == len(tail):
        return False                      # 全零 → 无可读数据
    if any(m in tail for m in _DEX_MAGICS):
        return False                      # 含明文 dex 头 → 内嵌 dex 有独立文件
    return True                           # 无 dex 头且非全零 → 疑加密源 dex


def dedupe_dumped_dex(out_dir: Path, pattern: str = "*.dex") -> list[Path]:
    """按 dex 头部元组去重，同组只保留体积最小者，其余删除。

    键取 (string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs,
    data_size, data_off, map_off)——同一份代码的不同 dump 边界只改物理字节数、
    不改这些字段，因此会被归入同组。

    **重要**：头部相同不代表尾部无价值。若较大副本的冗余区疑似加密源 dex
    （见 redundancy_holds_unique_data），则**不移动**它 —— 移走会丢失解密素材。
    实测全样本 278 个待去重副本中有 23 个属于此类（含民信贷 classes06.dex 的
    9.2MB 加密源 dex、ADIA classes08.dex 等）。

    pattern 需按流程产出命名传：
      - flow_dpt_shell（自研 hook）产出 dex_*.dex
      - flow_360（frida-dexdump）产出 classes*.dex，应传 "classes*.dex"
    只处理 out_dir 顶层。返回被删除的路径。
    """
    groups: dict[tuple, list[Path]] = {}
    for p in sorted(out_dir.glob(pattern)):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if not is_valid_dumped_dex(data):
            continue
        key = (
            *struct.unpack_from("<IIIIII", data, 0x38),  # string/type/proto/field/method/class
            *struct.unpack_from("<II", data, 0x68),      # data_size / data_off
            struct.unpack_from("<I", data, 0x34)[0],     # map_off
        )
        groups.setdefault(key, []).append(p)

    discarded: list[Path] = []
    kept: list[Path] = []
    for paths in groups.values():
        if len(paths) < 2:
            continue
        paths.sort(key=lambda q: (q.stat().st_size, q.name))
        for dup in paths[1:]:
            try:
                data = dup.read_bytes()
            except OSError:
                continue
            if redundancy_holds_unique_data(data):
                kept.append(dup)          # 保留：可能含唯一的加密源 dex
                continue
            dup.unlink(missing_ok=True)
            discarded.append(dup)
    if kept:
        print(f"[提示] 保留 {len(kept)} 个疑似含加密源 dex 的副本（移走会丢数据）：")
        for p in kept[:5]:
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            print(f"        {p.name}  {size / 1048576:.1f}MB")
        if len(kept) > 5:
            print(f"        ... 其余 {len(kept) - 5} 个")
    return discarded



def quarantine_invalid_dex(out_dir: Path) -> list[Path]:
    """删除目录里无效的 dex_*，返回被删路径。

    只按 is_valid_dumped_dex 硬校验判定，不做启发式剔除（理由见
    is_suspect_dumped_dex 的说明）。
    """
    discarded: list[Path] = []
    for p in sorted(out_dir.glob("dex_*.dex")):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if is_valid_dumped_dex(data):
            continue
        p.unlink(missing_ok=True)
        discarded.append(p)
    return discarded


def list_dumped_dex(out_dir: Path) -> list[Path]:
    return sorted(
        p for p in out_dir.glob("dex_*.dex")
        if p.is_file() and is_valid_dumped_dex(p.read_bytes())
    )


def _keep_best_dumps(out_dir: Path) -> int:
    """同 begin 多轮 dump 择优：方法体空占比低的留下，其余删除。

    dpt 回填发生在 LoadMethod 过程中，首轮 onEnter 抓到的可能是未回填的
    抽取态；重扫轮（_r2）大概率已是回填态。两组并存时按质量保留，
    避免 U1 竞态把抽取态 dex 锁死成最终产物。
    """
    from ..packer.packer_sigs import analyze_dex_structure

    groups: dict[str, list[Path]] = {}
    for p in list_dumped_dex(out_dir):
        # 文件名: dex_{begin}_{size:x}[_r{n}].dex；begin 是十六进制地址，不含下划线
        parts = p.stem.split("_")
        if len(parts) >= 3 and parts[1]:
            groups.setdefault(parts[1], []).append(p)
    moved = 0
    for paths in groups.values():
        if len(paths) < 2:
            continue
        scored = []
        for p in paths:
            try:
                info = analyze_dex_structure(str(p))
                rows = info.get("dex") or [{}]
                ratio = float(rows[0].get("shell_ratio") or 0.0)
            except Exception:
                ratio = 2.0  # 解析失败的 dump 视作最差，让位给可解析副本
            scored.append((ratio, p.name, p))
        scored.sort(key=lambda t: (t[0], t[1]))
        for ratio, _, p in scored[1:]:
            p.unlink(missing_ok=True)
            moved += 1
            print(f"[*] 同源多轮 dump 择优: 删除 {p.name}（空占比 {ratio:.1%} 较高）")
    return moved


class _ChunkAssembler:
    """U9：Frida 单次 send 大 buffer 易截断，JS 端对大 dex 分块发送，这里按 begin 重组。

    按 chunk 序号（seq）落位，而不是依赖到达顺序：Frida 单线程内 send 有序，
    但显式按 seq 组装能防住未来改动引入的乱序；同时能识别缺块 —— 缺块无法重组成
    合法 dex，必须丢弃，否则该 begin 的缓冲区会常驻泄漏。
    """

    def __init__(self):
        self._meta: dict[str, dict] = {}
        self._chunks: dict[str, dict[int, bytes]] = {}
        self.errors: list[str] = []

    def feed(self, payload: dict, data) -> tuple[str, bytes, int] | None:
        """喂入一个 chunk；所有块到齐时返回 (begin, 完整字节, round)，否则 None。

        无法重组的异常记入 self.errors（由调用方打印），并就地丢弃该 begin。
        """
        begin = str(payload.get("begin"))
        ptype = payload.get("type")
        if ptype == "dex-begin":
            total = int(payload.get("chunks") or 0)
            size = int(payload.get("size") or 0)
            if total <= 0 or size <= 0:
                return None
            self._meta[begin] = {
                "chunks": total,
                "size": size,
                "round": int(payload.get("round") or 1),
            }
            self._chunks[begin] = {}
            return None
        if ptype == "dex-chunk":
            if begin not in self._meta:
                self.errors.append(f"chunk 无对应 dex-begin，忽略 begin={begin}")
                return None
            if data is None:
                # 缺块 → 拼不出合法 dex，丢弃以免缓冲区常驻
                self._drop(begin)
                self.errors.append(f"chunk 数据为空，丢弃 begin={begin}")
                return None
            seq = int(payload.get("seq") or 0)
            self._chunks[begin][seq] = bytes(data)
            meta = self._meta[begin]
            want = int(meta["chunks"])
            if len(self._chunks[begin]) < want:
                return None
            missing = [i for i in range(want) if i not in self._chunks[begin]]
            if missing:
                self._drop(begin)
                self.errors.append(f"缺块 {missing}，丢弃 begin={begin}")
                return None
            full = b"".join(self._chunks[begin][i] for i in range(want))
            round_no = int(meta["round"])
            size = int(meta["size"])
            self._drop(begin)
            if len(full) != size:
                self.errors.append(
                    f"重组长度不符 begin={begin}：声明 {size} 实得 {len(full)}")
            return begin, full, round_no
        return None

    def _drop(self, begin: str) -> None:
        self._meta.pop(begin, None)
        self._chunks.pop(begin, None)


def _on_message(out_dir: Path, counter: dict):
    assembler = _ChunkAssembler()

    def _save(begin, raw: bytes, rnd: int):
        if not is_valid_dumped_dex(bytes(raw)):
            print(f"[!] 丢弃无效 dump begin={begin} 轮次={rnd} ({len(raw)} bytes，非完整 dex)")
            counter["skip"] = counter.get("skip", 0) + 1
            return
        safe_begin = "".join(c for c in str(begin) if c.isalnum() or c in "._")
        suffix = f"_r{rnd}" if rnd > 1 else ""
        name = f"dex_{safe_begin or 'unknown'}_{len(raw):x}{suffix}.dex"
        (out_dir / name).write_bytes(raw)
        counter["n"] += 1
        print(f"[+] 保存 {name} ({len(raw)} bytes)")

    def handler(message, data):
        mtype = message.get("type")
        if mtype == "send":
            payload = message.get("payload") or {}
            ptype = payload.get("type")
            raw = data if isinstance(data, (bytes, bytearray)) else b""
            if ptype == "dex":
                size = payload.get("size", 0)
                if size and len(raw) != size:
                    # Frida 大块 send 偶尔截断；截断的 dex 修不好
                    print(f"[!] 丢弃截断 dump begin={payload.get('begin')} "
                          f"声称 {size} 实收 {len(raw)}")
                    counter["skip"] = counter.get("skip", 0) + 1
                    return
                _save(payload.get("begin", "0"), raw, int(payload.get("round") or 1))
            elif ptype in ("dex-begin", "dex-chunk"):
                got = assembler.feed(payload, raw if raw else None)
                if got:
                    begin, full, rnd = got
                    _save(begin, full, rnd)
                while assembler.errors:
                    print(f"[!] 分块重组: {assembler.errors.pop(0)}")
            elif ptype == "log":
                print(f"[js] {payload.get('msg', payload)}")
        elif mtype == "error":
            print(f"[!] 脚本错误: {message.get('stack') or message.get('description')}")
        elif mtype == "log":
            print(f"[js] {message.get('payload')}")
        else:
            print(f"[msg] {message}")
    return handler


def _get_device(device_id: str | None):
    import frida
    try:
        if device_id:
            return frida.get_device(device_id)
        return frida.get_usb_device(timeout=10)
    except Exception as e:
        raise RuntimeError(f"找不到 Frida 设备: {e}（请确认 USB 调试已开且 frida-server 在跑）") from e


ADAPTER = "dpt-shell"


def _spawn_and_load(dev, package: str, script_path: Path, out_dir: Path, counter: dict):
    """spawn + attach + 注入脚本，返回 (session, pid)。

    attach/create_script/load 任一步失败时，目标进程仍处于 spawn suspended 态，
    必须就地 detach+kill 回收，否则进程永远挂着（U3）。
    """
    print(f"[*] spawn {package} ...")
    try:
        pid = dev.spawn([package])
    except Exception as e:
        msg = str(e).lower()
        if "not found" in msg or "notfound" in type(e).__name__.lower():
            raise RuntimeError(f"设备上找不到包 {package}，请先安装或检查包名") from e
        raise RuntimeError(f"spawn 失败: {e}") from e
    session = None
    try:
        session = dev.attach(pid)
        script = session.create_script(script_path.read_text(encoding="utf-8"))
        script.on("message", _on_message(out_dir, counter))
        script.load()
    except Exception:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        try:
            dev.kill(pid)
        except Exception:
            pass
        raise
    print("[*] 脚本已加载，resume app ...")
    dev.resume(pid)
    return session, pid


def _wait_for_dex(counter: dict, sleep: int) -> None:
    """至少等 30s（覆盖 JS 三轮主动 loadClass 与慢启动解密注入），
    之后连续 8s 无新 dex 可提前结束。min_wait 过短会在业务 dex 解密
    注入前收尾，只留下 stub 产物（U2）。"""
    min_wait = 30
    deadline = time.time() + max(sleep, min_wait)
    t0 = time.time()
    idle = 0
    last_n = 0
    while time.time() < deadline:
        time.sleep(1)
        if counter["n"] == last_n:
            idle += 1
            if idle >= 8 and counter["n"] > 0 and (time.time() - t0) >= min_wait:
                break
        else:
            idle = 0
            last_n = counter["n"]


def _find_adb() -> str | None:
    """force-stop fallback 用的 adb：XJB_ADB → ADB → PATH；找不到返回 None。"""
    for var in ("XJB_ADB", "ADB"):
        p = os.environ.get(var)
        if p and Path(p).exists():
            return p
    return shutil.which("adb")


def _cleanup(session, pid, dev, kill: bool, package: str) -> None:
    """detach/kill 在 loadClass 全量触发时可能卡住，限时后交给 adb force-stop。"""
    def _close():
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if kill and pid is not None:
            try:
                dev.kill(pid)
            except Exception:
                pass

    import threading
    t = threading.Thread(target=_close, daemon=True)
    t.start()
    t.join(5)
    if t.is_alive() and kill:
        adb = _find_adb()
        if not adb:
            return
        try:
            proc_run(
                [adb, "shell", "am", "force-stop", package],
                capture_output=True, timeout=8,
            )
        except Exception:
            pass


def dump(package: str, out_dir: Path, device: str | None = None,
         sleep: int = 20, kill: bool = True) -> list[Path]:
    """spawn 目标包，注入 dpt_shell_dump.js，把 dump 到的 dex 写到 out_dir。

    等到「sleep 秒用尽」或「已有产物且连续 8 秒没有新 dex」即结束。
    结束后：删除无效 dump → 同 begin 多轮择优 → 修复 checksum/SHA-1。
    返回写出的 dex 路径列表。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    counter = {"n": 0, "skip": 0}

    script_path = Path(__file__).parent / "dpt_shell_dump.js"
    if not script_path.exists():
        raise RuntimeError(f"找不到注入脚本: {script_path}")

    dev = _get_device(device)
    session = None
    pid = None
    try:
        session, pid = _spawn_and_load(dev, package, script_path, out_dir, counter)
        _wait_for_dex(counter, sleep)
    finally:
        _cleanup(session, pid, dev, kill, package)

    moved = quarantine_invalid_dex(out_dir)
    if moved:
        print(f"[*] 删除无效 dump {len(moved)} 个")
    trunc = purge_truncated_dex(out_dir, pattern="dex_*.dex")
    if trunc:
        print(f"[*] 删除截断 dump {len(trunc)} 个（class_data 越界）")
    # 顺序要紧：先按质量择优（多轮 dump 里保留回填态），再做同源去重。
    # 反过来的话，去重会按体积取小，可能先移走质量更好的回填态副本。
    superseded = _keep_best_dumps(out_dir)
    if superseded:
        print(f"[*] 多轮 dump 择优淘汰 {superseded} 个抽取态副本")
    dup = dedupe_dumped_dex(out_dir, pattern="dex_*.dex")
    if dup:
        print(f"[*] 删除同源边界副本 {len(dup)} 个")
    warn_suspect_dumped_dex(out_dir, pattern="dex_*.dex")
    from ..dex_utils import purge_dump_sidecars, repair_dumped_dexes
    fixed = repair_dumped_dexes(out_dir)
    if fixed:
        print(f"[*] 已重算 {fixed} 个 dex 的 checksum/SHA-1（内存 dump 常见，JADX 可直接打开）")
    purge_dump_sidecars(out_dir)
    dexes = list_dumped_dex(out_dir)
    skipped = counter.get("skip", 0)
    extra = f"（丢弃 {skipped} 个无效）" if skipped else ""
    print(f"\n[*] dump 结束: {len(dexes)} 个有效 dex -> {out_dir}{extra}")
    if not dexes:
        raise RuntimeError(
            f"未 dump 到任何 dex（目录 {out_dir}）。"
            "常见原因: frida 被杀、DefineClass 符号对不上、或应用秒退"
        )
    return dexes


def main() -> int:
    parser = argparse.ArgumentParser(description="dpt-shell 脱壳")
    parser.add_argument("package", help="目标包名")
    parser.add_argument("-o", "--out", default=None, help="输出目录")
    parser.add_argument("--device", help="覆盖 env.json 的 device")
    parser.add_argument("--sleep", type=int, default=None, help="覆盖 env.json 的 sleep")
    parser.add_argument("--keep", action="store_true", help="结束后不杀进程")
    args = parser.parse_args()

    out_dir = (Path(args.out) if args.out
               else Path("outputs/unpacked_dex") / args.package)
    try:
        from ..runtime.env import describe, resolve
        cfg = resolve(device=args.device, sleep=args.sleep)
        print(f"[*] 环境: {describe(cfg)}")
        dump(args.package, out_dir, device=cfg["device"], sleep=cfg["sleep"], kill=not args.keep)
    except Exception as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
