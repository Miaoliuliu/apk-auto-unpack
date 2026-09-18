#!/usr/bin/env python3
"""DEX 基础设施：头修复、校验和重算、从 APK/裸 dex 载入 DEX 对象。

只依赖 stdlib + androguard，不依赖包内任何其它模块——
壳识别与 URL 提取都从这里拿 dex 工具，避免两层互相 import。
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androguard.core.dex import DEX

_MAX_DEX_BYTES = 256 * 1024 * 1024
_MAX_TOTAL_DEX_BYTES = 512 * 1024 * 1024
_MAX_DEX_COMPRESSION_RATIO = 200
_MAX_DEX_ENTRIES = 1024

# monkey patch：androguard 4.1.4 的 HiddenApiClassDataItem.DomapiApiFlag 只定义 0-2，
# Android 13+ 的 dex 有 apiFlag=4/6 等新值，会抛 ValueError 导致整个 dex 解析失败
# （脱壳产物/高版本系统包的 dex 常见）。放这里而非 analyze.py，保证任何只 import
# dex_utils 的入口（auto-unpack-detect 等）也生效。analyze.py 里重复 patch 无害。
try:
    from androguard.core.dex import HiddenApiClassDataItem

    def _missing_domapi_flag(cls, value):
        if not isinstance(value, int):
            return None
        obj = int.__new__(cls, value)
        obj._name_ = "UNKNOWN_" + str(value)
        obj._value_ = value
        return obj

    HiddenApiClassDataItem.DomapiApiFlag._missing_ = classmethod(_missing_domapi_flag)
except Exception:
    pass


def fix_dex_header(data: bytes) -> bytes:
    """规范化 dex 头：修复 magic/size/endian，并重算 Adler32 校验和与 SHA-1 签名。

    脱壳产物（脱壳工具 / 重组工具）常带着损坏的校验和，androguard 的 DEX 解析
    会无条件校验 Adler32 并拒收，这里重算后即可正常解析。
    """
    if len(data) < 0x70:
        return data
    b = bytearray(data)
    if b[:4] != b"dex\n":
        b[:8] = b"dex\n035\x00"
    if b[0x28:0x2C] not in (b"\x78\x56\x34\x12", b"\x12\x34\x56\x78"):
        b[0x28:0x2C] = b"\x78\x56\x34\x12"  # 默认小端
    struct.pack_into("<I", b, 0x24, 0x70)  # header_size
    struct.pack_into("<I", b, 0x20, len(b))  # file_size
    b[0x0C:0x20] = hashlib.sha1(bytes(b[32:])).digest()  # signature = sha1(bytes[32:])
    struct.pack_into("<I", b, 0x08, zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF)  # checksum
    return bytes(b)


def purge_dump_sidecars(out_dir: Path | str) -> None:
    """删掉样本目录里的 raw/、_invalid_dex/，只留顶层修好的 dex。"""
    d = Path(out_dir)
    for name in ("raw", "_invalid_dex"):
        p = d / name
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)


def repair_dumped_dexes(out_dir: Path | str, keep_original: bool = False) -> int:
    """修复脱壳目录里损坏的 dex 头，返回写回了几个文件。

    直接覆盖写回；不保留原文件。keep_original 已废弃（忽略）。
    """
    del keep_original
    n = 0
    d = Path(out_dir)
    for p in sorted(d.glob("*.dex")):
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if len(data) < 0x70 or data[:4] != b"dex\n":
            continue
        file_size, header_size = struct.unpack_from("<II", data, 0x20)
        if header_size != 0x70 or file_size != len(data):
            continue
        fixed = fix_dex_header(data)
        if fixed == data:
            continue
        p.write_bytes(fixed)
        n += 1
    purge_dump_sidecars(d)
    return n


def _read_zip_entry(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[bytes | None, str]:
    """读 ZIP 条目。加密标志经常是假的（只改 GPBF bit0，载荷仍是普通 deflate）。

    JADX / Android 会忽略这根标志，所以 JADX 能看到实现，Python zipfile 却报 password。
    先清标志再 inflate；成功且像 dex 则当假加密；失败才是真加密。
    返回 (data, how)：ok / fake_encrypt / encrypted / error。
    """
    if not (info.flag_bits & 0x1):
        try:
            return z.read(info.filename), "ok"
        except Exception:
            return None, "error"
    old = info.flag_bits
    info.flag_bits = old & ~0x1
    try:
        data = z.read(info.filename)
        return data, "fake_encrypt"
    except Exception:
        return None, "encrypted"
    finally:
        info.flag_bits = old


# dex 头里各 id 段：(*_size 的偏移, 每条目字节数)
_DEX_ID_SECTIONS = (
    (0x38, 4),   # string_ids
    (0x40, 4),   # type_ids
    (0x48, 12),  # proto_ids
    (0x50, 8),   # field_ids
    (0x58, 8),   # method_ids
    (0x60, 32),  # class_defs
)


def dex_header_plausible(b: bytes) -> bool:
    """廉价头校验：id 段声明数量×条目长度必须落在文件范围内。

    黑产假 dex 诱饵会声明几十亿个 TYPE_ID——androguard 要解析到 map 阶段才拒绝
    （单个几秒，一批几百个就是几分钟）。合法 dex 的 id 段必然在文件内，
    这里读完头（64 字节）立刻否掉，把对抗样本的解析时间从分钟级压回秒级。
    """
    if len(b) < 0x70:
        return False
    n = len(b)
    for off, item in _DEX_ID_SECTIONS:
        size = int.from_bytes(b[off:off + 4], "little")
        if size == 0:
            continue
        base = int.from_bytes(b[off + 4:off + 8], "little")
        # 段体必须位于 header 之后且整体落在文件内，否则按畸形拒绝。
        if base < 0x70 or base >= n or size > (n - base) // item:
            return False
    return True


def _parse_bare_dex(data: bytes, p: Path, stats: dict | None) -> list[tuple[str, "DEX"]]:
    """裸 dex（非 zip）解析：廉价头校验拒收诱饵，再修复校验和载入。"""
    from androguard.core.dex import DEX

    # 裸 dex 同样可能被诱饵污染：进 androguard 前先做廉价头校验，
    # 声明异常（id 段越界）直接拒收，不给 DEX() 逐段解析的机会。
    if not dex_header_plausible(data):
        if stats is not None:
            stats["malformed_dex"] = [p.name]
        return []
    try:
        return [("classes.dex", DEX(fix_dex_header(data)))]
    except Exception as e:
        if stats is not None:
            stats["parse_failed"] = [(p.name, str(e))]
        return []


def _report_dex_summary(
    skipped: int, invalid_magic: int, fake_zip_encrypt: list[str],
    encrypted_dex: list[str], malformed_dex: list[str],
    parse_failed: list[tuple[str, str]],
) -> None:
    """聚合打印解析跳过统计（逐文件警告会刷屏淹没批量日志）。"""
    if skipped:
        print(f"[提示] 跳过 {skipped} 个假 dex 诱饵（非 ASCII 路径）", file=sys.stderr)
    if invalid_magic:
        print(
            f"[提示] 跳过 {invalid_magic} 个无标准 DEX 文件头的载荷",
            file=sys.stderr,
        )
    if fake_zip_encrypt:
        print(
            f"[提示] {len(fake_zip_encrypt)} 个 dex 带假 ZIP 加密标志，已按普通条目解析",
            file=sys.stderr,
        )
    if encrypted_dex:
        print(
            f"[提示] 跳过 {len(encrypted_dex)} 个无法解开的 ZIP 加密 dex 条目",
            file=sys.stderr,
        )
    if malformed_dex:
        print(
            f"[提示] 跳过 {len(malformed_dex)} 个声明异常的假 dex（id 段越界，未逐个解析）",
            file=sys.stderr,
        )
    if parse_failed:
        first_name, first_err = parse_failed[0]
        print(
            f"[提示] {len(parse_failed)} 个 dex 解析失败已跳过"
            f"（首个: {first_name}: {first_err}）",
            file=sys.stderr,
        )


def _parse_zip_dexes(p: Path, stats: dict | None) -> list[tuple[str, "DEX"]]:
    """解析 APK（zip）内 .dex 条目，对抗假诱饵/假加密/加密 dex。"""
    from androguard.core.dex import DEX

    out: list[tuple[str, "DEX"]] = []
    skipped = 0
    invalid_magic = 0
    encrypted_dex: list[str] = []
    fake_zip_encrypt: list[str] = []
    malformed_dex: list[str] = []
    parse_failed: list[tuple[str, str]] = []
    total_dex_bytes = 0
    with zipfile.ZipFile(str(p)) as z:
        dex_names = [dn for dn in z.namelist() if dn.endswith(".dex")]
        dex_names.sort(key=lambda n: (Path(n).name != "classes.dex", n))
        if len(dex_names) > _MAX_DEX_ENTRIES:
            if stats is not None:
                stats.setdefault("source_skipped", []).append({
                    "source": "dex",
                    "file": p.name,
                    "reason": f"dex_entry_limit:{len(dex_names)}>{_MAX_DEX_ENTRIES}",
                })
            dex_names = dex_names[:_MAX_DEX_ENTRIES]
        for dn in dex_names:
            # 假 dex 诱饵（非 ASCII 路径，阿拉伯语乱码）：跳过不解析，大幅提速。
            # 实测黑产 APK 一个含几百个此类诱饵，逐个 DEX() 解析是全批扫描的瓶颈。
            if any(ord(c) > 127 for c in dn):
                skipped += 1
                continue
            info = z.getinfo(dn)
            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > _MAX_DEX_BYTES:
                if stats is not None:
                    stats.setdefault("source_skipped", []).append({
                        "source": "dex", "file": dn, "reason": "member_too_large",
                    })
                continue
            if ratio > _MAX_DEX_COMPRESSION_RATIO:
                if stats is not None:
                    stats.setdefault("source_skipped", []).append({
                        "source": "dex", "file": dn,
                        "reason": "compression_ratio_exceeded",
                    })
                continue
            if total_dex_bytes + info.file_size > _MAX_TOTAL_DEX_BYTES:
                if stats is not None:
                    stats.setdefault("source_skipped", []).append({
                        "source": "dex", "file": dn, "reason": "byte_budget_exhausted",
                    })
                continue
            total_dex_bytes += info.file_size
            raw, how = _read_zip_entry(z, info)
            if how == "fake_encrypt":
                fake_zip_encrypt.append(dn)
            if raw is None:
                encrypted_dex.append(dn)
                continue
            # 伪装成 .dex 的加密/压缩载荷不应交给 Androguard 解析。
            # 否则会产生诸如 TYPE_ID 数十亿的误导性异常，且拖慢批量识别。
            if not (raw.startswith(b"dex\n") or raw.startswith(b"dey\n")):
                invalid_magic += 1
                if how == "fake_encrypt":
                    # 清标志后仍不是 dex：当真正读不出
                    encrypted_dex.append(dn)
                continue
            # 诱饵/损坏 dex 在进 androguard 前否掉（否则单个解析就要几秒）。
            # 头校验只读 id 段声明（O(1)），不依赖 fix_dex_header 的 magic/校验和
            # 修复，所以放在最前：命中即跳过，连全文件 sha1/adler32 都不用算。
            if not dex_header_plausible(raw):
                malformed_dex.append(dn)
                continue
            fixed = fix_dex_header(raw)
            try:
                out.append((dn, DEX(fixed)))
            except Exception as e:
                # 逐文件警告刷屏会淹没批量日志，改成聚合计数，最后统一打一行。
                parse_failed.append((dn, str(e)))
    _report_dex_summary(
        skipped, invalid_magic, fake_zip_encrypt,
        encrypted_dex, malformed_dex, parse_failed,
    )
    if stats is not None:
        stats["encrypted_dex"] = encrypted_dex
        stats["fake_zip_encrypt"] = fake_zip_encrypt
        stats["skipped"] = skipped
        stats["invalid_magic"] = invalid_magic
        stats["malformed_dex"] = malformed_dex
        stats["parse_failed"] = parse_failed
    return out


def parse_dexes(path: str, *, stats: dict | None = None) -> list[tuple[str, "DEX"]]:
    """解析 APK 或裸 dex，返回 [(dex 名, DEX 对象)]。裸 dex 会先修复校验和。

    stats 可选，写入 encrypted_dex / fake_zip_encrypt / skipped / invalid_magic /
    malformed_dex / parse_failed。
    """
    p = Path(path)
    with p.open("rb") as fh:
        head = fh.read(4)
    if head in (b"dex\n", b"dey\n"):
        if p.stat().st_size > _MAX_DEX_BYTES:
            if stats is not None:
                stats.setdefault("source_skipped", []).append({
                    "source": "dex", "file": p.name, "reason": "member_too_large",
                })
            return []
        data = p.read_bytes()
        return _parse_bare_dex(data, p, stats)
    if not head.startswith(b"PK"):
        print(f"[警告] 不是 dex 也不是 zip，跳过: {p.name}", file=sys.stderr)
        return []
    return _parse_zip_dexes(p, stats)
