#!/usr/bin/env python3
"""dpt-shell 脱壳 flow：frida spawn + 加载 dpt_shell_dump.js + 接收 dex 写盘。

用法:
    py -3.10 -m auto_unpack.unpacker.flow_dpt_shell <包名> [-o 输出目录]
"""

from __future__ import annotations

import argparse
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
    """
    if not data or len(data) < MIN_DEX:
        return False
    if data[:4] not in (b"dex\n", b"dey\n"):
        return False
    file_size, header_size = struct.unpack_from("<II", data, 0x20)
    if header_size != MIN_DEX:
        return False
    if file_size != len(data):
        return False
    return True


def quarantine_invalid_dex(out_dir: Path) -> list[Path]:
    """把目录里已有的无效 dex_* 挪到 _invalid_dex/，返回被隔离的路径。"""
    junk_dir = out_dir / "_invalid_dex"
    moved: list[Path] = []
    for p in sorted(out_dir.glob("dex_*.dex")):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if is_valid_dumped_dex(data):
            continue
        junk_dir.mkdir(parents=True, exist_ok=True)
        dest = junk_dir / p.name
        if dest.exists():
            dest = junk_dir / (p.stem + "_" + str(p.stat().st_size) + p.suffix)
        p.replace(dest)
        moved.append(dest)
    return moved


def list_dumped_dex(out_dir: Path) -> list[Path]:
    return sorted(
        p for p in out_dir.glob("dex_*.dex")
        if p.is_file() and is_valid_dumped_dex(p.read_bytes())
    )


def _on_message(out_dir: Path, counter: dict):
    def handler(message, data):
        mtype = message.get("type")
        if mtype == "send":
            payload = message.get("payload") or {}
            if payload.get("type") == "dex":
                size = payload.get("size", 0)
                begin = payload.get("begin", "0")
                raw = data if isinstance(data, (bytes, bytearray)) else b""
                if size and len(raw) != size:
                    # Frida 大块 send 偶尔截断；截断的 dex 修不好
                    print(f"[!] 丢弃截断 dump begin={begin} 声称 {size} 实收 {len(raw)}")
                    counter["skip"] = counter.get("skip", 0) + 1
                    return
                if not is_valid_dumped_dex(bytes(raw)):
                    print(f"[!] 丢弃无效 dump begin={begin} ({len(raw)} bytes，非完整 dex)")
                    counter["skip"] = counter.get("skip", 0) + 1
                    return
                safe_begin = "".join(c for c in str(begin) if c.isalnum() or c in "._")
                name = f"dex_{safe_begin or 'unknown'}_{len(raw):x}.dex"
                (out_dir / name).write_bytes(raw)
                counter["n"] += 1
                print(f"[+] 保存 {name} ({len(raw)} bytes)")
            elif payload.get("type") == "log":
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
    """spawn + attach + 注入脚本，返回 (session, pid)。"""
    print(f"[*] spawn {package} ...")
    try:
        pid = dev.spawn([package])
    except Exception as e:
        msg = str(e).lower()
        if "not found" in msg or "notfound" in type(e).__name__.lower():
            raise RuntimeError(f"设备上找不到包 {package}，请先安装或检查包名") from e
        raise RuntimeError(f"spawn 失败: {e}") from e
    session = dev.attach(pid)
    script = session.create_script(script_path.read_text(encoding="utf-8"))
    script.on("message", _on_message(out_dir, counter))
    script.load()
    print("[*] 脚本已加载，resume app ...")
    dev.resume(pid)
    return session, pid


def _wait_for_dex(counter: dict, sleep: int) -> None:
    """至少等 12s（覆盖两次主动 loadClass），之后连续 5s 无新 dex 可提前结束。"""
    min_wait = 12
    deadline = time.time() + max(sleep, min_wait)
    t0 = time.time()
    idle = 0
    last_n = 0
    while time.time() < deadline:
        time.sleep(1)
        if counter["n"] == last_n:
            idle += 1
            if idle >= 5 and counter["n"] > 0 and (time.time() - t0) >= min_wait:
                break
        else:
            idle = 0
            last_n = counter["n"]


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
        try:
            proc_run(
                ["adb", "shell", "am", "force-stop", package],
                capture_output=True, timeout=8,
            )
        except Exception:
            pass


def dump(package: str, out_dir: Path, device: str | None = None,
         sleep: int = 20, kill: bool = True) -> list[Path]:
    """spawn 目标包，注入 dpt_shell_dump.js，把 dump 到的 dex 写到 out_dir。

    等到「sleep 秒用尽」或「已有产物且连续 5 秒没有新 dex」即结束。
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
        print(f"[*] 隔离无效 dump {len(moved)} 个 -> {out_dir / '_invalid_dex'}")
    from ..dex_utils import repair_dumped_dexes
    fixed = repair_dumped_dexes(out_dir)
    if fixed:
        print(f"[*] 已重算 {fixed} 个 dex 的 checksum/SHA-1（内存 dump 常见，JADX 可直接打开）")
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

    out_dir = Path(args.out) if args.out else Path(f"dpt_out_{args.package}")
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
