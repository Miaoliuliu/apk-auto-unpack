"""厂商壳共用 dump：frida-dexdump spawn + 深度搜索。

360 / 乐固 / 易盾走同一条命令：
  frida-dexdump -U -f <包名> -d -o <目录> --sleep <秒>

官方 CLI（hluwa/frida-dexdump 2.0.1）：
  -f / --file         spawn 目标包
  -d / --deep-search  深度搜索（模糊找残缺头 dex）
  --sleep             spawn 后等待再 dump
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..runtime.proc import run as proc_run
from .flow_dpt_shell import is_valid_dumped_dex

ADAPTER = "360"
_DEFAULT_SLEEP = 10
_DEFAULT_TIMEOUT = 300


def find_frida_dexdump() -> str:
    """定位 frida-dexdump：环境变量 → PATH → 当前解释器 Scripts。"""
    for var in ("AUTO_UNPACK_FRIDA_DEXDUMP", "FRIDA_DEXDUMP"):
        raw = os.environ.get(var)
        if raw and Path(raw).is_file():
            return raw
    found = shutil.which("frida-dexdump")
    if found:
        return found
    scripts_dir = Path(sys.executable).parent / "Scripts"
    for name in ("frida-dexdump.exe", "frida-dexdump"):
        cand = scripts_dir / name
        if cand.is_file():
            return str(cand)
    raise RuntimeError(
        "找不到 frida-dexdump。请用系统 Python 3.10 安装: pip install frida-dexdump"
    )


def build_dexdump_cmd(
    *,
    exe: str,
    package: str,
    out_dir: Path,
    device: str | None,
    sleep: int | None,
) -> list[str]:
    """组装 frida-dexdump 命令。始终带 -d（深度搜索），用 -f spawn 包名。"""
    cmd = [exe]
    if device:
        cmd += ["-D", str(device)]
    else:
        cmd += ["-U"]
    cmd += ["-f", package, "-d", "-o", str(out_dir)]
    if sleep is not None:
        cmd += ["--sleep", str(int(sleep))]
    return cmd


def list_dumped_dex(out_dir: Path) -> list[Path]:
    """收集输出目录顶层有效 dex（frida-dexdump 写 classes.dex / classes02.dex）。"""
    return sorted(
        p for p in Path(out_dir).glob("*.dex")
        if p.is_file() and is_valid_dumped_dex(p.read_bytes())
    )


def quarantine_invalid_dex(out_dir: Path) -> list[Path]:
    """把顶层无效 *.dex 挪到 _invalid_dex/。"""
    junk_dir = Path(out_dir) / "_invalid_dex"
    moved: list[Path] = []
    for p in sorted(Path(out_dir).glob("*.dex")):
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


def _force_stop(package: str, device: str | None) -> None:
    adb = shutil.which("adb")
    if not adb:
        return
    cmd = [adb]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "am", "force-stop", package]
    try:
        proc_run(cmd, capture_output=True, timeout=8)
    except Exception:
        pass


def dump(
    package: str,
    out_dir: Path,
    device: str | None = None,
    sleep: int = _DEFAULT_SLEEP,
    timeout: int | None = None,
    vendor: str = "360",
) -> list[Path]:
    """spawn 目标包，frida-dexdump -f -d 深度搜索，把 dex 写到 out_dir。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = find_frida_dexdump()
    cmd = build_dexdump_cmd(
        exe=exe, package=package, out_dir=out_dir, device=device, sleep=sleep,
    )
    wait = _DEFAULT_TIMEOUT if timeout is None else int(timeout)
    if wait < 1:
        wait = _DEFAULT_TIMEOUT
    print(f"[*] {vendor} dump: {' '.join(cmd)}")
    try:
        proc = proc_run(cmd, timeout=wait)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"frida-dexdump 超时（{wait}s）") from e
    except FileNotFoundError as e:
        raise RuntimeError(f"无法启动 frida-dexdump: {e}") from e
    finally:
        _force_stop(package, device)
    if proc.returncode not in (0, None):
        raise RuntimeError(f"frida-dexdump 失败 exit={proc.returncode}")

    moved = quarantine_invalid_dex(out_dir)
    if moved:
        print(f"[*] 隔离无效 dump {len(moved)} 个 -> {out_dir / '_invalid_dex'}")
    from ..dex_utils import repair_dumped_dexes
    fixed = repair_dumped_dexes(out_dir)
    if fixed:
        print(f"[*] 已重算 {fixed} 个 dex 的 checksum/SHA-1")
    dexes = list_dumped_dex(out_dir)
    print(f"\n[*] {vendor} dump 结束: {len(dexes)} 个有效 dex -> {out_dir}")
    if not dexes:
        raise RuntimeError(
            f"frida-dexdump 未产出有效 dex（目录 {out_dir}）。"
            "常见原因: frida-server 未以 root 运行、应用秒退、或深度搜索未扫到"
        )
    return dexes


def main() -> int:
    parser = argparse.ArgumentParser(description="360 加固：frida-dexdump 深度脱壳")
    parser.add_argument("package", help="目标包名")
    parser.add_argument("-o", "--out", default=None, help="输出目录")
    parser.add_argument("--device", help="覆盖 env.json 的 device")
    parser.add_argument("--sleep", type=int, default=None, help="spawn 后等待秒数")
    args = parser.parse_args()
    out_dir = (Path(args.out) if args.out
               else Path("outputs/unpacked_dex") / args.package)
    try:
        from ..runtime.env import describe, resolve
        cfg = resolve(device=args.device, sleep=args.sleep)
        print(f"[*] 环境: {describe(cfg)}")
        dump(
            args.package, out_dir,
            device=cfg["device"], sleep=cfg["sleep"], timeout=cfg.get("timeout"),
        )
    except Exception as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
