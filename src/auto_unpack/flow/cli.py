"""CLI：analyze / detect。无子命令时把 APK 路径当成 analyze。

不指定 APK 时读取项目根 APK/ 下全部 .apk，依次跑完整流水线。
也可传入单个文件或任意目录。
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


_KNOWN = {"analyze", "detect", "-h", "--help"}


def _normalize_argv(argv: list[str] | None) -> list[str]:
    """空参数 / 只有选项 → 默认 analyze（读 APK/）。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return ["analyze"]
    if argv[0] not in _KNOWN:
        return ["analyze"] + argv
    return argv


def _add_common(parser: argparse.ArgumentParser) -> None:
    from ..runtime.env import add_install_args, add_unpack_args
    parser.add_argument(
        "apk",
        nargs="?",
        default=None,
        help="APK 文件或含 APK 的目录；省略则读取 APK/ 下全部 .apk",
    )
    parser.add_argument(
        "-o", "--out",
        help="URL 输出目录（默认 extracted_urls/<apk文件名>，目录内只放 urls_by_rank.txt；"
             "dex 在 unpacked_dex/）。"
             "批量时忽略此参数，每个 APK 仍写到各自默认目录",
    )
    parser.add_argument("--package", help="包名（畸形 Manifest / 启发式不可信时必须）")
    parser.add_argument("--device", help="覆盖 env.json 的 device")
    parser.add_argument("--sleep", type=int, help="覆盖 env.json 的 sleep")
    parser.add_argument("--skip-apkid", action="store_true", help="不跑 APKiD")
    parser.add_argument("--apkid", nargs="?", const="", default=None, help="强制跑 APKiD")
    parser.add_argument(
        "--inbox",
        help="APK 存放目录（默认 APK/）。不指定 apk 时扫描此目录",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="目录模式时递归查找子目录里的 .apk",
    )
    add_install_args(parser)
    add_unpack_args(parser)


def _run_one(args, apk: Path, *, detect_only: bool, out_dir: str | None) -> tuple[int, dict]:
    from ..runtime.env import install_from_args, unpack_from_args
    from .pipeline import print_cli_report, run
    from ..extraction.report import exit_code

    report = run(
        apk,
        out_dir=out_dir,
        package=args.package,
        device=args.device,
        sleep=args.sleep,
        deep=getattr(args, "deep", False),
        skip_apkid=args.skip_apkid,
        force_apkid=args.apkid is not None,
        apkid_exe=args.apkid,
        unpack=unpack_from_args(args),
        force_unpack=bool(getattr(args, "force_unpack", False)),
        timeout=getattr(args, "timeout", None),
        install=install_from_args(args),
        detect_only=detect_only,
    )
    print_cli_report(report)
    return exit_code(report), report


def _status_line(apk: Path, code: int, report: dict | None) -> str:
    if report is None:
        return f"  [{code}] {apk.name}  未产出报告"
    packer = report.get("packer_detection") or report.get("packer") or {}
    label = packer.get("packer") or packer.get("name") or ""
    packed = packer.get("packed")
    status = report.get("status") or "?"
    return f"  [{code}] {apk.name}  {status}  packed={packed}  {label}"


def _run_analyze(args, *, detect_only: bool = False) -> int:
    from ..runtime.product import default_apk_inbox, resolve_apk_input
    from ..extraction.report import EXIT_BAD_INPUT, EXIT_FAILED

    try:
        src, targets = resolve_apk_input(
            args.apk,
            inbox=getattr(args, "inbox", None),
            recursive=bool(args.recursive),
        )
    except FileNotFoundError as e:
        print(f"[错误] {e}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if not targets:
        inbox = default_apk_inbox()
        if src.resolve() == inbox.resolve():
            print(
                f"[错误] {src} 里没有 .apk 文件。\n"
                f"      把要分析的 APK 放到这个目录，再运行: python -m auto_unpack",
                file=sys.stderr,
            )
        else:
            print(f"[错误] 目录下没有 .apk 文件: {src}", file=sys.stderr)
        return EXIT_BAD_INPUT

    batch = len(targets) > 1 or not (args.apk and Path(args.apk).is_file())
    out_dir = args.out
    if batch:
        if out_dir:
            print(
                "[警告] 批量模式忽略 -o/--out，每个 APK 写到 extracted_urls/<apk名>/",
                flush=True,
            )
            out_dir = None
        if args.package:
            print(
                "[警告] 批量模式会把 --package 套到每一个 APK；"
                "包名各不相同时请改成单文件运行",
                flush=True,
            )
        print(f"[*] 从 {src} 读取 {len(targets)} 个 APK", flush=True)

    codes: list[int] = []
    rows: list[tuple[Path, int, dict | None]] = []
    interrupted = False
    try:
        for i, apk in enumerate(targets, 1):
            if batch:
                print(f"\n===== [{i}/{len(targets)}] {apk.name} =====", flush=True)
            t0 = time.perf_counter()
            try:
                code, report = _run_one(args, apk, detect_only=detect_only, out_dir=out_dir)
            except Exception as e:
                print(f"[错误] 处理失败: {apk}: {e}", file=sys.stderr)
                code, report = EXIT_FAILED, None
            elapsed = time.perf_counter() - t0
            if batch:
                print(f"[*] 耗时 {elapsed:.1f}s  exit={code}", flush=True)
            codes.append(code)
            rows.append((apk, code, report))
    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] 已中断", file=sys.stderr)

    if batch and rows:
        title = "已中断" if interrupted else "批量完成"
        print(f"\n========== {title} ==========", flush=True)
        print(f"目录: {src}", flush=True)
        print(f"共 {len(rows)}/{len(targets)} 个", flush=True)
        for apk, code, report in rows:
            print(_status_line(apk, code, report), flush=True)

    if interrupted:
        return 130
    return max(codes) if codes else EXIT_BAD_INPUT


def main(argv: list[str] | None = None) -> int:
    argv = _normalize_argv(argv)

    parser = argparse.ArgumentParser(
        prog="auto-unpack",
        description=(
            "APK 壳识别、脱壳与 URL 提取（analyze / detect）。"
            "不指定文件时读取 APK/ 下全部 .apk。"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="完整流水线：识别 →（可选）脱壳 → 提取 URL")
    _add_common(p_an)
    p_an.add_argument("--deep", action="store_true",
                      help="已废弃（原通用 frida 脱壳）；保留兼容，无效果")
    p_an.set_defaults(_fn=lambda a: _run_analyze(a, detect_only=False))

    p_de = sub.add_parser("detect", help="只做壳识别，不脱壳、不提取")
    _add_common(p_de)
    p_de.set_defaults(_fn=lambda a: _run_analyze(a, detect_only=True))

    args = parser.parse_args(argv)
    return args._fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
