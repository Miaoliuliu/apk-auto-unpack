"""网易易盾脱壳：与 360 相同，frida-dexdump -f -d --sleep。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import flow_360 as _dexdump

ADAPTER = "yidun"


def dump(
    package: str,
    out_dir: Path,
    device: str | None = None,
    sleep: int = 10,
    timeout: int | None = None,
) -> list[Path]:
    return _dexdump.dump(
        package, out_dir, device=device, sleep=sleep, timeout=timeout,
        vendor="网易易盾",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="网易易盾：frida-dexdump -f -d 深度脱壳")
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
