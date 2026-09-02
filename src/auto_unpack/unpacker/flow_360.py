"""360 适配器标记（自动 dump 未实现）。

识别到 360 时 adapter=unsupported，走静态提取；不回退通用 frida 脱壳。
"""

from __future__ import annotations

ADAPTER = "360"


def main() -> int:
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
