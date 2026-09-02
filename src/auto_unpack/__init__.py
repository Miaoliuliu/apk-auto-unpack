"""APK packer detection, unpacking, and URL extraction."""

import sys

__version__ = "0.1.0"


def _setup_console() -> None:
    """Windows 控制台默认 GBK：stdout 统一 UTF-8；androguard 的 loguru DEBUG 刷屏关掉。

    任何 `import auto_unpack.*` 都会先执行这里，各模块不再各自重复。
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        from loguru import logger

        logger.remove()
    except Exception:
        pass


_setup_console()
