"""子进程封装：Windows 默认 gbk 读管道会炸，统一 UTF-8。"""

from __future__ import annotations

import subprocess


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """subprocess.run，text 模式强制 utf-8 + replace。"""
    if kw.get("text") or kw.get("universal_newlines"):
        kw.setdefault("encoding", "utf-8")
        kw.setdefault("errors", "replace")
    return subprocess.run(cmd, **kw)
