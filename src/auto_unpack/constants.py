#!/usr/bin/env python3
"""跨域共享值契约（任务阶段 / 错误码 / 脱壳验证状态 / 时间工具）。

本模块位于依赖图最底层：任何层（flow / packer / extraction /
unpacker / runtime）都可以 import 它；它自身不得 import 其它
auto_unpack 模块。

背景：这些常量原先定义在 flow/states.py，导致 extraction/report.py
反向依赖编排层（全项目唯一一处反向依赖）。现已下沉到本模块。

- 任务阶段状态：对外报告 dict 的 status 字段
- E_* 错误码：sample/识别/脱壳/提取 各域都可能产生，report 需要解释
- UNPACK_*：脱壳产物验证取值，states.py 明确"不和任务阶段混用"
- now_iso：纯工具函数
"""

from __future__ import annotations

from datetime import datetime, timezone

# 任务阶段
RECEIVED = "RECEIVED"
VALIDATED = "VALIDATED"
DETECTING = "DETECTING"
NO_PACKER = "NO_PACKER"
PACKER_IDENTIFIED = "PACKER_IDENTIFIED"
PACKER_SUSPECTED = "PACKER_SUSPECTED"
UNPACKING = "UNPACKING"
UNPACKED = "UNPACKED"
EXTRACTING = "EXTRACTING"
COMPLETED = "COMPLETED"
NEEDS_REVIEW = "NEEDS_REVIEW"
FAILED = "FAILED"

# 脱壳产物验证（方案书 5.4）
UNPACK_VALID = "VALID"
UNPACK_PARTIAL = "PARTIAL"
UNPACK_STUB_ONLY = "STUB_ONLY"
UNPACK_CORRUPTED = "CORRUPTED"
UNPACK_SKIPPED = "SKIPPED"
UNPACK_NOT_INSTALLED = "NOT_INSTALLED"
UNPACK_UNSUPPORTED = "unsupported_packer"
UNPACK_MANUAL = "needs_manual"

# 错误码
E_NOT_FOUND = "E_NOT_FOUND"
E_TOO_LARGE = "E_TOO_LARGE"
E_NOT_ZIP = "E_NOT_ZIP"
E_ZIP_BOMB = "E_ZIP_BOMB"
E_NO_MANIFEST = "E_NO_MANIFEST"
E_VALIDATE = "E_VALIDATE"
E_DETECT = "E_DETECT"
E_BAD_PACKAGE = "E_BAD_PACKAGE"
E_UNPACK = "E_UNPACK"
E_EXTRACT = "E_EXTRACT"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
