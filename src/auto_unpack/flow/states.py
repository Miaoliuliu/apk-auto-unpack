#!/usr/bin/env python3
"""纯后端任务状态机。

阶段与方案书一致。终态：COMPLETED / NEEDS_REVIEW / FAILED。
脱壳产物验证另用 UnpackStatus，不和任务阶段混用。

值契约（任务阶段 / 错误码 / UNPACK_* / now_iso）已下沉到
../constants.py，本模块只保留状态机行为。
"""

from __future__ import annotations

from ..constants import (
    COMPLETED,
    DETECTING,
    E_BAD_PACKAGE,
    E_DETECT,
    E_EXTRACT,
    E_NO_MANIFEST,
    E_NOT_FOUND,
    E_NOT_ZIP,
    E_TOO_LARGE,
    E_UNPACK,
    E_VALIDATE,
    E_ZIP_BOMB,
    EXTRACTING,
    FAILED,
    NEEDS_REVIEW,
    NO_PACKER,
    PACKER_IDENTIFIED,
    PACKER_SUSPECTED,
    RECEIVED,
    UNPACK_CORRUPTED,
    UNPACK_MANUAL,
    UNPACK_NOT_INSTALLED,
    UNPACK_PARTIAL,
    UNPACK_SKIPPED,
    UNPACK_STUB_ONLY,
    UNPACK_UNSUPPORTED,
    UNPACK_VALID,
    UNPACKED,
    UNPACKING,
    VALIDATED,
    now_iso,
)

TERMINAL = {COMPLETED, NEEDS_REVIEW, FAILED}

TRANSITIONS: dict[str, frozenset[str]] = {
    RECEIVED: frozenset({VALIDATED, FAILED}),
    VALIDATED: frozenset({DETECTING, FAILED}),
    DETECTING: frozenset({
        NO_PACKER, PACKER_IDENTIFIED, PACKER_SUSPECTED,
        EXTRACTING, NEEDS_REVIEW, FAILED,
    }),
    NO_PACKER: frozenset({EXTRACTING, FAILED}),
    PACKER_IDENTIFIED: frozenset({UNPACKING, EXTRACTING, NEEDS_REVIEW, FAILED}),
    PACKER_SUSPECTED: frozenset({UNPACKING, EXTRACTING, NEEDS_REVIEW, FAILED}),
    UNPACKING: frozenset({UNPACKED, EXTRACTING, NEEDS_REVIEW, FAILED}),
    UNPACKED: frozenset({EXTRACTING, NEEDS_REVIEW, FAILED}),
    EXTRACTING: frozenset({COMPLETED, NEEDS_REVIEW, FAILED}),
    COMPLETED: frozenset(),
    NEEDS_REVIEW: frozenset(),
    FAILED: frozenset(),
}


class IllegalTransition(RuntimeError):
    pass


def can_transition(src: str, dst: str) -> bool:
    return dst in TRANSITIONS.get(src, frozenset())


def classify_unpack(quality: dict | None, rows: list | None) -> str:
    """业务 dex 完整性 -> VALID / PARTIAL / STUB_ONLY / CORRUPTED。"""
    rows = rows or []
    quality = quality or {}
    if not rows:
        return UNPACK_CORRUPTED
    if not quality.get("payload_dex_count"):
        return UNPACK_STUB_ONLY
    if quality.get("complete"):
        return UNPACK_VALID
    return UNPACK_PARTIAL


class Task:
    """一次分析任务。advance() 强制走合法边；终态不可再迁。"""

    def __init__(self, apk_path: str, task_id: str, out_dir: str):
        self.apk_path = apk_path
        self.task_id = task_id
        self.out_dir = out_dir
        self.status = RECEIVED
        self.history: list[dict] = [
            {"status": RECEIVED, "at": now_iso(), "note": apk_path},
        ]
        self.warnings: list[str] = []
        self.error: dict | None = None
        self.sample: dict = {}
        self.packer: dict = {}
        self.unpacking: dict = {}
        self.urls: list[dict] = []
        self.endpoints: list[str] = []
        self.extraction_stats: dict = {}
        self.tool_versions: dict = {}
        self.sig: dict = {}
        self.route: str | None = None

    def advance(self, dst: str, note: str = "") -> None:
        if self.status in TERMINAL:
            raise IllegalTransition(f"终态 {self.status} 不能迁到 {dst}")
        if not can_transition(self.status, dst):
            raise IllegalTransition(f"{self.status} -> {dst} 不合法")
        self.status = dst
        entry = {"status": dst, "at": now_iso()}
        if note:
            entry["note"] = note
        self.history.append(entry)
        print(f"[{dst}] {note}" if note else f"[{dst}]")

    def warn(self, msg: str) -> None:
        if msg and msg not in self.warnings:
            self.warnings.append(msg)
            print(f"[警告] {msg}")

    def fail(self, code: str, message: str) -> None:
        self.error = {"code": code, "message": message}
        if self.status not in TERMINAL:
            # TRANSITIONS 保证所有非终态都能到 FAILED
            self.advance(FAILED, f"{code}: {message}")

    def to_report(self) -> dict:
        from ..extraction.report import build_report
        return build_report(self)
