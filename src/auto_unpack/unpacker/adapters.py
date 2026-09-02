#!/usr/bin/env python3
"""脱壳适配器：统一 dump，不在这里提 URL。

probe / execute 对应方案书接口的最小实现。
validate 在 validate.py，collect 由 pipeline + validate 完成。
插件注册表（UNPACK_FLOWS / IMPLEMENTED_FLOWS）在 packer/apkid.py。

已实现动态脱壳：仅 dpt-shell。厂商壳未实现插件时返回 unsupported（静态提取）。
"""

from __future__ import annotations

from pathlib import Path

ADAPTERS = ("dpt-shell", "static", "unsupported", "manual", "skip")


def select_adapter(route: str, sig: dict, apkid_packers: list | None = None) -> str:
    """route -> 适配器 id。厂商壳走对应插件；未实现返回 unsupported；VMP 返回 manual；自研保护 skip。"""
    if route == "dpt":
        return "dpt-shell"
    if route == "static":
        return "static"
    if route == "unknown":
        return "skip"
    if route == "manual":
        return "manual"
    from ..packer.apkid import IMPLEMENTED_FLOWS, resolve_flow
    keys = [m.get("key") for m in (sig.get("matched") or []) if m.get("key")]
    if keys:
        flow = resolve_flow(keys)
        kind = IMPLEMENTED_FLOWS.get(flow) if flow else None
        if kind:
            return kind
        if route == "vendor":
            return "unsupported"
    if apkid_packers:
        flow = resolve_flow(list(apkid_packers))
        kind = IMPLEMENTED_FLOWS.get(flow) if flow else None
        if kind:
            return kind
        if route == "vendor":
            return "unsupported"
    if route == "vendor":
        return "unsupported"
    return "skip"


def execute(adapter: str, *, apk_path: str | None, package: str,
            out_dir: Path, device: str | None, sleep: int | None,
            deep: bool = False, timeout: int | None = None) -> list[Path]:
    """只 dump dex，返回路径列表。失败抛 RuntimeError。

    deep / timeout 保留签名兼容；当前仅 dpt-shell 实现动态 dump。
    """
    del deep, timeout, apk_path  # 未使用，保留调用方参数兼容
    if adapter == "unsupported":
        raise RuntimeError("unsupported_packer")
    if adapter == "manual":
        raise RuntimeError("vmp_needs_manual")
    if adapter == "skip":
        raise RuntimeError("unknown_packer")
    if adapter == "static":
        raise RuntimeError("static_no_dump")
    if adapter in ("dpt-shell", "dpt"):
        from .flow_dpt_shell import dump as dpt_dump
        return dpt_dump(package, out_dir, device=device, sleep=sleep or 20, kill=True)
    raise RuntimeError(f"unsupported_adapter:{adapter}")
