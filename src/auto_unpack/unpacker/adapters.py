#!/usr/bin/env python3
"""脱壳适配器：统一 dump，不在这里提 URL。

probe / execute 对应方案书接口的最小实现。
validate 在 validate.py，collect 由 pipeline + validate 完成。
插件注册表（UNPACK_FLOWS / IMPLEMENTED_FLOWS）在 packer/apkid.py。

已实现动态脱壳：dpt-shell（自研 dump.js）、360 / 乐固 / 易盾
（frida-dexdump -f -d）。其余厂商壳未实现插件时返回 unsupported。
"""

from __future__ import annotations

from pathlib import Path

ADAPTERS = ("dpt-shell", "360", "legu", "yidun", "static", "unsupported", "manual", "skip")
AUTOMATIC_ADAPTERS = ("dpt-shell", "dpt", "360", "legu", "yidun")


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

    360 / 乐固 / 易盾都走 frida-dexdump -f -d --sleep，忽略 deep。
    """
    del deep, apk_path
    wait = 10 if sleep is None else sleep
    if adapter == "unsupported":
        raise RuntimeError("unsupported_packer")
    if adapter == "manual":
        raise RuntimeError("vmp_needs_manual")
    if adapter == "skip":
        raise RuntimeError("unknown_packer")
    if adapter == "static":
        raise RuntimeError("static_no_dump")
    if adapter in ("360", "qihoo360"):
        from .flow_360 import dump as dump_360
        return dump_360(
            package, out_dir, device=device, sleep=wait, timeout=timeout,
        )
    if adapter in ("legu", "tencent"):
        from .flow_legu import dump as dump_legu
        return dump_legu(
            package, out_dir, device=device, sleep=wait, timeout=timeout,
        )
    if adapter in ("yidun", "netease"):
        from .flow_netease import dump as dump_yidun
        return dump_yidun(
            package, out_dir, device=device, sleep=wait, timeout=timeout,
        )
    if adapter in ("dpt-shell", "dpt"):
        from .flow_dpt_shell import dump as dpt_dump
        # sleep=0 是合法值（尽快收尾），不能用 or 判空——会把 0 吞成默认 10
        return dpt_dump(package, out_dir, device=device, sleep=wait, kill=True)
    raise RuntimeError(f"unsupported_adapter:{adapter}")
