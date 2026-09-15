#!/usr/bin/env python3
"""APKiD 合并 + 分流注册表 + CLI（流水线的壳识别口）。

APKiD 只补强静态识别：merge_apkid 把扫描结果并进 packer_sigs 的结论，
decide_route 在静态完全没识别出来时按 APKiD packer 名回退 vendor 路由。
UNPACK_FLOWS / IMPLEMENTED_FLOWS 是 packer key → 脱壳插件的注册表，
与 unpacker/adapters.py 的加载器配套（select_adapter 从这里查表）。

用法:
    python -m auto_unpack.packer.apkid <app.apk> [--out-dir 产物目录] [--skip-unpack] [--package NAME]

实际分析由 flow/pipeline 状态机完成；本文件不做识别本身。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..runtime.proc import run as proc_run


def find_apkid() -> str:
    """自动定位 apkid.exe：优先 PATH，否则从当前解释器的 Scripts 目录推导。"""
    found = shutil.which("apkid")
    if found:
        return found
    scripts_dir = Path(sys.executable).parent / "Scripts"
    for name in ("apkid.exe", "apkid"):
        cand = scripts_dir / name
        if cand.exists():
            return str(cand)
    return "apkid"


# 静态/APKiD packer key → 厂商脱壳插件（与 packer_sigs.PACKERS 的 key 对齐）。
# 已实现动态 dump：flow_dpt_shell、flow_360、flow_legu、flow_netease。
# 其余插件命中只把路由定成 vendor（→ unsupported），不会被执行。顺序即匹配优先级。
UNPACK_FLOWS: dict[str, tuple[str, ...]] = {
    "unpacker/flow_360.py": ("360", "qihoo", "jiagu"),
    "unpacker/flow_legu.py": ("legu", "tencent"),
    "unpacker/flow_ijiami.py": ("ijiami",),
    "unpacker/flow_bangcle.py": ("bangcle", "secneo"),
    "unpacker/flow_naga.py": ("naga",),
    "unpacker/flow_ali.py": ("alibaba",),
    "unpacker/flow_baidu.py": ("baidu",),
    "unpacker/flow_netease.py": ("yidun",),
    "unpacker/flow_dingxiang.py": ("dingxiang",),
    "unpacker/flow_tongfu.py": ("tongfu",),
    "unpacker/flow_eversafe.py": ("eversafe",),
    "unpacker/flow_liapp.py": ("liapp",),
    "unpacker/flow_vplusplus.py": ("vplusplus",),
    "unpacker/flow_oppo.py": ("oppo",),
}
IMPLEMENTED_FLOWS = {
    "unpacker/flow_dpt_shell.py": "dpt-shell",
    "unpacker/flow_360.py": "360",
    "unpacker/flow_legu.py": "legu",
    "unpacker/flow_netease.py": "yidun",
}


def decide_route(sig: dict, *, generation: int = 0, has_shell: bool = False) -> str:
    """根据识别结果分流。generation 仅兼容旧调用，不参与判断。"""
    from .packer_sigs import suggest_route
    merged = dict(sig)
    if has_shell:
        merged["has_shell"] = True
    route = suggest_route(merged)
    return route


EMPTY_APKID = {"tags": {}, "packers": [], "nested_dex": 0, "file_count": 0}


def merge_apkid(sig: dict, info: dict | None) -> dict:
    """把 APKiD 结果并进静态结论。APKiD 只补强，不覆盖已确认的 dpt。"""
    info = info or EMPTY_APKID
    tags = info.get("tags") or {}
    packers = list(info.get("packers") or [])
    apkid_vmp = [p for p in packers if "vmp" in str(p).lower()]
    static_vmp = bool(sig.get("vmp"))
    apkid_has_vmp = bool(apkid_vmp)
    vmp = static_vmp or apkid_has_vmp
    if static_vmp and apkid_has_vmp:
        vmp_source = "static+apkid"
    elif static_vmp:
        vmp_source = "static"
    elif apkid_has_vmp:
        vmp_source = "apkid"
    else:
        vmp_source = None
    generation = int(sig.get("generation") or 0)
    has_packer = "packer" in tags or bool(packers)
    # anti_hook 不进 suspicious：无壳 app 自带反 Xposed 代码很常见
    # （湖州小众通联批次 OpenIM Flutter 样本因 anti_hook 被误判「未知壳」），
    # 与 anti_vm/anti_debug 一样只作参考信息，不参与壳判定。
    suspicious = bool(
        tags.get("protector") or info.get("nested_dex")
    )
    has_shell = has_packer or bool(sig.get("matched")) or suspicious
    return {
        "vmp": vmp,
        "generation": generation,
        "has_shell": has_shell,
        "apkid_vmp": apkid_vmp,
        "vmp_source": vmp_source,
        "vmp_conflict": bool(sig.get("dpt_shell") and apkid_has_vmp),
        "apkid_packers": packers,
        "has_packer": has_packer,
        "has_protector": bool(tags.get("protector")),
        "has_anti_hook": bool(tags.get("anti_hook")),
        "suspicious": suspicious,
    }


def needs_apkid(sig: dict) -> bool:
    if sig.get("error"):
        return True
    if sig.get("vmp"):
        return False
    if sig.get("dpt_shell"):
        return False
    if sig.get("dex_status") in ("failed", "partial"):
        return True
    if sig.get("vendor_candidates"):
        return True
    if len(sig.get("matched") or []) > 1:
        return True
    if sig.get("custom_family") or sig.get("dpt_type") == "suspected":
        return True
    return not sig.get("matched")


def should_run_apkid(sig: dict, *, force: bool = False, skip: bool = False) -> bool:
    if skip:
        return False
    if force:
        return True
    return needs_apkid(sig)


def resolve_apkid_exe(explicit: str | None = None) -> tuple[str | None, str | None]:
    exe = (explicit or "").strip() or find_apkid()
    if Path(exe).exists() or shutil.which(exe):
        return exe, None
    return None, f"找不到 APKiD（{exe}），静态未识别的样本无法补全"


def run_apkid(apkid_exe: str, apk: Path) -> tuple[dict | None, str | None]:
    try:
        proc = proc_run(
            [apkid_exe, "-j", str(apk)],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError:
        return None, f"找不到 apkid.exe: {apkid_exe}"
    except subprocess.TimeoutExpired:
        return None, "APKiD 扫描超时"
    if proc.returncode != 0:
        return None, (proc.stderr or "").strip() or f"返回码 {proc.returncode}"
    if len(proc.stdout or "") > 64 * 1024 * 1024:
        return None, "APKiD stdout 超过 64 MiB 限制"
    if len(proc.stderr or "") > 8 * 1024 * 1024:
        return None, "APKiD stderr 超过 8 MiB 限制"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return None, f"JSON 解析失败: {e}"
    if not isinstance(data, dict):
        return None, f"APKiD 返回了非对象 JSON: {type(data).__name__}"
    return data, None


def classify(data: dict) -> dict:
    tags: dict[str, int] = {}
    packers: set[str] = set()
    nested_dex = 0
    if not isinstance(data, dict):
        return {"tags": tags, "packers": [], "nested_dex": 0, "file_count": 0}
    files = data.get("files", [])
    if not isinstance(files, list):
        files = []
    for f in files:
        if not isinstance(f, dict):
            continue
        fn = f.get("filename", "")
        if not isinstance(fn, str):
            fn = ""
        if fn.count("!") >= 2 and "classes" in fn:
            nested_dex += 1
        matches = f.get("matches", {})
        if not isinstance(matches, dict):
            continue
        for tag_key, rules in matches.items():
            if not isinstance(tag_key, str):
                continue
            tag_list = [t.strip() for t in tag_key.split(",")]
            n = len(rules) if isinstance(rules, list) else 1
            for t in tag_list:
                tags[t] = tags.get(t, 0) + n
            if "packer" in tag_list:
                if isinstance(rules, list):
                    packers.update(r for r in rules if isinstance(r, str))
                elif isinstance(rules, str):
                    packers.add(rules)
    return {
        "tags": tags,
        "packers": sorted(packers),
        "nested_dex": nested_dex,
        "file_count": len(files),
    }


def resolve_flow(packers: list[str]) -> str | None:
    """按 packer 名（大小写不敏感子串双向）找脱壳插件；找不到返回 None。"""
    flows = resolve_flows(packers)
    return flows[0] if len(flows) == 1 else None


_APKiD_ALIASES = {
    "360": "qihoo360", "qihoo": "qihoo360", "jiagu": "qihoo360",
    "legu": "legu", "tencent": "legu",
    "ijiami": "ijiami", "ai jiami": "ijiami",
    "bangcle": "bangcle", "secneo": "bangcle",
    "naga": "naga", "alibaba": "alibaba",
    "baidu": "baidu", "yidun": "yidun", "netease": "yidun",
    "dingxiang": "dingxiang", "tongfu": "tongfu",
    "eversafe": "eversafe", "liapp": "liapp", "vplusplus": "vplusplus",
    "v++": "vplusplus", "oppo": "oppo",
}


def _canonical_apkid_key(name: str) -> str | None:
    low = re.sub(r"[^a-z0-9+]+", " ", str(name).casefold()).strip()
    if not low:
        return None
    known_keys = set(_APKiD_ALIASES.values())
    if low in known_keys:
        return low
    for alias, key in _APKiD_ALIASES.items():
        alias_low = alias.casefold()
        if low == alias_low or alias_low in low.split():
            return key
    return None


def resolve_flows(packers: list[str]) -> list[str]:
    """Resolve explicit APKiD aliases without short reverse substring matches."""
    flows: set[str] = set()
    canonical_flow = {
        "qihoo360": "unpacker/flow_360.py",
        "legu": "unpacker/flow_legu.py",
        "ijiami": "unpacker/flow_ijiami.py",
        "bangcle": "unpacker/flow_bangcle.py",
        "naga": "unpacker/flow_naga.py",
        "alibaba": "unpacker/flow_ali.py",
        "baidu": "unpacker/flow_baidu.py",
        "yidun": "unpacker/flow_netease.py",
        "dingxiang": "unpacker/flow_dingxiang.py",
        "tongfu": "unpacker/flow_tongfu.py",
        "eversafe": "unpacker/flow_eversafe.py",
        "liapp": "unpacker/flow_liapp.py",
        "vplusplus": "unpacker/flow_vplusplus.py",
        "oppo": "unpacker/flow_oppo.py",
    }
    for name in packers or []:
        key = _canonical_apkid_key(str(name))
        if not key:
            continue
        flow = canonical_flow.get(key)
        if flow:
            flows.add(flow)
    return sorted(flows)


def main(argv: list[str] | None = None) -> int:
    """兼容入口：与 `python -m auto_unpack analyze ...` 等价（CLI 收口到 flow/cli.py）。

    旧参数兼容：
      --out-dir D  → 等价 cli 的 -o/--out D（URL 输出目录）
      --out F      （额外 URL 清单文件）废弃——该功能从未正常工作过
      --deep       废弃的空操作，不再接受
    """
    from ..flow.cli import main as cli_main
    if argv is None:
        argv = sys.argv[1:]
    argv = ["--out" if a == "--out-dir" else a for a in argv]
    return cli_main(list(argv))


if __name__ == "__main__":
    raise SystemExit(main())
