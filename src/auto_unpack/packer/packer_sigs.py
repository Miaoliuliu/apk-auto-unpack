#!/usr/bin/env python3
"""壳识别模块（唯一入口）：静态特征二次判定 + dex 方法体结构分析。

独立于 APKiD，弥补其 yara 规则对现代壳的滞后。整体分两部分：

  一、静态特征（so 文件名 + assets 特征文件 + Manifest stub）
      1. lib/ 与 assets/ 下的 so 文件名（加固壳常把 so 放在 assets/，启动时释放到 lib/）
      2. assets/ 下的特征文件（如 360 的 jiagu_data.bin、乐固的 0OO00l111l1l）
      3. AndroidManifest 里 <application android:name> 被替换成的壳 stub 类名
      特征来源: APKiD 3.1.0 自身规则的字面量（rules.yarc 内提取）+ 已知样本实测。

  二、dex 方法体结构（壳 stub / 脱壳产物完整性）
      1. method_code_stats()：统计「应有代码但 code_item 为空」的方法占比，用于脱壳产物校验。
      2. class_count()：根 dex 类数，用于判定根 classes.dex 是不是壳 stub。

分流（不按 Gen1/Gen2 切，商业壳一二代混用）：
  无壳 → 直接提取 URL
  dpt-shell（标准/魔改/内嵌ZIP/疑似，对外同一标签） → dpt 脱壳
  常见厂商壳 → 该厂商脱壳插件
  该厂商样本带 VMP → 标 VMP，转人工（不提取 URL）
  自研保护（JDog / packhub / 根 dex stub / 根 dex 读不出） → 转人工分析（不提取 URL）

用法:
    py -3.10 packer_sigs.py <app.apk> [--list]
"""

from __future__ import annotations

import argparse
import fnmatch
import io
import re
import sys
import zipfile
from pathlib import Path

from ..dex_utils import parse_dexes


def _norm_path(p: str) -> str:
    """统一 ZIP 条目路径分隔符为 /（部分 zip 写反斜杠）。"""
    return (p or "").replace("\\", "/")


def _basename(p: str) -> str:
    """取 ZIP 条目 basename（最后一个 / 之后），等价于 Path(p).name 但零分配。"""
    return _norm_path(p).rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# 厂商特征库
# ---------------------------------------------------------------------------
# 每个条目字段:
#   vendor     中文厂商名
#   key        英文路由 key（与 apkid.py 的 UNPACK_FLOWS 对齐）
#   generation 仅作记录（商业壳一二代混用，分流不看这一项）
#   so         lib/ 或 assets/ 下的 so 文件名模式（fnmatch，大小写不敏感）
#   assets     assets/ 下的特征文件名模式（fnmatch）
#   stub       <application android:name> 的类名子串（大小写不敏感）
# 命中任意一类即认定该厂商；stub 子串越具体越不易误报。
PACKERS: list[dict] = [
    {
        "vendor": "360加固",
        "key": "qihoo360",
        # 360 VMP 另走 VMP_SIGNATURES / APKiD，不把 libjiagu*.so 当 VMP。
        "generation": 1,
        "so": ["libjiagu*.so", "libjiagud*.so", "libprotectClass*.so"],
        "assets": ["libjiagu*.so", "jiagu_data.bin", "o0oooOO0ooOo.dat", "jiagu_*.bin"],
        "stub": ["com.stub.stubapp", "qihoo.util.stubapp"],
    },
    {
        "vendor": "腾讯乐固",
        "key": "legu",
        "generation": 2,
        "so": ["libshella*.so", "libshellx*.so", "libshellb*.so", "libshellc*.so",
               "libshellsuper*.so", "libshell-super*.so", "libshell.so", "libtup.so",
               "libtosprotection.so"],
        "assets": ["0OO00l111l1l", "0OO00oo01l1l", "tosversion", "libshellx*.so",
                   "libshella*.so"],
        "stub": ["tencent.stubshell", "stubshell", "com.tencent.stub"],
    },
    {
        "vendor": "爱加密",
        "key": "ijiami",
        "generation": 2,
        "so": ["libexec*.so", "libexecmain*.so"],
        "assets": ["ijiami.dat", "ijiami.ajm", "ijm_lib*", "ijmdal.data"],
        "stub": ["ijiami", "s.h.e.l.l", "com.shell.superapplication"],
    },
    {
        "vendor": "梆梆",
        "key": "bangcle",
        "generation": 2,
        "so": [
            "libSecShell*.so", "libsecexe*.so", "libsecmain*.so", "libsecData*.so",
            "libDexHelper*.so",
            # 企业版 Everisk：交通银行等样本用 libbangcle_risk* / libRiskStub*
            "libbangcle*.so", "libRiskStub*.so",
        ],
        "assets": [
            "secData0.jar", "classes0.jar", "libSecShell*.so",
            "RiskStub*.dex", "infosecdata",
        ],
        "stub": [
            "secneo.apkwrapper", "applicationwrapper", "com.secneo",
            "com.bangcle.everisk",
        ],
    },
    {
        "vendor": "娜迦",
        "key": "naga",
        "generation": 2,
        "so": ["libhdog*.so", "libnaga*.so", "libddog*.so"],
        "assets": [],
        "stub": ["nesun.stub", "nagainc"],
    },
    {
        "vendor": "阿里聚安全",
        "key": "alibaba",
        "generation": 2,
        "so": ["libmobisec*.so", "libsgmain*.so", "libsgsecuritybody*.so", "libsgavmp*.so"],
        "assets": ["ali_sec.dat", "libmobisec*.so"],
        "stub": ["mobisecenhance", "alibaba.wireless.security", "taobao.wireless.security"],
    },
    {
        "vendor": "百度加固",
        "key": "baidu",
        "generation": 1,
        "so": ["libbaiduprotect*.so"],
        "assets": [],
        "stub": ["baidu.protect"],
    },
    {
        "vendor": "网易易盾",
        "key": "yidun",
        "generation": 2,
        "so": ["libnesec*.so", "libnsecure*.so",
               "libprotectt*.so", "libapp-protectt*.so"],
        "assets": ["libnesec*.so", "nedata.db", "nedig.properties"],
        "stub": ["yidun", "netease.protect", "protectt"],
    },
    {
        "vendor": "顶象",
        "key": "dingxiang",
        "generation": 2,
        "so": ["libdxvmp*.so", "libdxx*.so"],
        "assets": [],
        "stub": ["dingxiang"],
    },
    {
        "vendor": "通付盾",
        "key": "tongfu",
        "generation": 1,
        "so": ["libtongfu*.so", "libtfd*.so"],
        "assets": [],
        "stub": ["tongfu"],
    },
    {
        "vendor": "几维安全",
        "key": "eversafe",
        "generation": 2,
        # 不要用 libkiwi*.so：HKTV mall 等业务库会误报几维。
        "so": ["libeversafe*.so", "libkiwicrash*.so", "libkiwivm*.so"],
        "assets": [],
        "stub": ["kiwivm.security"],
    },
    {
        "vendor": "LIA/LIAPP",
        "key": "liapp",
        "generation": 1,
        "so": ["libliapp*.so"],
        "assets": ["liapp.ini"],
        "stub": ["liapp"],
    },
    {
        "vendor": "V++",
        "key": "vplusplus",
        "generation": 2,
        "so": ["libv++*.so", "libv++_64*.so"],
        "assets": [],
        "stub": ["v++"],
    },
    {
        "vendor": "OPPO加固",
        "key": "oppo",
        "generation": 2,
        "so": ["liboppo*.so"],
        "assets": [],
        "stub": ["oppo.protect"],
    },
]

# 命中即认定该样本带 VMP/Dex2C：厂商壳走对应插件，但带这些库则转人工。
# 白名单，不是「文件名含 vmp」。libdxvmp=顶象，libdexvmp=梆梆，对不上不算。
VMP_SIGNATURES: list[str] = [
    "libchaosvmp*.so",   # 娜迦 ChaosVMP
    "libsgavmp*.so",     # 阿里聚安全 sgavmp
    "libdxvmp*.so",      # 顶象 VMP
    "libdexvmp*.so",     # 梆梆 DexVMP（企业版常见）
    "libvmpc*.so",       # 通用 VMP
    "libVMDexShellx.so", # 乐固 VMP 壳
]
# 切勿把 libjiagu*.so 当 VMP。360 的 libjiagu.so / libjiagu_art.so /
# libjiagu_x86.so / libjiagu_a64.so 是同一普通加固库的不同 ABI（_a64 = arm64）。
# 360 VMP 另靠 APKiD / 其它规则，不能用 jiagu 文件名一刀切。

# dpt-shell（开源指令抽取壳，github.com/luoyesiqiu/dpt-shell）特征文件。
# 特征来源：dpt-shell 源码 config/Const.java。检测到即确认为 dpt-shell 系函数抽取壳。
#   - i11111i111.zip   加密的真实 dex 存储
#   - OoooooOooo       方法字节码抽取目录
#   - vwwwwwvwww       壳 lib 目录
#   - d_shell_data_001 壳配置
#   - build-key        构建密钥
#   - dpt.jks          dpt-shell 自带签名 keystore
DPT_SHELL_FILES: list[str] = [
    "i11111i111.zip",
    "i11111i111_unaligned.zip",
    "OoooooOooo",
    "vwwwwwvwww",
    "d_shell_data_001",
    "build-key",
    "dpt.jks",
    "libdpt.so",
]
DPT_PRIMARY_FILES = {
    "i11111i111.zip", "i11111i111_unaligned.zip", "OoooooOooo",
    "vwwwwwvwww", "d_shell_data_001",
}

# 反分析特征 so（非加固壳，但标记该 app 有主动防分析行为，黑产 app 大量使用）。
# 这些 so 出现在 app 里即强烈提示「有保护」，即使没命中任何商业壳。
ANTI_ANALYSIS_SOS: list[str] = [
    "libemulator_check*.so", "libantitrace*.so", "libtoolChecker*.so",
    "libfrida_detect*.so", "librootcheck*.so", "libxposed*.so",
    "libproperty_get*.so", "libanti*.so",
]

# 随机名自定义 lib（黑产自研壳指纹）：lib<混合大小写/含数字/点号假版本 的随机名>.so
# 如 libQWQFmAjkdIsgLRh.so / lib39285EFA.so / libUEFdCxSHhpzJ.so / libverfjhivriufbhig.vrjkhfuvbirfgg.so。
# 正常 SDK 名（libreactnative/libDingRtc/libAgoraRtcWrapper/libImSDK）不会命中。
RANDOM_LIB_RE = re.compile(r"^lib([A-Za-z0-9]{8,})\.so$")
# 点号分隔的「假版本号」随机名：lib<长段>.<长段>.so（黑产用点伪装版本）
DOTTED_RANDOM_RE = re.compile(r"^lib([A-Za-z0-9]{8,})\.([A-Za-z0-9]{8,})\.so$")
# 8 位十六进制 stem：lib39285EFA.so + assets/39285EFA.dex 是反复出现的自研壳强指纹。
HEX8_LIB_RE = re.compile(r"^lib([0-9A-Fa-f]{8})\.so$")
HEX8_STEM_RE = re.compile(r"^[0-9A-Fa-f]{8}$")
# USB 摄像头 / 常见 SDK：大写连写会被随机名规则误伤（libUVCCamera.so → UVCC）。
RANDOM_LIB_ALLOWLIST = {
    "libuvccamera.so",
    "libopencvjava.so",
    "libopencv_java3.so",
}


def _looks_random_lib(name: str) -> bool:
    """判断 so 名是否为「随机名自定义库」（黑产定制壳指纹）。

    判定规则（实测校准，防 camelCase SDK 误报）：
      - 点号分隔双长段（libverfjhivriufbhig.vrjkhfuvbirfgg.so）= 假版本随机名
      - 含数字：非 camelCase+数字（排除 NERtcAudio3D/GLESv2），且长度>=8 → 随机
      - 无数字：>=4 连续大写（QWQFMA/GHLYMI）且长度>=8 → 随机
      - 无数字：大写 run 数>=4 且长度>=10（散布大写 UEFdCxSHhpzJ：UEF/C/SH/J 四段）
      - camelCase 词名（AgoraRtcWrapper/RNNitroSQLite/NetHTProtect）最多 3 个大写
        run，不命中；短缩写（ImSDK 5字符）长度不足不命中
    """
    if (name or "").lower() in RANDOM_LIB_ALLOWLIST:
        return False
    m = RANDOM_LIB_RE.match(name)
    if not m:
        # 点号分隔假版本随机名
        return bool(DOTTED_RANDOM_RE.match(name))
    core = m.group(1)
    has_upper = any(c.isupper() for c in core)
    has_lower = any(c.islower() for c in core)
    if any(c.isdigit() for c in core):
        # camelCase+数字（libNERtcAudio3D / libGLESv2）是正常 SDK，排除；
        # 纯大写+数字（lib39285EFA）或 纯小写+数字（libvhejiecl2）= 随机
        return len(core) >= 8 and not (has_upper and has_lower)
    runs = re.findall(r"[A-Z]+", core)
    return (
        (max(map(len, runs), default=0) >= 4 and len(core) >= 8)
        or (len(runs) >= 4 and len(core) >= 10)
    )


def _find_random_libs(lib_sos: set[str]) -> list[str]:
    return sorted(n for n in lib_sos if _looks_random_lib(n))


def _find_hex_packer_pairs(lib_sos: set[str], asset_names: set[str]) -> list[str]:
    """libXXXXXXXX.so 与 assets/XXXXXXXX.dex（或 .dat/.bin）成对出现。"""
    so_stems: set[str] = set()
    for n in lib_sos:
        m = HEX8_LIB_RE.match(n)
        if m:
            so_stems.add(m.group(1).upper())
    if not so_stems:
        return []
    hits: list[str] = []
    for a in asset_names:
        base = _basename(a)
        if "." not in base:
            continue
        stem, ext = base.rsplit(".", 1)
        if HEX8_STEM_RE.match(stem) and stem.upper() in so_stems and ext.lower() in (
            "dex", "dat", "bin", "so",
        ):
            hits.append(f"lib{stem.upper()}.so+{base}")
    return sorted(hits)


def _find_fake_dex_decoys(view: _ApkView) -> list[str]:
    """检测假 dex 诱饵：路径含非 ASCII 字符（阿拉伯语乱码）的 .dex 条目。

    黑产 app 会塞成百上千个乱码路径的伪 dex（TYPE_IDs 报 30 亿+ 的无效 dex）
    迷惑分析工具 + 撑大 APK。合法 app 不可能有阿拉伯语路径的 dex。
    """
    candidates = [
        f for f in view.files
        if f.lower().endswith(".dex") and any(ord(c) > 127 for c in f)
    ]
    if not candidates:
        return []
    decoys: list[str] = []
    try:
        for name in candidates:
            magic = view.head(name, 8) or b""
            # 乱码路径本身只是启发式；真实 DEX 可能被故意改名，不能误报为诱饵。
            if not (magic.startswith(b"dex\n") or magic.startswith(b"dey\n")):
                decoys.append(name)
    except Exception:
        # 无法读取内容时保留弱证据，避免静默丢失异常路径信息。
        return sorted(candidates)
    return sorted(decoys)


# so 内容反分析特征字符串（MobSF 思路：只匹配文件名会漏掉改名后的壳 so）。
# 注意：ptrace/maps/TracerPid/xposed 在正常 SDK（崩溃上报/音视频库）里大量出现，
# 误报率高，只作辅助证据（进 evidence），不参与 custom_packer 强判定。
SO_ANTI_STRINGS = (
    b"frida", b"anti_debug", b"anti_frida", b"substrate",
)

JDOG_NATIVE_REQUIRED = b"com/jdog/JLibrary"
JDOG_NATIVE_LOADER_MARKERS = (
    b"__LoadDexLow",
    b"__LoadDexHigh",
    b"CallMakeInMemoryDexElements",
    b"SetElementsToLoader",
    b"makeInMemoryDexElements",
)

# dpt-shell 系壳 native 核心符号。
# 魔改会改文件名，但常保留 ART hook 字符串（AWAKE / dpt-shell 源码 / APKiD #433）。
DPT_NATIVE_REQUIRED = (b"readAppComponentFactoryName", b"AppComponentFactory")
DPT_NATIVE_HINT = b"DexPathList"
DPT_NATIVE_STRONG = (
    b"readAppComponentFactoryName",
    b"DPT_UNKNOWN_DATA",
)
# bytehook 很多壳（Virbox / 爱加密 / 自研）都会链，不能当 dpt 独有特征。
DPT_NATIVE_WEAK = (
    b"AppComponentFactory",
    b"DexPathList",
    b"makeDexElements",
    b"libdpt.so",
    b"ProxyComponentFactory",
    b"bytehook-plt-trampolines",
)
DPT_APP_STUBS = (
    "proxyapplication",
    "proxycomponentfactory",
    "nashsiqiu.shell",
    "luoyesiqiu",
)


def _is_dpt_native(data: bytes) -> bool:
    """so 是否像 dpt 运行时库。只认 dpt 独有串，不用 bytehook（Virbox 等也链）。"""
    # 单个字符串可能来自复用的运行库或调试字符串；至少需要一组互相
    # 关联的 dpt 证据，避免普通业务 so 抢走厂商壳路由。
    if all(s in data for s in DPT_NATIVE_REQUIRED):
        return True
    return (
        DPT_NATIVE_STRONG[1] in data
        and any(s in data for s in (DPT_NATIVE_HINT, DPT_NATIVE_WEAK[0], DPT_NATIVE_WEAK[2]))
    )


def _is_jdog_native_loader(data: bytes) -> bool:
    """Require the JDog Java bridge and a native in-memory DEX loader symbol."""
    return JDOG_NATIVE_REQUIRED in data and any(
        marker in data for marker in JDOG_NATIVE_LOADER_MARKERS
    )


def _dpt_app_stub(application: str | None) -> bool:
    if not application:
        return False
    low = str(application).lower()
    return any(m in low for m in DPT_APP_STUBS)


def _match_dpt_feature(path: str, feature: str) -> bool:
    """匹配 dpt 主文件，避免 i11111i111.zip.bak 这类前缀误报。"""
    prefix = "assets/" + feature
    if feature in ("OoooooOooo", "vwwwwwvwww"):
        return path == prefix or path.startswith(prefix + "/")
    return path == prefix


def _appended_zip_in_dex_bytes(data: bytes) -> dict | None:
    """dpt-unpack / AWAKE：stub classes.dex 官方边界后接 ZIP，末 4 字节为 ZIP 长度。"""
    if len(data) < 72:
        return None
    for endian in ("big", "little"):
        zip_len = int.from_bytes(data[-4:], endian)
        if zip_len < 32 or zip_len + 4 >= len(data):
            continue
        off = len(data) - zip_len - 4
        if off >= 0 and _valid_zip_slice(data, off, zip_len):
            return {"offset": off, "zip_len": zip_len, "endian": endian}
    if data.startswith(b"dex\n") and len(data) >= 40:
        declared = int.from_bytes(data[32:36], "little")
        if (0x70 <= declared < len(data) - 8
                and _valid_zip_slice(data, declared, len(data) - declared)):
            return {
                "offset": declared,
                "zip_len": len(data) - declared,
                "endian": "header",
            }
    return None


def _valid_zip_slice(data: bytes, offset: int, size: int) -> bool:
    """确认 dpt 尾部候选确实是 ZIP，而不是偶然出现的 PK 字节。"""
    if offset < 0 or size < 22 or offset + size > len(data):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data[offset:offset + size])) as z:
            return bool(z.namelist())
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def _find_dpt_appended_zip(view: _ApkView) -> dict | None:
    try:
        if "classes.dex" not in view.files:
            return None
        data = view.read("classes.dex")
    except Exception:
        return None
    hit = _appended_zip_in_dex_bytes(data)
    if hit:
        hit["dex"] = "classes.dex"
    return hit


def _find_hidden_dex(view: _ApkView) -> list[str]:
    """APKiD magic typing：assets 里文件名不是 .dex，但头是 dex\\n（藏真实 dex）。"""
    hits: list[str] = []
    peeked = 0
    try:
        for info in view.zf.infolist():
            if peeked >= 24 or len(hits) >= 6:
                break
            n = _norm_path(info.filename)
            low = n.lower()
            if not low.startswith("assets/"):
                continue
            if low.endswith(".dex") or low.endswith(_ASSET_PAYLOAD_SKIP_EXT):
                continue
            if any(p in low for p in _ASSET_PAYLOAD_SKIP_DIR):
                continue
            if info.file_size < 4096:
                continue
            peeked += 1
            magic = view.head(info, 36) or b""
            declared_size = int.from_bytes(magic[32:36], "little") if len(magic) >= 36 else 0
            if ((magic.startswith(b"dex\n") or magic.startswith(b"dey\n"))
                    and declared_size >= 0x70 and declared_size <= info.file_size):
                hits.append(n)
    except Exception:
        return []
    return hits


def _scan_so_content(view: _ApkView, so_entries: list[str]) -> dict:
    """扫描 APK 内指定 so 条目的二进制内容（MobSF 思路，抓改名后的壳 so）。

    返回 {non_elf, anti_strings, dpt_shell_so}
      non_elf      = 非标准 ELF（可能被加密/自写格式的壳 so）
      anti_strings = 内容含 frida/anti_debug 等反分析字符串的 so
      dpt_shell_so = 命中 dpt-shell 系核心符号（readAppComponentFactoryName +
                     AppComponentFactory）的 so —— 魔改版 dpt-shell 的特征
    """
    non_elf: list[str] = []
    anti: dict[str, list[str]] = {}
    dpt_shell_so: list[str] = []
    jdog_native_loader: list[str] = []
    for entry in so_entries:
        try:
            data = view.read(entry)
        except Exception:
            continue
        if not data.startswith(b"\x7fELF"):
            non_elf.append(entry)
            continue
        hits = [s.decode("latin1") for s in SO_ANTI_STRINGS if s in data]
        if hits:
            anti[entry] = hits
        if _is_dpt_native(data):
            dpt_shell_so.append(entry)
        if _is_jdog_native_loader(data):
            jdog_native_loader.append(entry)
    return {
        "non_elf": non_elf,
        "anti_strings": anti,
        "dpt_shell_so": dpt_shell_so,
        "jdog_native_loader": jdog_native_loader,
    }


def _manifest_class_missing(application: str | None, activities: list[str],
                            class_names: set[str]) -> list[str]:
    """检查 manifest 声明的 Application/Activity 类是否存在于 dex 类名集合。

    运行时「类不可用」反推为静态「类不存在」：manifest 声明的类在 APK 任意 dex 里
    都不存在 → 真实 dex 被隐藏/运行时解密注入 → 强壳信号（frida-packing-detector 思路）。
    返回缺失的类名列表。仅作辅助证据（插件化 app 可能误报）。
    """
    def _norm(name) -> str:
        # dex 描述符 Lcom/foo/Bar; 与 manifest 的 com.foo.Bar 归一成同一形态；
        # 必须成对剥 L/;，不能 lstrip("L")——会把 L 开头的类名（LandingActivity）剥坏
        n = str(name).replace("/", ".")
        return n[1:-1] if n.startswith("L") and n.endswith(";") else n

    missing: list[str] = []
    norm = {_norm(c) for c in class_names}
    for cls in [application] + list(activities or []):
        if not cls or str(cls).startswith("@"):
            continue
        c = _norm(cls)
        if c and c not in norm:
            missing.append(c)
    return sorted(missing)

# dex 结构分析常量
ACC_ABSTRACT = 0x0400
ACC_NATIVE = 0x0100
FULL_THRESHOLD = 0.5      # 空方法占比 >= 0.5 判「函数抽取(Gen2)」
PARTIAL_THRESHOLD = 0.1   # 空方法占比 >= 0.1 判「部分抽取」
STUB_CLASS_THRESHOLD = 50  # 根 dex 类数 < 此值，判「疑似壳 stub」
PAYLOAD_CLASS_THRESHOLD = 1000  # 与 class_shortfall 上界对齐：原包已有业务 dex

# assets 里超大非网页/媒体文件：魔改 dpt 把加密 dex 改名后仍常留下这块。
# 不单靠 so 文件名判 dpt；要和 appComponentFactory + 根 dex stub 一起用。
ASSET_PAYLOAD_MIN = 512 * 1024
_ASSET_PAYLOAD_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp",
    ".mp3", ".mp4", ".ogg", ".wav", ".m4a",
    ".ttf", ".otf", ".woff", ".woff2",
    ".xml", ".html", ".htm", ".js", ".css", ".vue", ".json", ".svg",
    ".db", ".sqlite", ".sqlite3", ".so", ".a", ".o",
)
_ASSET_PAYLOAD_SKIP_DIR = ("/www/", "/flutter_assets/", "/apps/", "/unicloud/")

# ---------------------------------------------------------------------------
# 特征提取
# ---------------------------------------------------------------------------
class _ApkView:
    """APK 的单次打开视图：中心目录只解析一遍，跨检测阶段共享条目读取。

    文件列表走 zipfile 直接读目录，绕过 androguard 的 manifest 解析——黑产样本会用
    畸形/混淆 manifest（如 namespace 塞阿拉伯语）让 androguard 崩溃，zipfile 天然免疫。
    旧实现每个检测器各自 ZipFile(path)，单样本最多开 7 次，批量扫描时是纯浪费。
    """

    def __init__(self, path: str):
        self.path = path
        self.zf = zipfile.ZipFile(path)
        self.files: list[str] = self.zf.namelist()

    def read(self, name: str) -> bytes:
        return self.zf.read(name)

    def head(self, name, n: int = 8) -> bytes | None:
        """读条目前 n 字节；name 可为文件名或 ZipInfo（同名重复条目时按 info 精确定位）。"""
        try:
            with self.zf.open(name) as f:
                return f.read(n)
        except Exception:
            return None

    def close(self) -> None:
        self.zf.close()

    def __enter__(self) -> "_ApkView":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _find_asset_payloads(view: _ApkView, min_size: int = ASSET_PAYLOAD_MIN) -> list[str]:
    """assets/ 下超大块（加密 dex 等），排除 Uni-app www、Flutter、图片音视频。"""
    hits: list[str] = []
    for info in view.zf.infolist():
        if info.is_dir() or info.file_size < min_size:
            continue
        n = _norm_path(info.filename)
        low = n.lower()
        if not low.startswith("assets/"):
            continue
        if any(p in low for p in _ASSET_PAYLOAD_SKIP_DIR):
            continue
        if low.endswith(_ASSET_PAYLOAD_SKIP_EXT):
            continue
        hits.append(n)
        if len(hits) >= 8:
            break
    return hits


def _stub_like(dex_info: dict) -> bool:
    """根 dex 是 stub，或解不出任何类（真实 dex 被藏起来）。

    升「疑似 dpt」还要同时有 appComponentFactory + assets 大块，这里只提供其中一项。
    """
    if dex_info.get("stub"):
        return True
    classes = [d.get("classes", 0) for d in dex_info.get("dex") or []]
    if not classes:
        return True
    root = next(
        (d.get("classes", 0) for d in dex_info.get("dex") or []
         if _basename(d.get("name", "")) == "classes.dex"),
        classes[0],
    )
    return root < STUB_CLASS_THRESHOLD and sum(classes) < PAYLOAD_CLASS_THRESHOLD


def _class_total(values) -> int:
    total = 0
    for c in values or ():
        try:
            total += int(c)
        except (TypeError, ValueError):
            continue
    return total


def _dex_class_total(sig: dict) -> int:
    return _class_total(sig.get("dex_classes"))


def has_payload_dex(sig: dict) -> bool:
    """原包 DEX 类总数已经像完整业务包，不必为了 APKiD 疑似标签去 spawn。"""
    if sig.get("dex_stub"):
        return False
    return _dex_class_total(sig) >= PAYLOAD_CLASS_THRESHOLD


def dex_unreadable(sig: dict) -> bool:
    """根 DEX 静态一个类都解不出来（ZIP 加密 / 解析失败）。JADX 也看不到实现。"""
    if _dex_class_total(sig) > 0:
        return False
    return bool(
        sig.get("zip_encrypted_dex_count")
        or sig.get("zip_encrypted_dex")
        or sig.get("dex_stub")
    )


def class_shortfall(dex_classes: list[int], size_mb: float) -> bool:
    """体积大但 dex 类总数异常少。只作 evidence，不再单独打成未知壳。

    用类总数而不是单 dex 最大值：黑产 dex 拆分包（几十个小 dex，每个 ~200 类，
    总计上万类）单 dex 恒低于阈值，用 max 会把完整应用误判成壳（湖州小众通联批次
    OpenIM Flutter 样本 71 个 dex 曾因此报「未知壳」）。
    """
    total = _class_total(dex_classes)
    return size_mb > 10 and 0 < total < PAYLOAD_CLASS_THRESHOLD


def suggest_route(sig: dict) -> str:
    """分流：manual / dpt / vendor / unknown / static。

    自研保护（route=unknown，转人工、不抽 URL）：
      JDog / packhub / 根 dex stub / 根 dex 读不出
    完整业务 dex（≥1000 类或 has_payload_dex）→ static
    APKiD nested/protector、假 dex、畸形 Manifest 在可读 dex 上只进 evidence。
    """
    if sig.get("edition") == "paid" or any(
        m.get("edition") == "paid" for m in (sig.get("matched") or [])
    ):
        return "manual"
    if sig.get("vmp"):
        return "manual"
    # 标准/魔改/内嵌 ZIP 是明确 dpt 证据，优先保留 dpt 专用路由。
    # suspected 只代表组合启发式命中；若同时存在明确的 JDog native loader，
    # 应优先按自研保护转人工，避免把自研 loader 误套 dpt 流程。
    if sig.get("dpt_shell") and sig.get("dpt_type") in (
        "standard", "modified", "appended",
    ):
        return "dpt"
    if sig.get("custom_family"):
        return "unknown"
    if sig.get("matched"):
        return "vendor"
    if sig.get("dpt_shell"):
        return "dpt"
    if has_payload_dex(sig):
        return "static"
    if dex_unreadable(sig) or sig.get("dex_stub"):
        return "unknown"
    return "static"


def _collect_file_names(files) -> tuple[set[str], set[str], set[str]]:
    """文件分类：lib so / assets so / assets 文件 basename。"""
    lib_sos: set[str] = set()        # lib/<abi>/<name>.so 的 basename
    asset_so_names: set[str] = set()  # assets/ 下 .so 的 basename（加固壳常把 so 放 assets）
    asset_names: set[str] = set()     # assets/ 下所有文件的 basename
    for f in files:
        f = _norm_path(f)
        # 注意：标准路径是 lib/arm64-v8a/xxx.so（无前导斜杠），必须同时匹配前缀和 "/lib/"
        # 曾用 "/lib/" in f 导致 lib/ 下的 so 全部漏掉（只匹配到 assets/ 下的）
        if (f.startswith("lib/") or "/lib/" in f) and f.endswith(".so"):
            lib_sos.add(_basename(f))
        elif f.startswith("assets/") and f != "assets/":
            base = _basename(f)
            if base:
                asset_names.add(base)
                if base.endswith(".so"):
                    asset_so_names.add(base)
    return lib_sos, asset_so_names, asset_names


def _read_manifest(view: _ApkView) -> tuple:
    """读 application/activities。androguard 崩在 manifest 上 = 畸形 manifest 特征。"""
    application = None
    activities: list[str] = []
    manifest_error = None
    try:
        from androguard.core.apk import APK
        apk = APK(view.path)
        application = apk.get_attribute_value("application", "name")
        try:
            activities = apk.get_activities()
        except Exception:
            activities = []
    except Exception as e:
        # androguard 崩在 manifest 上 = 畸形/混淆 manifest（黑产反分析特征）
        manifest_error = str(e)[:120]
    # 资源引用（@string/xxx 或 @0x7f...）不是壳 stub，置空
    if application and str(application).startswith("@"):
        application = None
    return application, activities, manifest_error


def _detect_dpt_files(files, view: _ApkView) -> tuple[list[str], bool]:
    """dpt-shell 特征文件 + appComponentFactory（raw AXML 字节检测，畸形 manifest 也能读）。"""
    # dpt-shell 特征文件检测（主数据目录允许子路径，文件名必须精确匹配）。
    dpt_shell_files: list[str] = []
    for f in files:
        n = _norm_path(f)
        for feat in DPT_SHELL_FILES:
            if _match_dpt_feature(n, feat) and feat not in dpt_shell_files:
                dpt_shell_files.append(feat)

    # manifest 是否设置 appComponentFactory（dpt-shell 系壳特征，魔改版也保留）。
    has_appcomponentfactory = False
    if "AndroidManifest.xml" in files:
        try:
            manifest_bytes = view.read("AndroidManifest.xml")
            has_appcomponentfactory = b"appComponentFactory" in manifest_bytes
        except Exception:
            pass
    return dpt_shell_files, has_appcomponentfactory


def extract_features(view: _ApkView) -> dict:
    """从 APK 提取硬特征，返回 {lib_sos, asset_so_names, asset_names, application,
    manifest_error, fake_dex_decoys}。

    文件列表走 zipfile（不解析 manifest，畸形 manifest 不会让整个识别崩溃）；
    Application 类名仍尝试 androguard，失败则置空（stub 是辅助信号，非阻塞）。
    """
    files = view.files

    lib_sos, asset_so_names, asset_names = _collect_file_names(files)
    application, activities, manifest_error = _read_manifest(view)
    dpt_shell_files, has_appcomponentfactory = _detect_dpt_files(files, view)

    try:
        asset_payloads = _find_asset_payloads(view)
    except Exception:
        asset_payloads = []

    return {
        "lib_sos": lib_sos,
        "asset_so_names": asset_so_names,
        "asset_names": asset_names,
        "application": application,
        "activities": activities,
        "manifest_error": manifest_error,
        "fake_dex_decoys": _find_fake_dex_decoys(view),
        "dpt_primary_files": sorted(
            f for f in dpt_shell_files if f in DPT_PRIMARY_FILES
        ),
        "dpt_shell_files": sorted(dpt_shell_files),
        "appcomponentfactory": has_appcomponentfactory,
        "asset_payloads": asset_payloads,
    }


# ---------------------------------------------------------------------------
# 匹配
# ---------------------------------------------------------------------------
def _fnmatch_hits(patterns, names) -> list[str]:
    """fnmatch 大小写不敏感匹配，返回命中名（去重排序）。"""
    lows = {n.lower() for n in names if n}
    return sorted({n for p in patterns for n in lows if fnmatch.fnmatch(n, p.lower())})


def _match_stub(patterns: list[str], application: str | None) -> list[str]:
    if not application:
        return []
    low = application.lower()
    hits = [application for pat in patterns if pat.lower() in low]
    return sorted(set(hits))


def _classify_qihoo_edition(
    asset_names: set[str],
    asset_so_names: set[str],
    lib_sos: set[str] | None = None,
) -> tuple[str, list[str]]:
    """按强归档标记保守区分 360 版本（免费标准版 / 付费企业版）。"""
    assets = {str(x).lower() for x in asset_names | asset_so_names}
    libs = {str(x).lower() for x in (lib_sos or set())}
    all_names = assets | libs
    legacy_bundle = {
        "libjiagu.so",
        "libjiagu_a64.so",
        "libjiagu_x64.so",
        "libjiagu_x86.so",
    }
    has_mips = "libjiagu_mips.a" in all_names
    has_bundle = legacy_bundle.issubset(all_names)
    evidence: list[str] = []
    if has_mips:
        source = "asset" if "libjiagu_mips.a" in assets else "so"
        evidence.append(f"{source}:libjiagu_mips.a")
    if has_bundle:
        evidence.append("bundle:" + "+".join(sorted(legacy_bundle)))
    return ("paid", evidence) if has_mips and has_bundle else ("standard", [])


# ---------------------------------------------------------------------------
# dex 方法体结构分析
# ---------------------------------------------------------------------------
def _is_empty_shell_code(code) -> bool:
    """code_item 是否为空壳占位（函数抽取壳保留的占位方法体）。

    dpt-shell/BlackDex 观察：抽取壳把方法 insns 抽走后，原位替换为垃圾 nop(0x00)
    或 return-void(0x0e)，code_item 仍在但内容为空壳。get_code() is None 检测不到，
    需检查指令内容。
    """
    try:
        insns = list(code.get_instructions())
        if not insns:
            return True
        if len(insns) > 2:
            return False
        return all(i.get_op_value() in (0x00, 0x0E) for i in insns)
    except Exception:
        return False


def method_code_stats(dex) -> dict:
    """遍历所有 class 的方法，统计方法体完整度。

    返回 {total, concrete, empty, empty_shell, ratio, shell_ratio}
      concrete    = 非 abstract 非 native 的方法数（这些方法必须有代码）
      empty       = 其中 get_code() is None（code_item 被删）的方法数
      empty_shell = 其中 code_item 是空壳占位（nop/return-void）的方法数
      ratio       = empty / concrete（传统判定）
      shell_ratio = (empty + empty_shell) / concrete（含空壳占位，抓 dpt-shell 系抽取）
    """
    total = concrete = empty = empty_shell = 0
    for cls in dex.get_classes():
        for m in cls.get_methods():
            total += 1
            flags = m.access_flags  # androguard 里是 int
            if flags & (ACC_ABSTRACT | ACC_NATIVE):
                continue
            concrete += 1
            code = m.get_code()
            if code is None:
                empty += 1
            elif _is_empty_shell_code(code):
                empty_shell += 1
    ratio = empty / concrete if concrete else 0.0
    shell_ratio = (empty + empty_shell) / concrete if concrete else 0.0
    return {"total": total, "concrete": concrete, "empty": empty,
            "empty_shell": empty_shell, "ratio": ratio, "shell_ratio": shell_ratio}


def classify_extraction(stats: dict) -> str:
    """依据空方法占比判定抽取程度。

    - "full"    函数抽取（Gen2）：大部分方法体被抽走
    - "partial" 部分抽取/混淆
    - "none"    完整（未抽取）：Gen1 整体加密脱壳后应是此状态

    优先用 shell_ratio（含空壳 code_item 占位，抓 dpt-shell 系），
    无则回退 ratio（仅 get_code() is None）。
    """
    r = stats.get("shell_ratio", stats.get("ratio", 0.0))
    if r >= FULL_THRESHOLD:
        return "full"
    if r >= PARTIAL_THRESHOLD:
        return "partial"
    return "none"


def class_count(dex) -> int:
    return sum(1 for _ in dex.get_classes())


def _dex_row(name: str, d, light: bool, class_names: set[str] | None) -> dict:
    """单个 dex 的结构行：light 模式只统计类数，完整模式走方法体统计。"""
    if class_names is not None:
        class_names.update(c.get_name() for c in d.get_classes())
    if light:
        return {
            "name": name,
            "classes": class_count(d),
            "total": 0, "concrete": 0, "empty": 0, "ratio": 0.0,
            "extraction": "none",
        }
    st = method_code_stats(d)
    return {
        "name": name,
        "classes": class_count(d),
        "total": st["total"],
        "concrete": st["concrete"],
        "empty": st["empty"],
        "empty_shell": st["empty_shell"],
        "ratio": st["ratio"],
        "shell_ratio": st["shell_ratio"],
        "extraction": classify_extraction(st),
    }


def analyze_dex_structure(path: str, light: bool = False, collect_names: bool = False) -> dict:
    """综合 dex 结构分析，返回 {dex:[...], stub, class_names}。

    light=True 时只统计类数（壳识别/批量扫描用，快；不做方法体遍历）。
    collect_names=True 时额外收集全部类名集合（用于 manifest 类存在性检测，较慢）。
    完整模式（方法体空占比）用于脱壳产物 Gen1/Gen2 判定，较慢。
    """
    result = []
    class_names: set[str] = set() if collect_names else None
    parse_stats: dict = {}
    for name, d in parse_dexes(path, stats=parse_stats):
        result.append(_dex_row(name, d, light, class_names))
    encrypted_dex = list(parse_stats.get("encrypted_dex") or [])
    fake_zip_encrypt = list(parse_stats.get("fake_zip_encrypt") or [])
    total_classes = sum(r["classes"] for r in result)
    root_classes = next(
        (r["classes"] for r in result if _basename(r["name"]) == "classes.dex"),
        result[0]["classes"] if result else 0,
    )
    stub = bool(result) and root_classes < STUB_CLASS_THRESHOLD \
        and total_classes < PAYLOAD_CLASS_THRESHOLD
    # ZIP 加密导致一个标准 dex 都解不出来：是对抗，不是无壳。
    if not result and encrypted_dex:
        stub = True
    return {
        "dex": result,
        "stub": stub,
        "class_names": class_names,
        "encrypted_dex": encrypted_dex,
        "fake_zip_encrypt": fake_zip_encrypt,
    }


# ---------------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------------
def _match_vendors(feats: dict) -> list[dict]:
    """PACKERS 静态特征匹配：so / assets / stub 任一命中即认定该厂商。"""
    matched: list[dict] = []
    for entry in PACKERS:
        evidence = [
            *(f"so:{x}" for x in _fnmatch_hits(
                entry["so"], feats["lib_sos"] | feats["asset_so_names"])),
            *(f"asset:{x}" for x in _fnmatch_hits(entry["assets"], feats["asset_names"])),
            *(f"stub:{x}" for x in _match_stub(entry["stub"], feats["application"])),
        ]
        if evidence:
            matched.append({
                "vendor": entry["vendor"],
                "key": entry["key"],
                "generation": entry["generation"],
                "evidence": evidence,
            })
    return matched


_BANGCLE_ENT = (
    "libbangcle", "libriskstub", "riskstub", "infosecdata", "bangcle.everisk",
)


def _tag_editions(matched: list[dict], feats: dict) -> tuple[str | None, list[str]]:
    """厂商标注：梆梆企业版与 360 付费版。返回 (360 edition, edition_evidence)。

    梆梆企业版（Everisk）：交通银行等用 libbangcle_risk* / RiskStub，不只是 SecNeo DexHelper。
    """
    for m in matched:
        if m["key"] != "bangcle":
            continue
        blob = " ".join(m.get("evidence") or []).lower()
        acts = " ".join(feats.get("activities") or []).lower()
        if any(tok in blob or tok in acts for tok in _BANGCLE_ENT):
            m["vendor"] = "梆梆加固企业版"
            m["edition"] = "enterprise"

    if not any(m.get("key") == "qihoo360" for m in matched):
        return None, []
    edition, evidence = _classify_qihoo_edition(
        feats["asset_names"], feats["asset_so_names"], feats["lib_sos"],
    )
    if edition == "paid":
        for m in matched:
            if m.get("key") == "qihoo360":
                m["vendor"] = "360加固付费版"
                m["edition"] = "paid"
                m["edition_evidence"] = list(evidence)
    return edition, evidence


def _decide_dpt_type(feats: dict, so_content: dict, appended_zip: dict | None,
                     dex_info: dict, hidden_dex: list, asset_payloads: list,
                     dpt_shell_files: list) -> tuple[bool, str | None, list[str]]:
    """五级判定 dpt 类型：standard / modified / appended / suspected / none。"""
    if feats.get("dpt_primary_files"):
        return True, "standard", list(dpt_shell_files)
    if so_content.get("dpt_shell_so"):
        evidence = [
            *dict.fromkeys(
                _basename(n) for n in (so_content.get("dpt_shell_so") or [])
            )
        ]
        return True, "modified", evidence
    if appended_zip:
        return True, "appended", [
            f"classes.dex内嵌ZIP@{appended_zip.get('offset')}",
        ]
    if _dpt_app_stub(feats.get("application")):
        return True, "modified", [f"stub:{feats.get('application')}"]
    stub_like = _stub_like(dex_info)
    factory = bool(feats.get("appcomponentfactory"))
    if factory and stub_like and (asset_payloads or hidden_dex):
        evidence = [
            "appComponentFactory",
            "dex_stub" if dex_info.get("stub") else "根dex缺失或畸形Manifest",
        ]
        if asset_payloads:
            evidence.append(f"assets大块:{asset_payloads[0]}")
        if hidden_dex:
            evidence.append(f"藏dex:{hidden_dex[0]}")
        return True, "suspected", evidence
    return False, None, []


def _judge_dpt(signals: dict) -> tuple[bool, str | None, list[str], int]:
    """dpt-shell 系壳判定 + 证据拼装。返回 (dpt_shell, dpt_type, evidence, generation)。

      标准版：assets 特征文件
      魔改版：native 符号（含 AWAKE 补充的 DPT_UNKNOWN_DATA / bytehook）
      内嵌 ZIP：classes.dex 尾部接 ZIP（dpt-unpack 机制，改名也在）
      Java stub：ProxyApplication / nashsiqiu.shell
      去符号疑似：factory + stub + assets 大块
    """
    feats = signals["feats"]
    dex_info = signals["dex_info"]
    so_content = signals["so_content"]
    hidden_dex = signals["hidden_dex"]
    appended_zip = signals["appended_zip"]
    malformed_manifest = signals["malformed_manifest"]
    generation = signals["generation"]
    dpt_shell_files = feats.get("dpt_shell_files", [])
    asset_payloads = feats.get("asset_payloads") or []

    dpt_shell, dpt_type, dpt_suspect_evidence = _decide_dpt_type(
        feats, so_content, appended_zip, dex_info, hidden_dex,
        asset_payloads, dpt_shell_files,
    )

    if dpt_shell and generation < 2:
        generation = 2
    if dpt_shell:
        if dpt_type:
            dpt_suspect_evidence.insert(0, f"dpt_type:{dpt_type}")
        if feats.get("appcomponentfactory") and "appComponentFactory" not in dpt_suspect_evidence:
            dpt_suspect_evidence.append("appComponentFactory")
        if dex_info.get("stub"):
            dpt_suspect_evidence.append(
                f"dex_stub:{[d['classes'] for d in dex_info.get('dex') or []]}"
            )
        if malformed_manifest:
            dpt_suspect_evidence.append("malformed_manifest")
    return dpt_shell, dpt_type, dpt_suspect_evidence, generation


def _classify_custom_family(jdog_native_loader: list, jdog_payload_context: bool,
                            dex_info: dict) -> tuple[str | None, str | None]:
    """JDog native loader / packhub 归类。返回 (custom_family, confidence)。"""
    if jdog_native_loader and jdog_payload_context:
        return "jdog_native_dex_loader", "high"
    if any(
        "/packhub/" in str(n).lower()
        for n in (dex_info.get("class_names") or [])
    ):
        # XSJR 一类：根 dex 是 com.packhub.shell.DexLoader；载荷在 pack_enc。
        # 对外打自研保护、转人工。指纹仍记 custom_family。
        return "packhub_shell", "high"
    return None, None


def _judge_custom_family(signals: dict) -> dict:
    """黑产自研壳指纹归类：JDog native loader / packhub / 随机 lib + 假 dex 诱饵。

    强指纹（39285EFA 成对、假 dex 诱饵、随机 so+畸形 Manifest、8 位 hex so）
    在根 DEX 完整时只作 anti_analysis / zip_decoy 证据，不把样本打成未知壳。
    """
    feats = signals["feats"]
    dex_info = signals["dex_info"]
    so_content = signals["so_content"]
    hidden_dex = signals["hidden_dex"]
    malformed_manifest = signals["malformed_manifest"]
    random_libs = signals["random_libs"]
    hex_packer_pairs = signals["hex_packer_pairs"]
    fake_dex_decoys = signals["fake_dex_decoys"]

    hex_sos = [n for n in random_libs if HEX8_LIB_RE.match(n)]
    fake_dex_strong = len(fake_dex_decoys) >= 3
    jdog_native_loader = so_content.get("jdog_native_loader") or []
    # 39285EFA 成对文件是最强的 JDog 证据，但部分变体会把载荷改名为
    # .np_ab/.np_ai 等文件，只保留 native loader 和大块 assets。
    # native bridge + 运行时载荷上下文同样足以归入 JDog，自研保护不能再被
    # appComponentFactory + 大 assets 的 dpt 疑似规则抢走。
    jdog_payload_context = bool(
        hex_packer_pairs
        or feats.get("asset_payloads")
        or hidden_dex
        or dex_info.get("stub")
        or not dex_info.get("dex")
    )
    custom_family, custom_family_confidence = _classify_custom_family(
        jdog_native_loader, jdog_payload_context, dex_info)
    custom_packer_strong = bool(
        hex_packer_pairs or fake_dex_strong
        or (hex_sos and (dex_info.get("stub") or hidden_dex or malformed_manifest))
        or (random_libs and malformed_manifest)
    )
    custom_packer = bool(
        custom_packer_strong
        or random_libs or fake_dex_decoys or malformed_manifest
        or so_content["non_elf"] or hidden_dex
    )
    return {
        "custom_family": custom_family,
        "custom_family_confidence": custom_family_confidence,
        "custom_packer": custom_packer,
        "custom_packer_strong": custom_packer_strong,
        "fake_dex_strong": fake_dex_strong,
        "jdog_native_loader": jdog_native_loader,
    }


def detect(apk_path: str) -> dict:
    """对单个 APK 做壳识别，返回 matched/vmp/dex_stub，以及:
          dpt_shell / dpt_type (standard|modified|suspected)
          package / package_trusted / package_source
          route (manual|dpt|vendor|unknown|static)
    """
    view = _ApkView(apk_path)
    try:
        return _detect_apk(view, apk_path)
    finally:
        view.close()


def _collect_file_signals(feats: dict) -> dict:
    """从 extract_features 结果派生 VMP/随机 lib/畸形 manifest 等文件级信号。"""
    so_pool = feats["lib_sos"] | feats["asset_so_names"]
    # VMP 壳 so 也可能只出现在 assets 特征文件里（如 libVMDexShellx.so）
    vmp_evidence = _fnmatch_hits(
        VMP_SIGNATURES,
        feats["lib_sos"] | feats["asset_so_names"] | feats["asset_names"],
    )
    anti_analysis = _fnmatch_hits(
        ANTI_ANALYSIS_SOS, feats["lib_sos"] | feats["asset_so_names"])
    return {
        "vmp": bool(vmp_evidence),
        "vmp_evidence": vmp_evidence,
        "anti_analysis": anti_analysis,
        "random_libs": _find_random_libs(so_pool),
        "hex_packer_pairs": _find_hex_packer_pairs(so_pool, feats["asset_names"]),
        "fake_dex_decoys": feats["fake_dex_decoys"],
        "malformed_manifest": feats["manifest_error"] is not None,
        "dpt_shell_files": feats.get("dpt_shell_files", []),
        "asset_payloads": feats.get("asset_payloads") or [],
    }


def _collect_dex_info(apk_path: str, feats: dict) -> tuple[dict, list[str]]:
    """dex 结构分析 + manifest 类存在性检测。

    根 classes.dex 是否壳 stub（真实 dex 被隐藏/加密）。类数少单独不能作为加固
    信号（合法小 app 类也少），只作辅助证据，由 router 结合 so/stub 命中综合判断。
    collect_names=True：顺便收集类名集合，供 manifest 类存在性检测（强壳信号）。
    """
    try:
        dex_info = analyze_dex_structure(apk_path, light=True, collect_names=True)
    except Exception:
        dex_info = {"dex": [], "stub": False, "class_names": None}
    # manifest 声明的 Application/Activity 不在任何 dex 里 → 真实 dex 被隐藏/运行时
    # 注入（frida-packing-detector 思路的静态反推）。仅作辅助证据。
    manifest_missing: list[str] = []
    if dex_info.get("class_names"):
        try:
            manifest_missing = _manifest_class_missing(
                feats["application"], feats.get("activities", []), dex_info["class_names"])
        except Exception:
            manifest_missing = []
    return dex_info, manifest_missing


def _collect_so_content(view: _ApkView, dpt_shell_files: list[str]) -> dict:
    """so 内容检测（MobSF：扫 so 内部串，不单靠文件名）。

    标准 dpt 特征文件已足够定论，跳过全量 so 扫描提速。
    """
    so_content: dict = {
        "non_elf": [],
        "anti_strings": {},
        "dpt_shell_so": [],
        "jdog_native_loader": [],
    }
    try:
        so_entries = [n for n in view.files
                      if (n.startswith("lib/") or n.startswith("assets/")) and n.endswith(".so")]
        if so_entries and not dpt_shell_files:
            so_content = _scan_so_content(view, so_entries)
    except Exception:
        pass
    return so_content


def _resolve_package(apk_path: str) -> tuple:
    """包名解析（可信度链在 pkg_name 模块）。失败静默，返回空值。"""
    try:
        from ..runtime.pkg_name import get_package_info
        pinfo = get_package_info(apk_path)
        return (
            pinfo.get("package"),
            pinfo.get("package_source"),
            bool(pinfo.get("package_trusted")),
            pinfo.get("package_note") or "",
        )
    except Exception:
        return None, None, False, ""


def _compose_result(
    matched: list[dict], qihoo_edition: str | None, qihoo_edition_evidence: list[str],
    generation: int, feats: dict, file_sig: dict, dex_info: dict, so_content: dict,
    family: dict, hidden_dex: list, appended_zip: dict | None, manifest_missing: list[str],
    dpt_shell: bool, dpt_type: str | None, dpt_suspect_evidence: list[str],
    dex_classes: list[int], encrypted_dex: list, shortfall: bool,
    package, package_source, package_trusted, package_note,
) -> dict:
    """组装 detect 结果 dict（PRD 报告合同的数据源）+ 派生 route。"""
    result = {
        "matched": matched,
        "edition": qihoo_edition,
        "edition_evidence": qihoo_edition_evidence,
        "vmp": file_sig["vmp"],
        "vmp_evidence": file_sig["vmp_evidence"],
        "generation": generation,
        "dex_stub": dex_info["stub"],
        "dex_classes": dex_classes,
        "zip_encrypted_dex": encrypted_dex[:12],
        "zip_encrypted_dex_count": len(encrypted_dex),
        "fake_zip_encrypt": list(dex_info.get("fake_zip_encrypt") or [])[:12],
        "fake_zip_encrypt_count": len(dex_info.get("fake_zip_encrypt") or []),
        "anti_analysis": file_sig["anti_analysis"],
        "random_libs": file_sig["random_libs"],
        "hex_packer_pairs": file_sig["hex_packer_pairs"],
        "fake_dex_decoys_count": len(file_sig["fake_dex_decoys"]),
        "malformed_manifest": file_sig["malformed_manifest"],
        "dpt_shell_files": file_sig["dpt_shell_files"],
        "dpt_primary_files": feats.get("dpt_primary_files", []),
        "dpt_shell_so": so_content.get("dpt_shell_so", []),
        "dpt_shell": dpt_shell,
        "dpt_type": dpt_type,
        "dpt_suspect_evidence": dpt_suspect_evidence,
        "dpt_appended_zip": appended_zip,
        "hidden_dex": hidden_dex,
        "asset_payloads": file_sig["asset_payloads"],
        "appcomponentfactory": feats.get("appcomponentfactory", False),
        "manifest_class_missing": manifest_missing,
        "so_non_elf": so_content["non_elf"],
        "so_anti_strings": so_content["anti_strings"],
        "jdog_native_loader": family["jdog_native_loader"],
        "custom_packer": family["custom_packer"],
        "custom_packer_strong": family["custom_packer_strong"],
        "custom_family": family["custom_family"],
        "custom_family_confidence": family["custom_family_confidence"],
        "runtime_dex_loader": bool(family["jdog_native_loader"]) or family["custom_family"] == "packhub_shell",
        "fake_dex_strong": family["fake_dex_strong"],
        "class_shortfall": shortfall,
        "package": package,
        "package_source": package_source,
        "package_trusted": package_trusted,
        "package_note": package_note,
    }
    result["dex_unreadable"] = dex_unreadable(result)
    result["route"] = suggest_route(result)
    return result


def _detect_apk(view: _ApkView, apk_path: str) -> dict:
    feats = extract_features(view)
    matched = _match_vendors(feats)
    generation = max((m["generation"] for m in matched), default=0)
    qihoo_edition, qihoo_edition_evidence = _tag_editions(matched, feats)

    file_sig = _collect_file_signals(feats)
    dex_info, manifest_missing = _collect_dex_info(apk_path, feats)
    so_content = _collect_so_content(view, file_sig["dpt_shell_files"])
    hidden_dex = _find_hidden_dex(view)
    appended_zip = _find_dpt_appended_zip(view)

    signals = {
        "feats": feats,
        "dex_info": dex_info,
        "so_content": so_content,
        "hidden_dex": hidden_dex,
        "appended_zip": appended_zip,
        "malformed_manifest": file_sig["malformed_manifest"],
        "random_libs": file_sig["random_libs"],
        "hex_packer_pairs": file_sig["hex_packer_pairs"],
        "fake_dex_decoys": file_sig["fake_dex_decoys"],
        "generation": generation,
    }
    dpt_shell, dpt_type, dpt_suspect_evidence, generation = _judge_dpt(signals)
    family = _judge_custom_family(signals)

    dex_classes = [d["classes"] for d in dex_info["dex"]]
    encrypted_dex = list(dex_info.get("encrypted_dex") or [])
    try:
        size_mb = Path(apk_path).stat().st_size / (1024 * 1024)
    except Exception:
        size_mb = 0.0
    # 体积大但 dex 类总数异常少：不要当成无壳；解析失败不算进这条（走 stub_like）
    shortfall = class_shortfall(dex_classes, size_mb)
    # ZIP 加密 dex 且解不出类：class_shortfall 的 `0 < total` 进不去，靠 dex_stub。
    if encrypted_dex and not dex_classes:
        dex_info["stub"] = True

    package, package_source, package_trusted, package_note = _resolve_package(apk_path)

    return _compose_result(
        matched, qihoo_edition, qihoo_edition_evidence, generation,
        feats, file_sig, dex_info, so_content, family,
        hidden_dex, appended_zip, manifest_missing,
        dpt_shell, dpt_type, dpt_suspect_evidence,
        dex_classes, encrypted_dex, shortfall,
        package, package_source, package_trusted, package_note,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="壳识别：静态特征(so/assets/stub) + dex 方法体结构")
    parser.add_argument("apk", nargs="?", help="APK 文件路径")
    parser.add_argument("--list", action="store_true", help="打印特征库")
    args = parser.parse_args()

    if args.list:
        for e in PACKERS:
            print(f"{e['vendor']:12s}  {e['key']:12s}  so={e['so']}  assets={e['assets']}  stub={e['stub']}")
        print(f"\nVMP 特征: {VMP_SIGNATURES}")
        return 0

    if not args.apk:
        parser.error("需要 APK 路径或 --list")

    apk = Path(args.apk)
    if not apk.exists():
        print(f"[错误] 文件不存在: {apk}", file=sys.stderr)
        return 2

    try:
        r = detect(str(apk))
    except Exception as e:
        print(f"[错误] 壳识别失败: {e}", file=sys.stderr)
        return 2

    route = r.get("route") or suggest_route(r)
    shell, next_step = _cli_conclusion(r, route)
    print(f"[结论] 壳={shell}  下一步={next_step}")
    try:
        from ..runtime.product import archive_detected_apk, archive_enabled
        if archive_enabled():
            archived = archive_detected_apk(apk, shell)
            print(f"[+] 壳识别归档 -> {archived}")
    except Exception as e:
        print(f"[警告] 壳识别归档失败: {e}", file=sys.stderr)
    return 0


def _cli_conclusion(r: dict, route: str) -> tuple[str, str]:
    """CLI 单行结论：(壳名, 下一步)。"""
    if route == "dpt" or (r.get("dpt_shell") and route not in ("manual", "unknown")):
        return "dpt-shell", "走 dpt 脱壳"

    if route == "manual" or r.get("vmp"):
        vendors = "+".join(
            (m.get("vendor") or m.get("key") or "?") for m in (r.get("matched") or [])
        )
        if r.get("vmp"):
            name = f"{vendors}(VMP)" if vendors else "VMP/Dex2C"
        else:
            name = vendors or "商业壳(付费/人工)"
        return name, "需人工处理"

    if route == "vendor" and r.get("matched"):
        vendors = "+".join(
            (m.get("vendor") or m.get("key") or "?") for m in r["matched"]
        )
        return vendors, "走对应厂商脱壳插件"

    if route == "unknown":
        return "自研保护", "转人工分析"

    if r.get("custom_packer") or r.get("class_shortfall"):
        return "无加固壳(有保护痕迹)", "继续静态提取 URL"

    return "无壳", "直接提取 URL"


if __name__ == "__main__":
    raise SystemExit(main())
