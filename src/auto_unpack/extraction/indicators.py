#!/usr/bin/env python3
"""URL 规则底座：正则、噪音/业务分级、配置收割、折叠与指标合并。

「业务 URL 漏报时优先改本文件的规则表」——规则全部在这一个文件里，
纯字符串逻辑，不做任何文件/ZIP I/O（扫 APK 的编排见 analyze.py）。
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import unicodedata
from urllib.parse import quote, urlsplit, urlunsplit

# rank -> 业务相关性；这不是 URL 语法或可达性置信度。
RANK_SCORE = {"biz": 0.9, "weak": 0.55, "noise": 0.25}
# 保留导出名称供旧调用方过渡；新报告使用 business_likelihood。
RANK_CONF = RANK_SCORE

_SUPPORTED_SCHEMES = frozenset({"http", "https", "ws", "wss"})
_SCHEME_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_BAD_URL_CHARS = frozenset('{}\\^|`<>"\'')
MAX_URL_CHARS = 2048


def _parse_ip(host: str):
    """解析 IPv4/IPv6（可带方括号）。非法则 None。"""
    if not host:
        return None
    try:
        return ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        return None


def _is_ip_host(host: str) -> bool:
    return _parse_ip(host) is not None


def _format_ip_host(host: str) -> str:
    """IPv6 字面量套方括号，供 netloc / canonical 使用。"""
    ip = _parse_ip(host)
    if ip is None or ip.version != 6:
        return host
    return f"[{host.strip().strip('[]')}]"


def classify_type(raw: str, host: str, path: str) -> str:
    """PRD：url / domain / ip。带 scheme 的一律算 url。"""
    has_scheme = "://" in (raw or "")
    path = path or ""
    if has_scheme:
        return "url"
    if _is_ip_host(host):
        return "url" if path not in ("", "/") else "ip"
    if path not in ("", "/"):
        return "url"
    return "domain"


def _netloc(scheme: str, host: str, port: int | None) -> str:
    """组装 netloc，剥离默认端口（http/ws=80，https/wss=443）。IPv6 带方括号。"""
    host = _format_ip_host(host)
    if port and not ((scheme in ("http", "ws") and port == 80)
                     or (scheme in ("https", "wss") and port == 443)):
        return f"{host}:{port}"
    return host


def _valid_dns_host(host: str) -> tuple[bool, str]:
    """校验 HTTP/WS 主机名并返回 IDNA 形式。"""
    if not host or len(host) > 253:
        return False, ""
    trailing_dot = host.endswith(".")
    body = host[:-1] if trailing_dot else host
    try:
        ascii_host = body.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False, ""
    labels = ascii_host.split(".")
    if not labels or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
        return False, ""
    normalized = ascii_host + ("." if trailing_dot else "")
    return True, normalized


def _split_candidate(raw: str):
    """解析绝对 URL 或无协议 host[/path]，不为后者伪造协议。"""
    if len(raw) > MAX_URL_CHARS:
        return None
    has_scheme = bool(_SCHEME_PREFIX_RE.match(raw))
    target = raw if has_scheme else "//" + raw
    try:
        parts = urlsplit(target)
    except ValueError:
        return None
    scheme = parts.scheme.lower() if has_scheme else ""
    if has_scheme and scheme not in _SUPPORTED_SCHEMES:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    ip = _parse_ip(host)
    if ip is not None:
        normalized_host = str(ip)
    else:
        valid, normalized_host = _valid_dns_host(host)
        if not valid:
            return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    for component in (parts.path, parts.query, parts.fragment):
        if _BAD_PERCENT_RE.search(component):
            return None
        if any(ch.isspace() or ord(ch) < 0x20 or ch in _BAD_URL_CHARS for ch in component):
            return None
    return parts, scheme, normalized_host, port


# so / dex 调试符号、源码路径：无协议时不能当 host。
_FILE_EXT_LABELS = frozenset({
    "c", "cc", "cpp", "cxx", "h", "hpp", "hxx", "hh",
    "rs", "java", "kt", "kts", "go", "py", "proto", "class",
    "so", "a", "o", "png", "jpg", "jpeg", "gif", "webp", "bmp",
    "xml", "html", "htm", "css", "map", "smali", "dex", "jar",
    "aar", "m", "mm", "swift", "gradle", "properties", "json",
    "js", "ts", "tsx", "vue", "scss", "sass", "md", "txt",
    "dat", "bin", "pak", "wasm",
})
_JUNK_PATH_MARKERS = (
    "/home/runner/",
    ".cargo/registry",
    "index.crates.io",
    "termux-android-tools",
    "boringssl/src",
    "resources.arsc",
)
_SOURCE_FILE_LINE_RE = re.compile(
    r"(?i)(?:^|/)[A-Za-z0-9_.+\-]+\.(?:cc|c|cpp|h|hpp|rs|java|kt|go|m)(?::\d+)?$"
)
_ICON_STYLE_RE = re.compile(
    r"^(?:Filled|Outlined|Rounded|TwoTone|Sharp|Material)\.",
)
_PASCAL_TOKEN_RE = re.compile(r"^[A-Z][a-z]+[A-Za-z0-9]*$")


def _is_junk_network_token(raw: str) -> bool:
    """无协议源码文件名、cargo 路径、图标常量等，不是通联地址。"""
    s = (raw or "").strip().strip("\x00")
    if not s or _SCHEME_PREFIX_RE.match(s):
        return False
    low = s.lower()
    if any(p in low for p in _JUNK_PATH_MARKERS):
        return True
    head = s.split("?", 1)[0].split("#", 1)[0]
    if _SOURCE_FILE_LINE_RE.search(head):
        return True
    if _ICON_STYLE_RE.match(s):
        return True
    hostport = head.split("/", 1)[0]
    host = hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport
    if host.startswith("[") and "]" in host:
        return False
    first = host.split(".", 1)[0]
    if _PASCAL_TOKEN_RE.match(first) and "." in host:
        return True
    labels = host.split(".")
    if len(labels) >= 2 and labels[-1].lower() in _FILE_EXT_LABELS:
        if len(labels) == 2:
            return True
        if _PASCAL_TOKEN_RE.match(first):
            return True
    return False


# 包名 / Android authority：urlsplit 能解析，但不是网络定位符。
_NOT_NETWORK_HOST_PREFIXES = (
    "com.android.",
    "com.google.android.",
    "com.huawei.android.",
    "com.hihonor.android.",
    "com.termux.",
    "androidx.",
    "dev.flutter.",
    "dev.fluttercommunity.",
    "io.flutter.",
    "vnd.android.",
    "vnd.google.",
)
_UNIXISH_PATH_MARKERS = (
    "/lib/", "/lib64/", "/usr/", "/files/", "/system/", "/data/",
    "/proc/", "/apex/", "/vendor/",
)
_CERT_GLUE_RE = re.compile(r"\.(?:crl|pem|crt|der)[0-9a-z]", re.IGNORECASE)
_SECOND_SCHEME_RE = re.compile(r"(?:https?|wss?)://", re.IGNORECASE)
_QUERY_TLD_GLUE_RE = re.compile(
    r"\.(?:com|net|org|io)[a-zA-Z]",
    re.IGNORECASE,
)
_SDK_SOURCE_RE = re.compile(
    r"(?i)(?:libzego|libliteav|libbugly|libimsdk|libbyteplus|"
    r"zegoexpress|grs_sdk_)"
)


def _is_sdk_source_file(source_file: str) -> bool:
    """已知广告/直播/统计 SDK 的 so/js/json，其中的 URL 不是样本通联。"""
    name = source_basename(source_file)
    return bool(name and _SDK_SOURCE_RE.search(name))


_JS_REGEX_FLAGS_PATH_RE = re.compile(r"/[igmsuy]{1,6}$", re.IGNORECASE)


def _is_cidr_notation(host: str, path: str, port) -> bool:
    """IPv4/IPv6 + /前缀长度（10.0.0.0/8）是网段，不是 URL。带业务端口的不当 CIDR。"""
    ip = _parse_ip(host)
    if ip is None or port is not None:
        return False
    m = re.fullmatch(r"/(\d{1,3})", (path or "").split("?")[0])
    if not m:
        return False
    n = int(m.group(1))
    return 0 <= n <= (32 if ip.version == 4 else 128)


def _is_well_formed_locator(raw: str, parsed) -> bool:
    """语法闸：必须是单独一条 HTTP/WS URL 或 host[:port][/path]，不管是否可达。"""
    parts, scheme, host, port = parsed
    path = parts.path or ""
    low_host = (host or "").lower()
    if not low_host:
        return False
    if low_host.startswith("vnd."):
        return False
    if any(low_host == p.rstrip(".") or low_host.startswith(p)
           for p in _NOT_NETWORK_HOST_PREFIXES):
        return False
    path_l = path.lower()
    if not scheme:
        if any(m in path_l for m in _UNIXISH_PATH_MARKERS):
            return False
        if path_l.endswith((".so", ".a", ".o", ".jar", ".dex")):
            return False
        if path_l.startswith(("/com.", "/android.", "/kotlin.")):
            return False
    if _parse_ip(host) is not None:
        if _is_cidr_notation(host, path, port):
            return False
        if any(ch in path for ch in "(),"):
            return False
        if _JS_REGEX_FLAGS_PATH_RE.fullmatch((path or "").split("?")[0]):
            return False
    if re.search(r"\)[A-Za-z_]", raw):
        return False
    if re.search(r"Content-Type", raw, re.I) and "content-type=" not in raw.lower():
        return False
    if path_l and _CERT_GLUE_RE.search(path_l):
        return False
    return True


def is_syntax_valid_candidate(raw: str) -> bool:
    """是否为合法 HTTP/WS URL 或无协议网络主机指标。可达性不在此判定。"""
    value = (raw or "").strip().strip("\x00")
    if len(value) < 4 or _is_junk_network_token(value):
        return False
    parsed = _split_candidate(value)
    if parsed is None:
        return False
    return _is_well_formed_locator(value, parsed)


def _canonical_candidate(raw: str, parsed) -> tuple[str, str, str, int | None, str]:
    parts, scheme, host, port = parsed
    userinfo = ""
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0] + "@"
    netloc = userinfo + _netloc(scheme, host, port)
    path = quote(parts.path, safe="/%:@!$&'()*+,;=-._~%")
    query = quote(parts.query, safe="/?@!$&'()*+,;=:-._~%[]")
    fragment = quote(parts.fragment, safe="/?@!$&'()*+,;=:-._~%[]")
    if scheme:
        canonical = urlunsplit((scheme, netloc, path, query, fragment))
    else:
        canonical = netloc + path
        if query:
            canonical += "?" + query
        if fragment:
            canonical += "#" + fragment
    return canonical, scheme, host, port, parts.path or ""


def make_indicator(url: str, source_type: str, source_file: str,
                   method: str = "regex") -> dict | None:
    raw = (url or "").strip().strip("\x00")
    if not raw or len(raw) < 4:
        return None
    if _is_junk_network_token(raw):
        return None
    parsed = _split_candidate(raw)
    if parsed is None or not _is_well_formed_locator(raw, parsed):
        return None
    canonical, scheme, host, port, path = _canonical_candidate(raw, parsed)
    kind = classify_type(raw, host, path)
    rank = url_rank(raw)
    # so 里无 scheme、又不是 host:非常用端口 的点分串，默认不是业务后端。
    if source_type == "native" and not scheme:
        if not (port and port not in (80, 443, 53, 853)):
            if rank == "biz":
                rank = "weak"
    if _is_sdk_source_file(source_file) and rank != "noise":
        rank = "noise"
    return {
        "value": raw,
        "observed_value": raw,
        "type": kind,
        "url": raw,
        "canonical": canonical,
        "scheme": scheme or None,
        "host": host,
        "port": port,
        "path": path,
        "rank": rank,
        "business_likelihood": RANK_SCORE.get(rank, 0.4),
        "validation": {
            "syntax": "valid",
            "dns": "not_checked",
            "http": "not_checked",
        },
        "source_kind": source_type,
        "sources": [{"type": source_type, "file": source_file, "method": method}],
    }


def _merge_key(raw: str) -> str:
    """仅合并同一规范化值；HTTP 与 HTTPS 必须保持独立。"""
    return raw


def merge_indicators(items: list[dict]) -> list[dict]:
    by: dict[str, dict] = {}
    for it in items:
        if not it:
            continue
        raw = it.get("canonical") or it.get("url") or ""
        if not raw:
            continue
        key = _merge_key(raw)
        if key not in by:
            by[key] = dict(it)
            by[key]["sources"] = [dict(s) for s in (it.get("sources") or [])]
            continue
        seen = {(s.get("type"), s.get("file"), s.get("method"))
                for s in by[key]["sources"]}
        for s in it.get("sources") or []:
            sig = (s.get("type"), s.get("file"), s.get("method"))
            if sig not in seen:
                by[key]["sources"].append(dict(s))
                seen.add(sig)
        if RANK_SCORE.get(it.get("rank"), 0) > RANK_SCORE.get(by[key].get("rank"), 0):
            by[key]["rank"] = it.get("rank")
            by[key]["business_likelihood"] = it.get("business_likelihood")
    return sorted(by.values(), key=lambda x: (x.get("rank") != "biz", x.get("url") or ""))


# ---------------------------------------------------------------------------
# 来源标注（产物可读层：人工复核时回答「这条 URL 从哪来的」）
#
# 只做字符串拼装，不参与任何分级判定——加来源标注不得改变 rank，
# 遵守「判定通过即等价」原则：标注是给人看的，不是给算法降级的依据。
# ---------------------------------------------------------------------------

# (source_type, method) -> 中文说明。未收录的退化为 "<type> 来源"。
SOURCE_LABELS: dict[tuple[str, str], str] = {
    ("dex", "string_pool"): "DEX 字符串池明文（包内可直接搜到）",
    ("dex", "decoded"): "DEX 内 base64/hex 解码还原（包内搜不到明文）",
    ("dex", "harvest"): "DEX 常量二次收割（拼接/配置片段）",
    ("dex", "raw_bytes"): "裸 dex 原始字节扫描",
    ("assets", "harvest"): "assets 文件（含 uni-app www）",
    ("resources", "string_pool"): "resources.arsc 字符串池",
    ("native", "so_string"): "原生 .so 内字符串",
    ("manifest", "regex"): "AndroidManifest.xml",
    ("binary", "binary"): "全包二进制扫描",
    ("binary", "binary_deep"): "全包二进制深度兜底扫描",
}


def source_basename(file: str | None) -> str:
    """来源文件只留文件名，避免产物带出本机目录。"""
    if not file:
        return ""
    return str(file).replace("\\", "/").rsplit("/", 1)[-1]


def source_tag(src: dict | None, *, with_file: bool = True) -> str:
    """单条来源 -> `dex/string_pool@classes.dex`。"""
    src = src or {}
    tag = f"{src.get('type') or 'unknown'}/{src.get('method') or '-'}"
    if with_file:
        name = source_basename(src.get("file"))
        if name:
            tag += f"@{name}"
    return tag


def source_label(src: dict | None) -> str:
    """图例用中文说明。"""
    src = src or {}
    return SOURCE_LABELS.get(
        (src.get("type") or "", src.get("method") or ""),
        f"{src.get('type') or 'unknown'} 来源",
    )


def _source_sort_key(src: dict) -> tuple[int, str, str]:
    """来源排序：越具体的越靠前，`binary/*` 全包兜底排最后。

    保证两点：① 输出顺序稳定可复现；② limit 截断时先丢的是信息量最低的兜底来源。
    """
    stype = src.get("type") or "unknown"
    return (1 if stype == "binary" else 0, stype, src.get("method") or "-")


def format_sources(sources: list[dict] | None, *, limit: int = 3) -> str:
    """多条来源并成一行：`dex/string_pool@classes.dex, assets/harvest@cfg.json`。

    超出 limit 条折叠成 `+N`，避免长尾来源把产物撑爆。
    """
    tags: list[str] = []
    seen: set[str] = set()
    for s in sorted(sources or [], key=_source_sort_key):
        t = source_tag(s)
        if t and t not in seen:
            seen.add(t)
            tags.append(t)
    if not tags:
        return "unknown"
    if len(tags) > limit:
        tags = tags[:limit] + [f"+{len(tags) - limit}"]
    return ", ".join(tags)


def display_width(text: str) -> int:
    """终端显示宽度：CJK/全角占 2 列。

    URL 尾巴偶有全角粘连（如 `...guidelines)。`），按 len() 对齐会让该行
    的来源列整列右移，故 padding 一律按显示宽度算。
    """
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
               for c in text or "")


def render_url_line(url: str, sources: list[dict] | None,
                    *, width: int = 0, gap: int = 2, bullet: str = "·") -> str:
    """一行成品：`<URL><padding>· <来源>`。width=0 时按 gap 给固定间隔。

    width 按显示宽度计（见 display_width），不是字符数。
    """
    tag = format_sources(sources)
    if width:
        pad = " " * max(gap, width - display_width(url) + gap)
    else:
        pad = " " * gap
    return f"{url}{pad}{bullet} {tag}"


# ---------------------------------------------------------------------------
# 提取规则（自 analyze.py 平移，唯一去处，勿再回搬）
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# URL 提取
# ---------------------------------------------------------------------------
# 完整 http/https/ws/wss URL（大小写不敏感；不含控制字符，避免二进制粘连）
_URL_SAFE = r"[^\s\"'<>\\`{}^|\x00-\x1f\x7f]"
URL_RE = re.compile(
    r"(?:https?|wss?)://[^\s\"'<>\\`\x00-\x1f\x7f]+",
    re.IGNORECASE,
)
_URL_BYTE_RE = re.compile(
    rb"(?:https?|wss?)://[^\x00-\x1f\x7f-\xff\s\"'<>\\`]{4,2040}"
    rb"(?![^\x00-\x1f\x7f-\xff\s\"'<>\\`])",
    re.IGNORECASE,
)
# resources.arsc / so 里常见 UTF-16LE：h\0t\0t\0p\0s\0:\0/\0/\0...
_URL_UTF16_RE = re.compile(
    rb"(?:h\x00t\x00t\x00p\x00s?\x00|w\x00s\x00s?\x00)"
    rb":\x00/\x00/\x00"
    rb"(?:[\x20-\x7e]\x00){4,2040}(?![\x20-\x7e]\x00)"
    rb"(?![{}^|]\x00)",
    re.IGNORECASE,
)
# 裸 IPv4:port 或 IPv4/path（配置/资源表常不带 scheme）
_IP_PORT_BYTE_RE = re.compile(
    rb"(?<![0-9.])"
    rb"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    rb"(?::\d{1,5}(?:/[^\x00-\x1f\x7f-\xff\s\"'<>\\`{}^|]{0,2020})?"
    rb"|/[^\x00-\x1f\x7f-\xff\s\"'<>\\`{}^|]{1,2020})"
    rb"(?![^\x00-\x1f\x7f-\xff\s\"'<>\\`{}^|])"
)
# 裸 IPv4，要求带端口或路径（避免匹配普通数字串）: 192.168.1.1:8080/api
IP_HOST_RE = re.compile(
    rf'(?<![\w.])(?:\d{{1,3}}\.){{3}}\d{{1,3}}(?::\d{{1,5}}(?:/{_URL_SAFE}*)?|/{_URL_SAFE}*)'
)
# 方括号 IPv6，同样要求端口或路径；地址合法性交给 ipaddress。
# lookbehind 只排除紧贴的冒号（避免从更长的 :[addr] 里切），字母（含 a-f）可紧贴，
# 二进制里常见 pad[2001:db8::1]:8080 这种无分隔形态。
_IPV6_BARE_RE = re.compile(
    r'(?<!:)\[([0-9a-fA-F:.]{2,45})\]'
    rf'(?::\d{{1,5}}(?:/{_URL_SAFE}*)?|/{_URL_SAFE}+)'
)
_IPV6_HOSTPORT_RE = re.compile(
    r'^\[([0-9a-fA-F:.]{2,45})\](?::(\d{1,5}))?$',
    re.IGNORECASE,
)
_IPV6_PORT_BYTE_RE = re.compile(
    rb'(?<!:)\['
    rb'[0-9a-fA-F:.]{2,45}'
    rb'\]'
    rb'(?::\d{1,5}(?:/[^\x00-\x1f\x7f-\xff\s\"\'<>\\`{}^|]{0,1980})?'
    rb'|/[^\x00-\x1f\x7f-\xff\s\"\'<>\\`{}^|]{1,1980})'
    rb'(?![^\x00-\x1f\x7f-\xff\s\"\'<>\\`{}^|])'
)
# www. 开头的域名（强信号，几乎不会误报）
WWW_RE = re.compile(rf'(?<![\w.])www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}(?:{_URL_SAFE}*)?')
# 无 scheme 的域名，要求合法 TLD 形态且带端口或路径，降低与包名/类名的误报
# 裸域名只约束 TLD 语法，不维护必然过时的后缀白名单。DNS/PSL 状态由验证层给出。
_TLDS = r'(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})'
DOMAIN_RE = re.compile(
    rf'(?<![\w.])[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?'
    rf'(?:\.[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?)*'
    rf'\.{_TLDS}(?::\d{{1,5}}(?:/{_URL_SAFE}*)?|/{_URL_SAFE}*)',
    re.IGNORECASE,
)
# 无 scheme、无端口/路径的裸域名（uni-app JS 常写 "api.xxx.cn"）
_BARE_HOST_RE = re.compile(
    r'(?<![\w.])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.'
    + _TLDS
    + r'(?![\w.:/])',
    re.IGNORECASE,
)
# Java 包名前缀，避免把 com.example.app 当 host
_PKG_FIRST_LABELS = frozenset({
    "com", "org", "net", "io", "android", "java", "javax", "kotlin", "cn",
})

# ---------------------------------------------------------------------------
# 业务 URL 过滤（丢掉框架/SDK 噪音，留下样本自己的后端）
# ---------------------------------------------------------------------------
_NOISE_SUBSTR = (
    "schemas.android.com", "xmlpull.org", "slf4j.org", "w3.org",
    "xml.apache.org", "java.sun.com", "developer.android",
    "b.android.com",
    "googleapis.com", "accounts.google.com", "plus.google.com",
    "maps.googleapis", "googleblog.com", "google.github.io",
    "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
    "youtube.com", "youtu.be", "youtube.googleapis",
    "dcloud.net.cn", "dcloud.io", "ask.dcloud.",
    "imtt.qq.com", "html5.qq.com", "tbs.qq.com", "debugtbs.qq.com",
    "debugx5.qq.com", "mqqad.html5", "pms.mb.qq.com",
    "jetbrains.com", "youtrack.jetbrains",
    "exoplayer", "github.com", "sourceforge.net",
    "example.com", "localhost", "ns.adobe.com",
    "microsoft.com/drm", "smpte-ra.org", "itunes.apple.com",
    "paypal.com", "twitch.tv", "vimeo.com", "coub.com",
    "attheme.org", "stripe.com/docs", "stripe.com/api",
    "android-developers.googleblog", "ccil.org",
    "shibatch.sourceforge", "null.sun.com",
    "jsdelivr.net", "unpkg.com", "bootcdn.cn", "cdnjs.cloudflare",
    # dump dex 里 WebView / XML 解析器常量
    "apache.org/xml", "xml.org/sax", "xml.org/trax",
    "exslt.org", "crbug.com", "chromium.org", "googlesource.com",
    "bugs.chromium", "aomedia.org", "javax.xml", "relaxng.org",
    "xsl.lotus.com", "alphaworks.ibm.com", "webaddress.elided",
    "digicert-ct.com", "w3.org/1999", "w3.org/2000", "w3.org/tr/",
    "ietf.org", "oasis-open.org", "unicode.org", "openjdk.org",
    "oracle.com/technetwork", "jcp.org",
    # 证书链 / CRL / OCSP 碎片（DEX 字符串池常带尾巴）
    "entrust.net", "geotrust.com", "verisign.com", "godaddy.com",
    "letsencrypt.org", "digicert.com", "startssl.com", "wosign.com",
    "identrust.com", "amazontrust.com", "usertrust.com", "thawte.com",
    "starfieldtech.com", "public-trust.com", "crash.163.com",
    "119.29.29.98",
    "configgetsvc", "rainbowapi.configs",
)
_NOISE_PREFIX = ("android.", "androidx.", "kotlin.", "java.", "javax.")
_NOISE_HOST_ROOTS = (
    "baidu.com", "baifubao.com", "bdstatic.com", "amap.com",
    "vuejs.org", "alipay.com", "live.com", "yahoo.com",
    "stripe.com", "ip-api.com", "google.com", "android.com",
    "m3w.cn", "shareinstall.com.cn", "ntsc.ac.cn",
    "qq.com", "umeng.com", "jpush.cn", "getui.com", "pgyer.com",
    "sentry.io", "jquery.com", "bootstrapcdn.com",
    "apache.org", "xml.org", "w3.org", "ietf.org",
    "chromium.org", "crbug.com", "aomedia.org",
    "googlesource.com", "oasis-open.org", "unicode.org",
    "java.net", "openjdk.org", "jcp.org",
    "myqcloud.com", "qcloud.com", "tencent.com", "googleapis.cn",
    "ffmpeg.org", "byteintl.com", "iccvlog.com", "21cn.com",
    # Flutter AOT / Go 二进制字符串池里带出的 SDK 域名（湖州小众通联批次实测）
    "flutter.dev", "igexin.com", "meizu.com", "flyme.cn",
    # Go 二进制模块路径（2026-09-02 批次实测：google.golang.org 4093 条 +
    # go.uber.org 759 条灌满 weak 档，真实信号被淹没）。
    # 注意：Go 串池的长度前缀字节常粘成数字前缀（0google.golang.org、
    # 1google.golang.org…），靠 endswith(".golang.org") 后缀匹配仍能全覆盖。
    "golang.org", "go.uber.org",
    # 同性质的框架/SDK 字符串（实测 webrtc.org 126 条、plugins.flutter.io 24 条）
    "webrtc.org", "plugins.flutter.io",
    # 公共搜索 / 播放器 / 官网 CDN：有路径也会被抬成 biz，必须进 noise
    "bing.com", "brave.com", "duckduckgo.com",
    "videolan.org", "dashif.org", "mql5.com", "mql4.com",
    "bigo.live", "smart-glocal.com",
    "tencent-cloud.com", "alibaba.com",
    "libcore.icu.icu", "mi1.cc",
    # 2026-09-08 重跑：IM/直播/广告 SDK 带 /v2/ 或灰产 TLD，被抬成 biz
    "zego.im", "kugou.com", "netease.im",
    "pangolin-sdk-toutiao.com", "pangolin-sdk-toutiao-b.com",
    "mozilla.org", "bytedance.com",
    "telegram.org", "nextcloud.com",
    # 2026-09-09：公共基础设施用形态过滤；下列是普通 .com 漏网
    "weibo.com", "oceanengine.com", "sigmob.cn",
    "hicloud.com", "dbankcloud.ru", "dbankcloud.com",
    "cmpassport.com", "rustdesk.com", "curl.se", "docs.rs",
    "dartbug.com", "zegocloud.com", "flutter.io",
    "ip.sb", "ipify.org", "seeip.org",
)
# 公共 DNS / 模拟器：端口常不是 80/443，旧规则会误抬成 biz
_PUBLIC_DNS_IPS = frozenset({
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "223.5.5.5", "223.6.6.6",
    "114.114.114.114", "114.114.115.115",
    "119.29.29.29", "119.28.28.28",
    "180.76.76.76", "168.95.1.1",
    "1.12.12.12", "120.53.53.53",
})
_PUBLIC_DNS_V6 = frozenset({
    ipaddress.IPv6Address("2001:4860:4860::8888"),
    ipaddress.IPv6Address("2001:4860:4860::8844"),
    ipaddress.IPv6Address("2606:4700:4700::1111"),
    ipaddress.IPv6Address("2606:4700:4700::1001"),
    ipaddress.IPv6Address("2620:fe::fe"),
    ipaddress.IPv6Address("2620:fe::9"),
    ipaddress.IPv6Address("2400:3200::1"),
    ipaddress.IPv6Address("2400:3200:baba::1"),
    ipaddress.IPv6Address("2400:da00::6666"),
})
_EMULATOR_IPS = frozenset({"10.0.2.2", "10.0.2.3", "10.0.3.2"})
_DNS_PORTS = frozenset({53, 853})
# CSS/布局字段被拼成 host（如 lineheightstyle.alignment.top）
_CODE_HOST_LABELS = frozenset({
    "alignment", "lineheight", "lineheightstyle", "fontweight", "fontsize",
    "textalign", "textstyle", "letterspacing", "wordspacing",
    "padding", "margin", "baseline", "leading", "decoration",
    "flexbox", "flexgrow", "flexshrink", "justifycontent",
})
# 移动端 / CDN 常见单字母子域；其它单字母标签仍视为假 host
_SINGLE_CHAR_LABEL_ALLOW = frozenset("msivwtu")
_LOG_INFO_LABELS = frozenset({
    "logger", "log", "error", "debug", "warn", "warning", "info", "verbose",
    "trace", "level", "le", "a", "x", "y", "z",
})


def _looks_plausible_url(u: str) -> bool:
    """丢掉 logger.info / a.x.info / 7.error.cn / 非白名单单字母标签等假 host。

    合法 IPv4/IPv6 直接放行（噪音由 is_noise_url 处理）。
    单字母子域只放行 m/s/i/v/w/t/u（m.api.xxx.com）；a.myservice.com 仍拒。
    两字符 SLD（jd.com）放行，不再用「非 TLD 标签全 ≤2」一刀切。
    """
    host = _host_of(u)
    if not host:
        return False
    if _parse_ip(host) is not None:
        return True
    if len(host) < 4:
        return False
    labels = host.split(".")
    if len(labels) < 2 or any(len(lab) == 0 for lab in labels):
        return False
    if any(
        len(lab) == 1 and not lab.isdigit() and lab.lower() not in _SINGLE_CHAR_LABEL_ALLOW
        for lab in labels[:-1]
    ):
        return False
    # 数字开头短标签 + 普通词中间层：7.error.cn / 1.logger.info
    # （360.cn / 163.com 这类「数字.TLD」两标签真域名放行）
    if labels[0].isdigit() and len(labels[0]) <= 3 and len(labels) >= 3:
        return False
    if labels[-1] == "info" and labels[-2].lower() in _LOG_INFO_LABELS:
        return False
    return not (
        labels[-2].lower() in ("error", "logger", "debug", "verbose")
        and labels[-1] in ("cn", "com", "net", "org", "info")
    )


# ---------------------------------------------------------------------------
# 业务提取规则（新样本漏报：把键名 / TLD / 路径形态加到这张表，再补一条测试）
# ---------------------------------------------------------------------------
# 灰产常用 TLD：带 scheme 时抬成 biz；无协议裸域名不再单靠 TLD 进 biz。
# 例外：无协议但首标签是 api/apis 的灰产 host（助手小智 api.*.shop）。
_GRAY_TLD_LABELS = frozenset({
    "shop", "top", "xyz", "vip", "cc", "im", "icu", "fun", "club",
    "online", "site", "live", "store", "wang", "xin", "work", "cfd",
    "bond", "click", "cyou", "rest", "today", "cloud", "tech", "sbs",
})
_GRAY_TLD = r'(?:' + "|".join(sorted(_GRAY_TLD_LABELS, key=len, reverse=True)) + ")"
# 非常用端口抬 biz：最后一节必须是可识别 TLD（ccTLD 两字母另判），挡住 i.length:16
_PORT_BIZ_TLDS = _GRAY_TLD_LABELS | frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "biz", "info",
    "pro", "name", "mobi", "asia", "aero", "coop", "app", "dev",
    "zip", "chat", "blog", "news", "page", "wiki", "host", "space",
    "website", "email", "link", "group", "ltd", "llc", "games",
})
_CAMEL_LABEL_RE = re.compile(r"[a-z][A-Z]")
_HOST_LIST_RE = re.compile(
    r"(?:domainList|hostList|urlList|apiList|serverList|domain_list|host_list)"
    r"\s*[:=]\s*\[([^\]]*)\]",
    re.IGNORECASE,
)
_CONFIG_KEY_PATTERN = (
    r"baseUrl|base_url|apiUrl|api_url|apiHost|api_host|serverUrl|serverHost|"
    r"commonUrl|requestUrl|h5Url|hostUrl|ossUrl|uploadUrl|cdnUrl|wsUrl|wssUrl|"
    r"imUrl|BASE_URL|API_URL|API_HOST|BASE_HOST|SERVER_URL|APP_URL|H5_URL"
)
_CONFIG_ASSIGN_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<key>{_CONFIG_KEY_PATTERN})"
    r"\s*[:=]\s*(?:['\"](?P<quoted>[^'\"]+)['\"]|"
    r"(?P<bare>(?:https?|wss?)://[^\s'\"#,;]+))",
    re.IGNORECASE,
)
_JSON_URL_FIELD_RE = re.compile(
    r"['\"](?P<key>url|baseUrl|apiUrl|apiHost|host|domain|server|"
    r"endpoint|origin|cdn|oss|upload|wss|wsHost)['\"]\s*:\s*"
    r"['\"](?P<value>[^'\"]+)['\"]",
    re.IGNORECASE,
)
_CONCAT_PATH_RE = re.compile(
    r"(?P<key>commonUrl|baseUrl|apiUrl|requestUrl|serverUrl)"
    r"\s*\+\s*['\"](?P<path>/[^'\"]+)['\"]",
    re.IGNORECASE,
)
_PHP_PATH_RE = re.compile(r"/(?:index|api|app|admin)\.php/[A-Za-z0-9_./-]+")
_PHP_STATIC_RE = re.compile(r"/static/[A-Za-z0-9_./-]+\.php")
_QUOTED_API_PATH_RE = re.compile(
    r"['\"](/(?:index|api|app|admin)\.php/[^'\"]+"
    r"|/(?:api|v[12])/[A-Za-z0-9_./-]+"
    r"|/static/[^'\"]+\.php)['\"]"
)
_QUOTED_GRAY_HOST_RE = re.compile(
    r"['\"]([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\."
    + _GRAY_TLD
    + r")['\"]",
    re.IGNORECASE,
)
_QUOTED_HOST_RE = re.compile(
    r"['\"]([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\."
    + _TLDS
    + r")['\"]",
    re.IGNORECASE,
)
_SCHEME_RE = re.compile(r"^(?:https?|wss?)://", re.IGNORECASE)

_DEX_HARVEST_HINTS = (
    "http://", "https://", "ws://", "wss://",
    "domainList", "hostList", "baseUrl", "baseURL", "apiUrl",
    "index.php", "BASE_URL", "API_URL", "commonUrl",
)

def _host_of(url: str) -> str:
    """取 host（小写）。IPv6 字面量取方括号内地址。"""
    parsed = _split_candidate((url or "").strip())
    return parsed[2] if parsed is not None else ""


def _url_port_and_path(url: str) -> tuple[int | None, str]:
    """从 URL 里拆端口和路径（不含 query）。"""
    parsed = _split_candidate((url or "").strip())
    if parsed is None:
        return None, ""
    parts, _scheme, _host, port = parsed
    return port, parts.path or ""


def _looks_code_host(host: str) -> bool:
    """CSS/布局字段拼出来的假 host，不是域名。"""
    labels = (host or "").lower().split(".")
    return any(lab in _CODE_HOST_LABELS for lab in labels[:-1])


def _host_variants_for_noise(host: str) -> list[str]:
    """Go 串池长度前缀：0github.com / 0google.golang.org 归一到真实 host。"""
    host = (host or "").lower()
    out = [host]
    m = re.match(r"^(\d{1,4})([a-z][a-z0-9\-]*\..+)$", host)
    if m:
        out.append(m.group(2))
    return out


def _host_matches_root(host: str, root: str) -> bool:
    root = (root or "").lower()
    return any(h == root or h.endswith("." + root) for h in _host_variants_for_noise(host))


def _is_infra_shape(host: str, path: str) -> bool:
    """证书 / DoH / 阿里云 NLS：按形态过滤，不靠域名追名单。"""
    path_l = (path or "").split("?")[0].lower().rstrip("/")
    host_l = (host or "").lower()
    if path_l.endswith("/dns-query") or path_l == "dns-query":
        return True
    if path_l.endswith(".crl") or "/crl/" in (path or "").lower():
        return True
    if "/ocsp" in (path or "").lower():
        return True
    first = host_l.split(".")[0]
    if first in ("ocsp", "crl"):
        return True
    if host_l.endswith(".aliyuncs.com") and re.search(r"(^|\.)nls[-.]", host_l):
        return True
    return False


def is_noise_url(u: str) -> bool:
    """框架文档、系统 schema、SDK 埋点等，不是样本业务后端。"""
    u = (u or "").strip().strip("\x00")
    if not u or len(u) < 8:
        return True
    if u in ("http://www", "https://www", "http://localhost", "https://localhost"):
        return True
    if u.endswith("://") or "%s" in u or "${" in u:
        return True
    low = u.lower()
    if low.startswith(_NOISE_PREFIX) and "://" not in u:
        return True
    host = _host_of(u)
    if not host:
        return True
    # 域名规则按 host 边界匹配；带路径/普通关键词的规则才做子串匹配。
    # 避免 query 里嵌套的外部 URL（?u=https://github.com/...）整条被误杀
    no_q = low.split("?", 1)[0].split("#", 1)[0]
    for n in _NOISE_SUBSTR:
        if "/" in n or "." not in n:
            if n in no_q:
                return True
            continue
        if _host_matches_root(host, n):
            return True
    port, path = _url_port_and_path(u)
    if (path or "").split("?")[0].rstrip("/").endswith("/netcheck"):
        return True
    if _is_infra_shape(host, path):
        return True
    ip = _parse_ip(host)
    if ip is not None:
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return True
        if ip.version == 4:
            dotted = str(ip)
            if dotted.startswith("0.") or dotted in _PUBLIC_DNS_IPS or dotted in _EMULATOR_IPS:
                return True
        else:
            if ip in _PUBLIC_DNS_V6:
                return True
            mapped = getattr(ip, "ipv4_mapped", None)
            if mapped is not None and (
                str(mapped) in _PUBLIC_DNS_IPS or str(mapped) in _EMULATOR_IPS
            ):
                return True
        return port in _DNS_PORTS
    if "." not in host:
        return True
    if _looks_code_host(host):
        return True
    if any(_host_matches_root(host, root) for root in _NOISE_HOST_ROOTS):
        return True
    # XML namespace / SAX feature 形态
    if any(p in low for p in ("/xml/features", "/sax/features", "/sax/properties",
                              "/trax/features", "/ns/structure")):
        return True
    check = u if "://" in u else "http://" + u
    return not _looks_plausible_url(check)


_GRAY_TLD_HOST_RE = re.compile(r"\." + _GRAY_TLD + r"$", re.IGNORECASE)


def _host_ok_for_unusual_port(host: str) -> bool:
    """非常用端口抬 biz 时，host 必须是 IP 或带可识别 TLD 的域名。

    挡住 JS/二进制碎片：i.length:16、xmp.did:50、t.audioBitrate:1。
    """
    if _parse_ip(host or "") is not None:
        return True
    labels = (host or "").split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1].lower()
    if not ((len(tld) == 2 and tld.isalpha()) or tld in _PORT_BIZ_TLDS):
        return False
    return not any(_CAMEL_LABEL_RE.search(lab) for lab in labels)


def url_rank(u: str) -> str:
    """通联分级（字符串层）：noise=公共基础设施，biz=样本业务后端，weak=像 URL 但证据不足。

    不再用 /api/、/v2/、/login 单独抬 biz（广告/云 SDK 同样带这些路径）。
    可达性不参与分级。
    """
    u = (u or "").strip().strip("\x00")
    if not u or _is_junk_network_token(u) or is_noise_url(u):
        return "noise"
    parsed = _split_candidate(u)
    if parsed is None or not _is_well_formed_locator(u, parsed):
        return "noise"
    host = _host_of(u)
    low = u.lower()
    port, path = _url_port_and_path(u)
    path_only = (path or "").split("?")[0]
    has_scheme = bool(_SCHEME_PREFIX_RE.match(u))
    has_php = ".php" in path_only.lower()
    first = (host or "").split(".")[0]
    if _parse_ip(host or "") is not None:
        # 硬编码 IP 带路径或非常用端口，视为通联；80/443 裸 IP 证据不足
        if has_php or path_only not in ("", "/"):
            return "biz"
        if port and port not in (80, 443):
            return "biz"
        return "weak"
    if (
        port and port not in (80, 443) and port not in _DNS_PORTS
        and _host_ok_for_unusual_port(host)
    ):
        return "biz"
    if host and _GRAY_TLD_HOST_RE.search(host):
        if has_scheme or first in ("api", "apis"):
            return "biz"
    if has_php:
        return "biz"
    if has_scheme and first in ("api", "apis", "gateway", "gw"):
        return "biz"
    if low.startswith(("ws://", "wss://")):
        return "biz"
    return "weak"


def fold_related_urls(urls: set[str]) -> set[str]:
    """只做空值清理；不同协议、query 和 fragment 都是独立观测证据。"""
    return {u for u in urls if u}


def _weak_has_signal(u: str) -> bool:
    """weak 是否值得写入清单：有路径、非常用端口、IP，或 api/gw 前缀。"""
    host = _host_of(u)
    port, path = _url_port_and_path(u)
    path_only = (path or "").split("?")[0]
    if _parse_ip(host or "") is not None:
        return True
    if port and port not in (80, 443) and _host_ok_for_unusual_port(host):
        return True
    if path_only not in ("", "/"):
        return True
    first = (host or "").split(".")[0]
    return first in ("api", "apis", "gateway", "gw", "im", "oss")


def weak_worth_listing(u: str) -> bool:
    """写进 urls_by_rank.txt 的 weak：要有路径、非常用端口、IP，避免裸域名刷屏。"""
    return url_rank(u) == "weak" and _weak_has_signal(u)


def business_urls(urls: set[str]) -> set[str]:
    """只保留通联（灰产 TLD / 硬编码 IP / .php / api. 主机 / ws）。"""
    return {u.strip("\x00") for u in urls if u and url_rank(u) == "biz"}

# ---------------------------------------------------------------------------
# 端点提取
# ---------------------------------------------------------------------------
# RFC3986 path 字符（pchar 含 % @ : 等），末尾的 '-' 是字面量不是区间
_ENDPOINT_CHARS = r"A-Za-z0-9._~!$&'()*+,;=:@%-"
ENDPOINT_RE = re.compile(r'^/[' + _ENDPOINT_CHARS + r'/]+$')
# 相对路径端点：v1/user/info（要求 >=2 段、全小写/数字，控制噪音）
REL_ENDPOINT_RE = re.compile(r'^[a-z0-9][a-z0-9_.~-]*(?:/[a-z0-9][a-z0-9_.~-]*)+$')

# 明显是文件/资源路径的噪音，排除掉
ENDPOINT_EXT_BLACKLIST = (".xml", ".png", ".jpg", ".jpeg", ".gif", ".json", ".so", ".jar",
                          ".dex", ".html", ".css", ".js", ".ttf", ".mp3", ".mp4", ".zip", ".apk")

# Android/Linux 文件系统根目录，这些不是 API
FS_PREFIXES = ("/proc/", "/sys/", "/dev/", "/system/", "/data/", "/sdcard/", "/storage/",
               "/mnt/", "/cache/", "/etc/", "/apex/", "/vendor/", "/odm/", "/product/",
               "/acct/", "/config/", "/root/", "/sbin/", "/lib/", "/lib64/", "/usr/",
               "/bin/", "/opt/", "/home/", "/tmp/", "/var/", "/run/", "/boot/", "/media/")


def _clean_url(s: str) -> str:
    s = (s or "").strip().strip("\x00")
    # 只剥离明显不配对的宿主文本闭合符；不得删除 URL 合法的 / ; ! . 等尾字符。
    while s.endswith(")") and s.count(")") > s.count("("):
        s = s[:-1]
    while s.endswith("]") and s.count("]") > s.count("["):
        s = s[:-1]
    return _trim_binary_glue(s)


def _trim_binary_glue(s: str) -> str:
    """二进制扫描常把下一条字符串粘在 URL 后面；截成单独一条，保留前缀通联。"""
    schemes = list(_SECOND_SCHEME_RE.finditer(s))
    if len(schemes) >= 2:
        for m in schemes[1:]:
            prev = s[m.start() - 1] if m.start() else ""
            if prev in "=&#":
                continue
            s = s[:m.start()]
            break
    m = re.search(r"\)[A-Za-z_]", s)
    if m:
        s = s[:m.start()]
        while s.endswith(")") and s.count(")") > s.count("("):
            s = s[:-1]
    m = re.search(r"Content-Type", s, re.I)
    if m and "content-type=" not in s.lower():
        s = s[:m.start()].rstrip("/?&=;._-")
    if "?" in s:
        pre, query = s.split("?", 1)
        qm = _QUERY_TLD_GLUE_RE.search(query)
        if qm:
            s = pre + "?" + query[:qm.end() - 1]
    return s


def _utf16le_to_ascii(blob: bytes) -> str:
    """把 UTF-16LE 交错字节收成 ASCII 串（失败则空）。"""
    if len(blob) < 2:
        return ""
    text = blob.decode("utf-16le", errors="ignore")
    return "".join(ch for ch in text if ch.isprintable() or ch in "/:?&=#%+.-_")


def _scan_raw_for_urls(raw: bytes) -> set[str]:
    """从任意二进制里抠 URL（ASCII / UTF-16LE / 裸 IPv4:port / 方括号 IPv6）。"""
    found: set[str] = set()
    if not raw:
        return found
    full_matches = list(_URL_BYTE_RE.finditer(raw))
    full_spans = [match.span() for match in full_matches]
    for m in full_matches:
        u = _clean_url(m.group().decode("ascii", errors="ignore"))
        if is_syntax_valid_candidate(u):
            found.add(u)
    for m in _URL_UTF16_RE.finditer(raw):
        u = _clean_url(_utf16le_to_ascii(m.group()))
        if "://" in u and is_syntax_valid_candidate(u):
            found.add(u)
    for m in _IP_PORT_BYTE_RE.finditer(raw):
        if any(start < m.end() and m.start() < end for start, end in full_spans):
            continue
        hostpath = m.group().decode("ascii", errors="ignore")
        if not hostpath:
            continue
        u = _clean_url(hostpath)
        if is_syntax_valid_candidate(u) and not is_noise_url(u):
            found.add(u)
    for m in _IPV6_PORT_BYTE_RE.finditer(raw):
        if any(start < m.end() and m.start() < end for start, end in full_spans):
            continue
        blob = m.group().decode("ascii", errors="ignore")
        inner = blob[1:blob.find("]")] if blob.startswith("[") and "]" in blob else ""
        if _parse_ip(inner) is None:
            continue
        u = _clean_url(blob)
        if is_syntax_valid_candidate(u) and not is_noise_url(u):
            found.add(u)
    return found



def _mask(s: str, matches) -> str:
    """把 matches 覆盖的区间替换成空格，返回剩余文本。"""
    if not matches:
        return s
    parts, prev = [], 0
    for m in matches:
        parts.append(s[prev:m.start()])
        prev = m.end()
    parts.append(s[prev:])
    return " ".join(parts)


def _is_package_like_host(host: str) -> bool:
    first = (host or "").split(".")[0].lower()
    return first in _PKG_FIRST_LABELS


def _iter_urls(s: str):
    """从单个字符串常量里迭代出各类 URL。

    按优先级「完整 URL -> IPv4 -> IPv6 -> www -> 带路径裸域名 -> 裸 host」逐级提取并掩码，
    避免低优先级规则在高优先级 URL 的子串上产生幻影匹配（如 https:// 里的 host/path）。
    注意：不做 `//host` 协议相对匹配——`//` 在 dex 字符串里更多是 base64 或
    content:// 片段的噪音；真正的协议相对域名由裸域名规则兜底。
    """
    full = list(URL_RE.finditer(s))
    for m in full:
        u = _clean_url(m.group(0))
        if not u.endswith("://") and is_syntax_valid_candidate(u):
            yield u
    s = _mask(s, full)

    ip = list(IP_HOST_RE.finditer(s))
    for m in ip:
        u = _clean_url(m.group(0))
        if is_syntax_valid_candidate(u):
            yield u
    s = _mask(s, ip)

    ipv6 = list(_IPV6_BARE_RE.finditer(s))
    for m in ipv6:
        if _parse_ip(m.group(1)) is None:
            continue
        u = _clean_url(m.group(0))
        if is_syntax_valid_candidate(u):
            yield u
    s = _mask(s, ipv6)

    www = list(WWW_RE.finditer(s))
    for m in www:
        u = _clean_url(m.group(0))
        if is_syntax_valid_candidate(u):
            yield u
    s = _mask(s, www)

    dom = list(DOMAIN_RE.finditer(s))
    for m in dom:
        u = _clean_url(m.group(0))
        if is_syntax_valid_candidate(u):
            yield u
    s = _mask(s, dom)

    for m in _BARE_HOST_RE.finditer(s):
        u = _clean_url(m.group(0))
        host = u.split("/")[0].split(":")[0]
        if (not _is_package_like_host(host)
                and is_syntax_valid_candidate(u)):
            yield u


def _is_abs_endpoint(p: str) -> bool:
    if len(p) < 3:  # 至少 '/xy'，丢弃 /a /x 之类单字符噪音
        return False
    segs = p.split("/")[1:]  # 去掉开头的空段（p 以 '/' 开头）
    if any(seg in ("", ".", "..") for seg in segs):
        return False
    low = p.lower()
    if low.endswith(ENDPOINT_EXT_BLACKLIST):
        return False
    return not low.startswith(FS_PREFIXES)


def _is_rel_endpoint(p: str) -> bool:
    segs = p.split("/")
    if any(seg in ("", ".", "..") for seg in segs):
        return False
    return not p.lower().endswith(ENDPOINT_EXT_BLACKLIST)


def _collect_endpoint(s: str, out: set[str]) -> None:
    # 先剥 query/fragment，再对路径部分做整串匹配（保持「整串=路径」的噪音控制）
    cand = s.split("?", 1)[0].split("#", 1)[0].strip()
    if not cand:
        return
    if cand.startswith("/"):
        if ENDPOINT_RE.match(cand) and _is_abs_endpoint(cand):
            out.add(cand)
    else:
        if REL_ENDPOINT_RE.match(cand) and _is_rel_endpoint(cand):
            out.add(cand)



def _is_ws_base(base: str) -> bool:
    return base.lower().startswith(("ws://", "wss://"))


def _looks_like_api_path(p: str) -> bool:
    pl = (p or "").split("?", 1)[0].lower()
    if len(pl) < 3 or not pl.startswith("/"):
        return False
    if pl.endswith(ENDPOINT_EXT_BLACKLIST):
        return False
    if "/index.php/" in pl or "/api.php/" in pl or pl.endswith(".php"):
        return True
    if pl.startswith(("/api/", "/v1/", "/v2/", "/app/", "/admin/")):
        return True
    return "/home/" in pl


def _join_base_path(base: str, path: str) -> str:
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def _normalize_base(value: str) -> list[str]:
    """配置值 -> 保真、语法合法的 origin/前缀；绝不猜测协议。"""
    v = (value or "").strip().strip("\x00").strip()
    if not v or len(v) > 180 or " " in v or "\n" in v:
        return []
    if "${" in v or "%s" in v:
        return []
    u = _clean_url(v)
    return [u] if is_syntax_valid_candidate(u) else []


def _ingest_config_value(
    value: str,
    urls: set[str],
    endpoints: set[str],
) -> list[str]:
    v = (value or "").strip()
    if not v:
        return []
    if v.startswith("/"):
        path = v.split("?", 1)[0]
        if _looks_like_api_path(path):
            endpoints.add(path)
        return []
    normalized = _normalize_base(v)
    for b in normalized:
        urls.add(b)
    return normalized


def _collect_api_paths(text: str, endpoints: set[str]) -> set[str]:
    paths: set[str] = set()
    for p in _PHP_PATH_RE.findall(text):
        paths.add(p)
    for p in _PHP_STATIC_RE.findall(text):
        paths.add(p)
    for p in _QUOTED_API_PATH_RE.findall(text):
        paths.add(p.split("?", 1)[0])
    for match in _CONCAT_PATH_RE.finditer(text):
        paths.add(match.group("path").split("?", 1)[0])
    for p in paths:
        endpoints.add(p)
    return paths


def _harvest_config(text: str, urls: set[str], endpoints: set[str]) -> None:
    """收割配置值；只按同名变量的显式拼接关系还原 URL。"""
    bases_by_name: dict[str, set[str]] = {}
    for m in _HOST_LIST_RE.finditer(text):
        for d in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            _ingest_config_value(d, urls, endpoints)
    for m in _CONFIG_ASSIGN_RE.finditer(text):
        values = _ingest_config_value(
            m.group("quoted") or m.group("bare"), urls, endpoints,
        )
        bases_by_name.setdefault(m.group("key").lower(), set()).update(values)
    for m in _JSON_URL_FIELD_RE.finditer(text):
        values = _ingest_config_value(m.group("value"), urls, endpoints)
        bases_by_name.setdefault(m.group("key").lower(), set()).update(values)
    for h in _QUOTED_GRAY_HOST_RE.findall(text):
        _ingest_config_value(h, urls, endpoints)
    for h in _QUOTED_HOST_RE.findall(text):
        if _is_package_like_host(h):
            continue
        _ingest_config_value(h, urls, endpoints)

    _collect_api_paths(text, endpoints)
    for match in _CONCAT_PATH_RE.finditer(text):
        path = match.group("path").split("?", 1)[0]
        for b in bases_by_name.get(match.group("key").lower(), set()):
            if _is_ws_base(b):
                continue
            joined = _join_base_path(b, path)
            if is_syntax_valid_candidate(joined):
                urls.add(joined)


def _maybe_harvest_dex_string(s: str, urls: set[str], endpoints: set[str]) -> None:
    if len(s) < 20:
        return
    if not any(h in s for h in _DEX_HARVEST_HINTS):
        return
    _harvest_config(s, urls, endpoints)


# ---------------------------------------------------------------------------
# 编码还原：盲解 base64/hex，命中 URL 判定器才采信（decode-then-validate）
# ---------------------------------------------------------------------------
_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_ALPHABET = frozenset("0123456789abcdefABCDEF")
_B64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,1022}={0,2}(?![A-Za-z0-9+/_-])"
)
_HEX_TOKEN_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,1024}(?![0-9A-Fa-f])")


def _is_texty(text: str) -> bool:
    """解码结果是可读文本（可打印率 ≥ 90%）才继续，挡住二进制垃圾。"""
    if not text or len(text) < 8:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\t\r\n")
    return printable / len(text) >= 0.9


def _decode_b64_variants(s: str) -> list[str]:
    """标准 base64 + urlsafe base64，容忍去掉 padding，返回解出的 UTF-8 文本。"""
    out: list[str] = []
    body = s.rstrip("=")
    for variant in (body, body.replace("-", "+").replace("_", "/")):
        if any(c not in _B64_ALPHABET for c in variant):
            continue
        rem = len(variant) % 4
        if rem == 1:
            continue
        pad = "=" * ((4 - rem) % 4)
        try:
            raw = base64.b64decode(variant + pad, validate=True)
        except (ValueError, binascii.Error):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text and _is_texty(text) and text not in out:
            out.append(text)
    return out


def _decode_hex_variants(s: str) -> list[str]:
    """偶数长纯 hex 串解码为 UTF-8 文本。"""
    if len(s) < 16 or len(s) % 2 != 0:
        return []
    if any(c not in _HEX_ALPHABET for c in s):
        return []
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return [text] if _is_texty(text) else []


def _harvest_encoded(s: str, urls: set[str], endpoints: set[str]) -> None:
    """提取并盲解 base64/hex token，最多递归两层，再交给统一语法判定器。

    只还原确定性的文本编码；XOR/AES/压缩等无法静态确认的内容由编排层标记待复核。
    """
    if len(s) < 16:
        return
    pending = {
        match.group(0)
        for match in (*_B64_TOKEN_RE.finditer(s), *_HEX_TOKEN_RE.finditer(s))
    }
    seen_tokens: set[str] = set()
    seen_texts: set[str] = set()
    for _depth in range(2):
        decoded: set[str] = set()
        for token in pending - seen_tokens:
            seen_tokens.add(token)
            decoded.update(_decode_b64_variants(token))
            decoded.update(_decode_hex_variants(token))
        decoded -= seen_texts
        if not decoded:
            break
        seen_texts.update(decoded)
        pending = set()
        for text in decoded:
            for u in _iter_urls(text):
                urls.add(u.rstrip("\x00"))
            _harvest_config(text, urls, endpoints)
            pending.update(match.group(0) for match in _B64_TOKEN_RE.finditer(text))
            pending.update(match.group(0) for match in _HEX_TOKEN_RE.finditer(text))


def _harvest_text(text: str, urls: set[str], endpoints: set[str]) -> None:
    """从一段文本收 URL + 业务配置。"""
    if not text:
        return
    for u in _iter_urls(text):
        urls.add(u.rstrip("\x00"))
    _harvest_config(text, urls, endpoints)


