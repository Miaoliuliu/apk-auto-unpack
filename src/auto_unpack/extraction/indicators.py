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
from urllib.parse import urlsplit, urlunsplit

# rank -> 置信度（report.py 的 PRD 合同同用这一份）
RANK_CONF = {"biz": 0.9, "weak": 0.55, "noise": 0.25}


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


def make_indicator(url: str, source_type: str, source_file: str,
                   method: str = "regex") -> dict | None:
    raw = (url or "").strip().strip("\x00")
    if not raw or len(raw) < 4:
        return None
    candidate = raw
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    scheme = (parts.scheme or "http").lower()
    if scheme not in ("http", "https", "ws", "wss"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        port = None
    path = parts.path or ""
    netloc = _netloc(scheme, host, port)
    canonical = urlunsplit((scheme, netloc, path, parts.query, ""))
    ranked = raw if "://" in raw else canonical
    kind = classify_type(raw, host, path)
    rank = url_rank(ranked)
    return {
        "value": ranked,
        "type": kind,
        "url": ranked,
        "canonical": canonical,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "rank": rank,
        "confidence": RANK_CONF.get(rank, 0.4),
        "source_kind": source_type,
        "sources": [{"type": source_type, "file": source_file, "method": method}],
    }


def _merge_key(raw: str) -> str:
    """计算合并去重键：http/https 折叠 + 默认端口剥离。"""
    try:
        parts = urlsplit(raw if "://" in raw else "http://" + raw)
    except ValueError:
        return raw
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    fold_scheme = "http" if scheme in ("http", "https") else scheme
    return urlunsplit((fold_scheme, _netloc(scheme, host, port), parts.path, parts.query, ""))


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
        # https 优先；保留更像完整 URL 的展示串
        old = by[key].get("url") or ""
        new = it.get("url") or ""
        if new.lower().startswith("https://") and not old.lower().startswith("https://"):
            for field in ("url", "value", "canonical", "scheme"):
                if field in it:
                    by[key][field] = it[field]
        elif "://" in new and "://" not in old:
            by[key]["url"] = new
            if it.get("value"):
                by[key]["value"] = it["value"]
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
_URL_SAFE = r"[^\s\"'<>\\`\x00-\x1f\x7f]"
URL_RE = re.compile(rf"(?:https?|wss?)://{_URL_SAFE}+", re.IGNORECASE)
_URL_BYTE_RE = re.compile(
    rb"(?:https?|wss?)://[^\x00-\x1f\x7f-\xff\s\"'<>\\`]{4,240}",
    re.IGNORECASE,
)
# resources.arsc / so 里常见 UTF-16LE：h\0t\0t\0p\0s\0:\0/\0/\0...
_URL_UTF16_RE = re.compile(
    rb"(?:h\x00t\x00t\x00p\x00s?\x00|w\x00s\x00s?\x00)"
    rb":\x00/\x00/\x00"
    rb"(?:[\x20-\x7e]\x00){4,240}",
    re.IGNORECASE,
)
# 裸 IPv4:port 或 IPv4/path（配置/资源表常不带 scheme）
_IP_PORT_BYTE_RE = re.compile(
    rb"(?<![0-9.])"
    rb"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    rb"(?::\d{2,5}(?:/[^\x00-\x1f\x7f-\xff\s\"'<>\\`]{0,80})?"
    rb"|/[^\x00-\x1f\x7f-\xff\s\"'<>\\`]{1,80})"
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
    re.I,
)
_IPV6_PORT_BYTE_RE = re.compile(
    rb'(?<!:)\['
    rb'[0-9a-fA-F:.]{2,45}'
    rb'\]'
    rb'(?::\d{2,5}(?:/[^\x00-\x1f\x7f-\xff\s\"\'<>\\`]{0,80})?'
    rb'|/[^\x00-\x1f\x7f-\xff\s\"\'<>\\`]{1,80})'
)
# www. 开头的域名（强信号，几乎不会误报）
WWW_RE = re.compile(rf'(?<![\w.])www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}(?:{_URL_SAFE}*)?')
# 无 scheme 的域名，要求已知 TLD 且带端口或路径，降低与包名/类名的误报
_TLDS = (
    r'(?:com|net|org|cn|io|co|app|xyz|dev|ai|me|info|biz|top|vip|shop|tech|'
    r'online|site|cloud|fun|icu|club|live|store|cc|tv|us|ru|jp|kr|hk|tw|im|'
    r'wang|xin|work|cfd|bond|click|cyou|rest|today|sbs)'
)
DOMAIN_RE = re.compile(
    rf'(?<![\w.])[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?'
    rf'(?:\.[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?)+'
    rf'\.{_TLDS}(?::\d{{1,5}}(?:/{_URL_SAFE}*)?|/{_URL_SAFE}*)',
    re.IGNORECASE,
)
# 无 scheme、无端口/路径的裸域名（uni-app JS 常写 "api.xxx.cn"）
_BARE_HOST_RE = re.compile(
    r'(?<![\w.])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.'
    + _TLDS
    + r'(?![\w.:/])',
    re.I,
)
# Java 包名前缀，避免把 com.example.app 当 host
_PKG_FIRST_LABELS = frozenset({
    "com", "org", "net", "io", "android", "java", "javax", "kotlin", "cn",
})

# 去掉 URL 尾部的标点/引号/NUL。`]` 单独处理：IPv6 闭合括号不能剥。
CLEAN_RE = re.compile(r'[\x00),.;:!]+$')

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
_NOISE_PREFIX = ("android.", "kotlin.", "java.", "javax.")
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
    if labels[-2].lower() in ("error", "logger", "debug", "verbose") and labels[-1] in (
        "cn", "com", "net", "org", "info",
    ):
        return False
    return True


# ---------------------------------------------------------------------------
# 业务提取规则（新样本漏报：把键名 / TLD / 路径形态加到这张表，再补一条测试）
# ---------------------------------------------------------------------------
# 灰产常用 TLD：即使没有路径，引号里的裸域名也当业务 host
_GRAY_TLD = (
    r'(?:shop|top|xyz|vip|cc|im|icu|fun|club|online|site|live|store|'
    r'wang|xin|work|cfd|bond|click|cyou|rest|today|cloud|tech|sbs)'
)
_HOST_LIST_RE = re.compile(
    r"(?:domainList|hostList|urlList|apiList|serverList|domain_list|host_list)"
    r"\s*[:=]\s*\[([^\]]*)\]",
    re.I,
)
_CONFIG_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:baseUrl|baseURL|base_url|apiUrl|apiURL|api_url|"
    r"apiHost|api_host|serverUrl|serverURL|serverHost|commonUrl|requestUrl|"
    r"h5Url|H5Url|hostUrl|ossUrl|uploadUrl|cdnUrl|wsUrl|wssUrl|imUrl|"
    r"BASE_URL|API_URL|API_HOST|BASE_HOST|SERVER_URL|APP_URL|H5_URL)"
    r"\s*[:=]\s*(?:['\"]([^'\"]+)['\"]|((?:https?|wss?)://[^\s'\"#,;]+))",
    re.I,
)
_JSON_URL_FIELD_RE = re.compile(
    r"['\"](?:url|baseUrl|baseURL|apiUrl|apiHost|host|domain|server|"
    r"endpoint|origin|cdn|oss|upload|wss|wsHost)['\"]\s*:\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_CONCAT_PATH_RE = re.compile(
    r"(?:commonUrl|baseUrl|baseURL|apiUrl|apiURL|requestUrl|serverUrl)"
    r"\s*\+\s*['\"](/[^'\"]+)['\"]",
    re.I,
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
    re.I,
)
_QUOTED_HOST_RE = re.compile(
    r"['\"]([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\."
    + _TLDS
    + r")['\"]",
    re.I,
)
_SCHEME_RE = re.compile(r"^(?:https?|wss?)://", re.I)

_DEX_HARVEST_HINTS = (
    "http://", "https://", "ws://", "wss://",
    "domainList", "hostList", "baseUrl", "baseURL", "apiUrl",
    "index.php", "BASE_URL", "API_URL", "commonUrl",
)

def _host_of(url: str) -> str:
    """取 host（小写）。IPv6 字面量取方括号内地址。"""
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0].split("?")[0]
    if s.startswith("["):  # IPv6: [2001:db8::1]:8080
        end = s.find("]")
        s = s[1:end] if end != -1 else s
    else:
        s = s.split(":")[0]
    return s.lower()


def _url_port_and_path(url: str) -> tuple[int | None, str]:
    """从 URL 里拆端口和路径（不含 query）。"""
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    hostport, _, rest = s.partition("/")
    path = "/" + rest.split("?")[0] if rest else ""
    port = None
    if ":" in hostport:
        maybe = hostport.rsplit(":", 1)[-1]
        if maybe.isdigit():
            try:
                port = int(maybe)
            except ValueError:
                port = None
    return port, path


def _looks_code_host(host: str) -> bool:
    """CSS/布局字段拼出来的假 host，不是域名。"""
    labels = (host or "").lower().split(".")
    return any(lab in _CODE_HOST_LABELS for lab in labels[:-1])


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
    # 噪音子串只匹配 scheme://host/path 部分（剔除 query/fragment），
    # 避免 query 里嵌套的外部 URL（?u=https://github.com/...）整条被误杀
    no_q = low.split("?", 1)[0].split("#", 1)[0]
    if any(n in no_q for n in _NOISE_SUBSTR):
        return True
    host = _host_of(u)
    if not host:
        return True
    port, _path = _url_port_and_path(u)
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
        if port in _DNS_PORTS:
            return True
        return False
    if "." not in host:
        return True
    if _looks_code_host(host):
        return True
    if any(host == root or host.endswith("." + root) for root in _NOISE_HOST_ROOTS):
        return True
    # XML namespace / SAX feature 形态
    if any(p in low for p in ("/xml/features", "/sax/features", "/sax/properties",
                              "/trax/features", "/ns/structure")):
        return True
    check = u if "://" in u else "http://" + u
    if not _looks_plausible_url(check):
        return True
    return False


_BIZ_PATH_HINTS = (
    "/index.php/", "/api.php/", "/home/", "/api/", "/v1/", "/v2/",
    "/user/", "/login", "/upload", "/ios", "/android", "/bot/",
    "/release", "/gateway", "/im/", "/socket",
)
_GRAY_TLD_HOST_RE = re.compile(r"\." + _GRAY_TLD + r"$", re.I)


def url_rank(u: str) -> str:
    """noise = 框架/文档；weak = 像 URL 但无业务信号；biz = 灰产后端。"""
    u = (u or "").strip().strip("\x00")
    if not u or is_noise_url(u):
        return "noise"
    host = _host_of(u)
    low = u.lower()
    port, path = _url_port_and_path(u)
    path_only = (path or "").split("?")[0]
    has_biz_path = (
        any(h in low for h in _BIZ_PATH_HINTS)
        or ".php" in path_only.lower()
    )
    if _parse_ip(host or "") is not None:
        # 裸 IP:80/443 无路径多半是 CDN/证书探测；真正 C2 常带路径或非常用端口
        if has_biz_path or path_only not in ("", "/"):
            return "biz"
        if port and port not in (80, 443):
            return "biz"
        return "weak"
    if host and _GRAY_TLD_HOST_RE.search(host):
        return "biz"
    if has_biz_path:
        return "biz"
    first = (host or "").split(".")[0]
    if first in ("api", "apis", "gateway", "gw"):
        return "biz"
    if low.startswith(("ws://", "wss://")):
        return "biz"
    return "weak"


def _url_core(u: str) -> tuple[str, str, str, str]:
    """(scheme, hostport, path, query) 便于折叠 http/https 与 tracking query。"""
    s = (u or "").strip()
    scheme = ""
    if "://" in s:
        scheme, s = s.split("://", 1)
        scheme = scheme.lower()
    hostport, _, rest = s.partition("/")
    if rest:
        path, _, query = rest.partition("?")
        path = "/" + path
    else:
        path, query = "", ""
    return scheme, hostport.lower(), path, query


def _query_is_tracking(query: str) -> bool:
    q = (query or "").lower().replace("&amp;", "&")
    if not q:
        return False
    return "utm_" in q or "mail.welcome" in q or "campaign=" in q


def fold_related_urls(urls: set[str]) -> set[str]:
    """同一资源只留一条：https 优于 http；utm/locale query 变体只留一条。"""
    by_full: dict[tuple[str, str, str], str] = {}
    for u in urls:
        if not u:
            continue
        scheme, hostport, path, query = _url_core(u)
        key = (hostport, path, query)
        prev = by_full.get(key)
        if prev is None:
            by_full[key] = u
            continue
        if scheme == "https" and not prev.lower().startswith("https://"):
            by_full[key] = u
    groups: dict[tuple[str, str], list[str]] = {}
    for u in by_full.values():
        _scheme, hostport, path, _query = _url_core(u)
        groups.setdefault((hostport, path), []).append(u)
    out: set[str] = set()
    for variants in groups.values():
        tracking = [v for v in variants if _query_is_tracking(_url_core(v)[3])]
        plain = [v for v in variants if not _query_is_tracking(_url_core(v)[3])]
        if len(tracking) >= 2 and not plain:
            https = [v for v in tracking if v.lower().startswith("https://")]
            out.add(sorted(https or tracking, key=len)[0])
            continue
        out.update(plain or tracking)
    return out


def weak_worth_listing(u: str) -> bool:
    """写进 urls_by_rank.txt 的 weak：要有路径、非常用端口、IP，避免裸域名刷屏。"""
    if url_rank(u) != "weak":
        return False
    host = _host_of(u)
    port, path = _url_port_and_path(u)
    path_only = (path or "").split("?")[0]
    if _parse_ip(host or "") is not None:
        return True
    if port and port not in (80, 443):
        return True
    if path_only not in ("", "/"):
        return True
    first = (host or "").split(".")[0]
    return first in ("api", "apis", "gateway", "gw", "im", "oss")


def business_urls(urls: set[str]) -> set[str]:
    """只保留有业务信号的 URL（灰产 TLD / 内网 IP / php·api 路径 / ws）。"""
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
    s = "".join(ch for ch in (s or "") if ch.isprintable() and ch not in "\x7f")
    s = CLEAN_RE.sub("", s)
    # 尾部 ] 多半是 [url] 包裹；IPv6 hostport 的闭合括号要留
    while s.endswith("]"):
        rest = s.split("://", 1)[-1]
        hp = rest.split("/", 1)[0].split("?", 1)[0]
        if _IPV6_HOSTPORT_RE.match(hp) and (
            s.endswith(hp) or rest.startswith(hp + "/") or rest.startswith(hp + "?")
        ):
            break
        s = s[:-1]
    return s.rstrip("/\\")


def _utf16le_to_ascii(blob: bytes) -> str:
    """把 UTF-16LE 交错字节收成 ASCII 串（失败则空）。"""
    if len(blob) < 2:
        return ""
    try:
        text = blob.decode("utf-16le", errors="ignore")
    except Exception:
        return ""
    return "".join(ch for ch in text if ch.isprintable() or ch in "/:?&=#%+.-_")


def _scan_raw_for_urls(raw: bytes) -> set[str]:
    """从任意二进制里抠 URL（ASCII / UTF-16LE / 裸 IPv4:port / 方括号 IPv6）。"""
    found: set[str] = set()
    if not raw:
        return found
    for m in _URL_BYTE_RE.finditer(raw):
        u = _clean_url(m.group().decode("ascii", errors="ignore"))
        if u and _looks_plausible_url(u):
            found.add(u)
    for m in _URL_UTF16_RE.finditer(raw):
        u = _clean_url(_utf16le_to_ascii(m.group()))
        if u and "://" in u and _looks_plausible_url(u):
            found.add(u)
    for m in _IP_PORT_BYTE_RE.finditer(raw):
        hostpath = m.group().decode("ascii", errors="ignore")
        if not hostpath:
            continue
        for scheme in ("https://", "http://"):
            u = _clean_url(scheme + hostpath)
            if u and not is_noise_url(u) and _looks_plausible_url(u):
                found.add(u)
                break
    for m in _IPV6_PORT_BYTE_RE.finditer(raw):
        blob = m.group().decode("ascii", errors="ignore")
        inner = blob[1:blob.find("]")] if blob.startswith("[") and "]" in blob else ""
        if _parse_ip(inner) is None:
            continue
        for scheme in ("https://", "http://"):
            u = _clean_url(scheme + blob)
            if u and not is_noise_url(u) and _looks_plausible_url(u):
                found.add(u)
                break
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
        if u and not u.endswith("://"):
            yield u
    s = _mask(s, full)

    ip = list(IP_HOST_RE.finditer(s))
    for m in ip:
        u = _clean_url(m.group(0))
        if u:
            yield u
    s = _mask(s, ip)

    ipv6 = list(_IPV6_BARE_RE.finditer(s))
    for m in ipv6:
        if _parse_ip(m.group(1)) is None:
            continue
        u = _clean_url(m.group(0))
        if u:
            yield u
    s = _mask(s, ipv6)

    www = list(WWW_RE.finditer(s))
    for m in www:
        u = _clean_url(m.group(0))
        if u:
            yield u
    s = _mask(s, www)

    dom = list(DOMAIN_RE.finditer(s))
    for m in dom:
        u = _clean_url(m.group(0))
        if u:
            yield u
    s = _mask(s, dom)

    for m in _BARE_HOST_RE.finditer(s):
        u = _clean_url(m.group(0))
        host = u.split("/")[0].split(":")[0]
        if u and not _is_package_like_host(host):
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
    if low.startswith(FS_PREFIXES):
        return False
    return True


def _is_rel_endpoint(p: str) -> bool:
    segs = p.split("/")
    if any(seg in ("", ".", "..") for seg in segs):
        return False
    if p.lower().endswith(ENDPOINT_EXT_BLACKLIST):
        return False
    return True


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


def _is_origin_only(base: str) -> bool:
    rest = base.split("://", 1)[-1]
    return "/" not in rest


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
    if "/home/" in pl:
        return True
    return False


def _join_base_path(base: str, path: str) -> str:
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def _normalize_base(value: str) -> list[str]:
    """配置值 -> 可拼接的 origin/前缀（已滤噪音）。"""
    v = (value or "").strip().strip("\x00").strip().rstrip("/")
    if not v or len(v) > 180 or " " in v or "\n" in v:
        return []
    if "${" in v or "%s" in v:
        return []
    if _SCHEME_RE.match(v):
        u = _clean_url(v)
        if u and not is_noise_url(u):
            return [u]
        return []
    host = _host_of(v)
    if "." not in host and _parse_ip(host) is None:
        return []
    out = []
    for scheme in ("http://", "https://"):
        u = _clean_url(scheme + v)
        if u and not is_noise_url(u):
            out.append(u)
    return out


def _ingest_config_value(value: str, urls: set[str], endpoints: set[str],
                         bases: set[str]) -> None:
    v = (value or "").strip()
    if not v:
        return
    if v.startswith("/"):
        path = v.split("?", 1)[0]
        if _looks_like_api_path(path):
            endpoints.add(path)
        return
    for b in _normalize_base(v):
        urls.add(b)
        bases.add(b)


def _collect_api_paths(text: str, endpoints: set[str]) -> set[str]:
    paths: set[str] = set()
    for p in _PHP_PATH_RE.findall(text):
        paths.add(p)
    for p in _PHP_STATIC_RE.findall(text):
        paths.add(p)
    for p in _QUOTED_API_PATH_RE.findall(text):
        paths.add(p.split("?", 1)[0])
    for p in _CONCAT_PATH_RE.findall(text):
        paths.add(p.split("?", 1)[0])
    for p in paths:
        endpoints.add(p)
    return paths


def _harvest_config(text: str, urls: set[str], endpoints: set[str]) -> None:
    """配置键、域名列表、灰产 TLD 裸域名、拼接路径；同文件 host×接口还原。"""
    bases: set[str] = set()
    for m in _HOST_LIST_RE.finditer(text):
        for d in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            _ingest_config_value(d, urls, endpoints, bases)
    for m in _CONFIG_ASSIGN_RE.finditer(text):
        _ingest_config_value(m.group(1) or m.group(2), urls, endpoints, bases)
    for m in _JSON_URL_FIELD_RE.finditer(text):
        _ingest_config_value(m.group(1), urls, endpoints, bases)
    for h in _QUOTED_GRAY_HOST_RE.findall(text):
        _ingest_config_value(h, urls, endpoints, bases)
    for h in _QUOTED_HOST_RE.findall(text):
        if _is_package_like_host(h):
            continue
        _ingest_config_value(h, urls, endpoints, bases)

    api_paths = _collect_api_paths(text, endpoints)
    for p in _CONCAT_PATH_RE.findall(text):
        path = p.split("?", 1)[0]
        for b in bases:
            if _is_ws_base(b):
                continue
            urls.add(_join_base_path(b, path))
    for b in bases:
        if _is_ws_base(b) or not _is_origin_only(b):
            continue
        for p in api_paths:
            if _looks_like_api_path(p):
                urls.add(_join_base_path(b, p))


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
    """盲解 base64/hex 编码的 URL，命中判定器才收，否则静默丢弃。

    不做「识别混淆」，而是把像编码的长 token 盲解后交给 URL 正则 + 域名合法性
    + 噪音表三重判定。确定性、与 app 无关。密文 URL 常以 dex 字符串常量形式存在。
    """
    if "://" in s:
        return  # 明文 URL 已由 _iter_urls 处理，不做重复
    if len(s) < 16 or len(s) > 1024:
        return
    for text in _decode_b64_variants(s):
        for u in _iter_urls(text):
            u = u.rstrip("\x00")
            if u and _looks_plausible_url(u) and not is_noise_url(u):
                urls.add(u)
        _harvest_config(text, urls, endpoints)
    for text in _decode_hex_variants(s):
        for u in _iter_urls(text):
            u = u.rstrip("\x00")
            if u and _looks_plausible_url(u) and not is_noise_url(u):
                urls.add(u)
        _harvest_config(text, urls, endpoints)


def _harvest_text(text: str, urls: set[str], endpoints: set[str]) -> None:
    """从一段文本收 URL + 业务配置。"""
    if not text:
        return
    for u in _iter_urls(text):
        urls.add(u.rstrip("\x00"))
    _harvest_config(text, urls, endpoints)


