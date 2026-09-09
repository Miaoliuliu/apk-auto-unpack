"""URL 提取规则底座（extraction/indicators.py）· 行为锁定测试（Characterization Tests）。

目的：不是证明「规则正确」，而是锁定「当前行为」——任何正则/阈值/分级
调整导致行为变化时，测试立即变红，提示人工确认是有意变更。

断言值来源：2026-09-02 对 indicators.py 各纯函数实跑校准（见下文各 docstring）。

不依赖 androguard（indicators 顶层仅 stdlib re + urllib.parse），离线可跑：
    C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe -m pytest tests/test_extraction_indicators.py -v

约定：
- 示例域名刻意避开噪音表里的 example.com（`_NOISE_SUBSTR` 已含）、以及单字符
  子域（`_looks_plausible_url` 会拒绝 `a.b.com` 形态），统一用 myservice.com 系。
- 已知缺陷（P0）的用例放在文件末尾「已知缺陷」分组，函数名带 `_known_bug`，
  修复后需同步把断言改成期望行为并去掉标记。
"""
from __future__ import annotations

import pytest

from auto_unpack.extraction import indicators as ind


# ---------------------------------------------------------------------------
# classify_type：url / domain / ip 三态
# ---------------------------------------------------------------------------
def test_classify_type_url_with_scheme():
    assert ind.classify_type("https://a.com/x", "a.com", "/x") == "url"


def test_classify_type_ip_bare():
    assert ind.classify_type("192.168.1.1", "192.168.1.1", "") == "ip"


def test_classify_type_domain_bare():
    assert ind.classify_type("api.myservice.com", "api.myservice.com", "") == "domain"


def test_classify_type_url_bare_with_path():
    assert ind.classify_type("api.myservice.com/login", "api.myservice.com", "/login") == "url"


# ---------------------------------------------------------------------------
# make_indicator：字段装配 + 归一化
# ---------------------------------------------------------------------------
def test_make_indicator_full_url():
    i = ind.make_indicator("https://api.myservice.com/v1", "dex", "classes.dex")
    assert i["type"] == "url"
    assert i["host"] == "api.myservice.com"
    assert i["path"] == "/v1"
    assert i["scheme"] == "https"
    assert i["rank"] == "biz"
    assert i["business_likelihood"] == 0.9
    assert i["validation"]["syntax"] == "valid"
    assert i["sources"] == [{"type": "dex", "file": "classes.dex", "method": "regex"}]


def test_make_indicator_bare_domain_preserves_observed_value():
    i = ind.make_indicator("api.myservice.com", "dex", "classes.dex")
    assert i["type"] == "domain"
    assert i["value"] == "api.myservice.com"
    assert i["canonical"] == "api.myservice.com"
    assert i["scheme"] is None
    assert i["host"] == "api.myservice.com"


def test_make_indicator_empty_or_short_is_none():
    assert ind.make_indicator("", "dex", "x") is None
    assert ind.make_indicator("abc", "dex", "x") is None  # len < 4


def test_make_indicator_rejects_ftp_scheme():
    assert ind.make_indicator("ftp://api.myservice.com", "dex", "x") is None


# ---------------------------------------------------------------------------
# url_rank：noise / weak / biz 三档
# ---------------------------------------------------------------------------
def test_rank_biz_gray_tld():
    assert ind.url_rank("https://api.grayapp.shop") == "biz"  # .shop 灰产 TLD


def test_rank_biz_api_prefix():
    assert ind.url_rank("https://api.myservice.com") == "biz"


def test_rank_biz_api_path():
    assert ind.url_rank("https://api.myservice.com/v1/login") == "biz"


def test_rank_biz_ws():
    assert ind.url_rank("ws://api.myservice.com") == "biz"


def test_rank_biz_ip_with_path():
    assert ind.url_rank("http://192.168.1.1:8080/api") == "biz"


def test_rank_biz_ip_non_standard_port():
    assert ind.url_rank("http://192.168.1.1:8080") == "biz"


def test_rank_weak_ip_no_path():
    assert ind.url_rank("http://192.168.1.1") == "weak"


def test_rank_weak_plain_domain():
    assert ind.url_rank("https://www.myservice.com") == "weak"


def test_rank_noise_placeholder_domain():
    assert ind.url_rank("https://example.com") == "noise"


def test_rank_noise_schema_url():
    assert ind.url_rank("https://schemas.android.com/apk/res/android") == "noise"


def test_rank_noise_public_dns():
    assert ind.url_rank("http://8.8.8.8") == "noise"


# ---------------------------------------------------------------------------
# is_noise_url
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("u", [
    "https://www.umeng.com",       # SDK 域名根
    "http://127.0.0.1",            # 回环
    "http://10.0.2.2",             # 模拟器 host
    "http://1.1.1.1:53",           # 公共 DNS + 53 端口
    "http://lineheightstyle.alignment.top",  # CSS 布局字段假 host
    "http://localhost",
])
def test_is_noise_url_true(u):
    assert ind.is_noise_url(u) is True


def test_is_noise_url_false_business():
    assert ind.is_noise_url("https://api.myservice.com") is False


# ---------------------------------------------------------------------------
# _looks_plausible_url：假 host 过滤
# ---------------------------------------------------------------------------
def test_plausible_false_logger_info():
    assert ind._looks_plausible_url("http://logger.info") is False


def test_plausible_false_digit_logword():
    assert ind._looks_plausible_url("http://7.error.cn") is False


def test_plausible_false_single_char_label():
    assert ind._looks_plausible_url("http://a.myservice.com") is False


def test_plausible_true_business():
    assert ind._looks_plausible_url("http://api.myservice.com") is True


# ---------------------------------------------------------------------------
# _iter_urls：多形态提取 + 掩码去重
# ---------------------------------------------------------------------------
def test_iter_urls_full_url_masks_host():
    # 完整 URL 提取后 host 被掩码，不再重复产出裸域名
    assert list(ind._iter_urls("https://api.myservice.com/v1")) == \
        ["https://api.myservice.com/v1"]


def test_iter_urls_multiple_urls():
    got = list(ind._iter_urls("go https://api.myservice.com/x or http://cdn.myservice.com/y"))
    assert got == ["https://api.myservice.com/x", "http://cdn.myservice.com/y"]


def test_iter_urls_bare_domain_with_path():
    assert list(ind._iter_urls("api.myservice.com/index.php")) == \
        ["api.myservice.com/index.php"]


# ---------------------------------------------------------------------------
# _harvest_config / _harvest_text：配置收割 + base×path 拼接还原
# ---------------------------------------------------------------------------
def test_harvest_config_base_url_plus_path_concat():
    urls, eps = set(), set()
    ind._harvest_config(
        'const baseUrl = "https://api.myservice.com"; const u = baseUrl + "/api/login";',
        urls, eps,
    )
    assert urls == {"https://api.myservice.com", "https://api.myservice.com/api/login"}
    assert eps == {"/api/login"}


def test_harvest_config_json_url_field():
    urls, eps = set(), set()
    ind._harvest_config('{"url": "https://api.myservice.com"}', urls, eps)
    assert urls == {"https://api.myservice.com"}


def test_harvest_config_domain_list_does_not_invent_schemes():
    urls, eps = set(), set()
    ind._harvest_config('domainList: ["api1.myservice.com", "cdn.myservice.com"]', urls, eps)
    assert urls == {"api1.myservice.com", "cdn.myservice.com"}


# ---------------------------------------------------------------------------
# merge_indicators：跨来源去重 + https 优先
# ---------------------------------------------------------------------------
def test_merge_indicators_keeps_http_https_distinct():
    a = ind.make_indicator("http://api.myservice.com", "dex", "classes.dex")
    b = ind.make_indicator("https://api.myservice.com", "assets", "www/app.js")
    m = ind.merge_indicators([a, b])
    assert [item["url"] for item in m] == [
        "http://api.myservice.com", "https://api.myservice.com",
    ]


def test_merge_indicators_tolerates_none():
    assert ind.merge_indicators([None, {}]) == []


# ---------------------------------------------------------------------------
# fold_related_urls：scheme/query 变体折叠
# ---------------------------------------------------------------------------
def test_fold_related_urls_preserves_observed_variants():
    got = ind.fold_related_urls({
        "http://api.myservice.com/x",
        "https://api.myservice.com/x",
        "https://api.myservice.com/x?utm_source=1",
        "https://api.myservice.com/x?utm_source=2",
    })
    assert got == {
        "http://api.myservice.com/x",
        "https://api.myservice.com/x",
        "https://api.myservice.com/x?utm_source=1",
        "https://api.myservice.com/x?utm_source=2",
    }


# ---------------------------------------------------------------------------
# weak_worth_listing / business_urls
# ---------------------------------------------------------------------------
def test_weak_worth_listing_ip_true():
    assert ind.weak_worth_listing("http://10.1.2.3") is True


def test_weak_worth_listing_bare_domain_false():
    assert ind.weak_worth_listing("https://www.myservice.com") is False


def test_business_urls_only_biz():
    got = ind.business_urls({
        "https://api.grayapp.shop",   # biz
        "https://api.myservice.com",  # biz
        "http://10.1.2.3",            # weak
    })
    assert got == {"https://api.grayapp.shop", "https://api.myservice.com"}


# ---------------------------------------------------------------------------
# P0 修复回归：大小写裸域名 / 数字前缀域名（2026-09-02 修复）
# ---------------------------------------------------------------------------
def test_domain_re_uppercase():
    """P0 修复①：DOMAIN_RE 补 re.IGNORECASE，大写裸域名+路径不再漏报。"""
    assert list(ind._iter_urls("API.Example.COM/index.php")) == \
        ["API.Example.COM/index.php"]


def test_numeric_prefix_domain_preserved():
    """P0 修复②：两标签「数字.TLD」真域名放行，日志词假 host 仍被拒。"""
    assert ind._looks_plausible_url("http://360.cn") is True
    assert ind._looks_plausible_url("http://163.com") is True
    assert ind.url_rank("http://360.cn/xxx") == "weak"
    # 日志词假 host 不受影响
    assert ind._looks_plausible_url("http://7.error.cn") is False


# ---------------------------------------------------------------------------
# P1 修复回归：嵌套 URL 误杀 / IPv6 host（2026-09-02 修复）
# ---------------------------------------------------------------------------
def test_is_noise_url_query_nested_url_not_noise():
    """P1 修复③：query 里嵌套外链不应整条误杀（噪音子串只匹配 host+path）。"""
    u = "https://api.myservice.com/goto?u=https://github.com/xxx"
    assert ind.is_noise_url(u) is False


def test_is_noise_url_plain_github_still_noise():
    """嵌套 URL 修复不破坏正常噪音判定：github.com 本身仍是噪音。"""
    assert ind.is_noise_url("https://github.com/xxx") is True


def test_host_of_ipv6_no_crash():
    """P1 修复⑥b：IPv6 字面量取方括号内地址，不再拆成 '['。"""
    assert ind._host_of("http://[2001:db8::1]:8080/x") == "2001:db8::1"


def test_is_ip_host():
    """IPv4 / IPv6 都算 IP；域名不算。"""
    assert ind._is_ip_host("192.168.1.1") is True
    assert ind._is_ip_host("2001:db8::1") is True
    assert ind._is_ip_host("[2001:db8::1]") is True
    assert ind._is_ip_host("example.com") is False
    assert ind._is_ip_host("999.999.999.999") is False


# ---------------------------------------------------------------------------
# P0 修复回归：IPv6 误杀 / 短域名误杀（2026-09-03）
# ---------------------------------------------------------------------------
def test_ipv6_url_is_not_noise():
    """P0：有点号才算 host 的旧规则会把 IPv6 整条打成 noise。"""
    u = "https://[2001:db8::1]:8080/v1/token"
    assert ind.is_noise_url(u) is False
    assert ind.url_rank(u) == "biz"
    assert ind._looks_plausible_url(u) is True


def test_ipv6_loopback_linklocal_dns_still_noise():
    assert ind.is_noise_url("http://[::1]:8080/x") is True
    assert ind.is_noise_url("https://[fe80::1]/api") is True
    assert ind.is_noise_url("https://[2001:4860:4860::8888]") is True


def test_ipv6_ula_with_path_is_biz():
    """ULA 与 RFC1918 一样：内网通联，有路径算 biz。"""
    u = "https://[fd12:3456:789a::1]:8443/api/login"
    assert ind.is_noise_url(u) is False
    assert ind.url_rank(u) == "biz"


def test_iter_urls_ipv6_full_and_bare():
    full = "https://[2001:db8::1]:8080/v1"
    assert list(ind._iter_urls(full)) == [full]
    bare = list(ind._iter_urls("c2 [2001:db8::1]:8080/api now"))
    assert "[2001:db8::1]:8080/api" in bare
    # 二进制/拼接常见：字母紧贴 '['，a-f 不能当 hex lookbehind 挡掉
    glued = list(ind._iter_urls("pad[2001:db8::1]:8080/v1"))
    assert "[2001:db8::1]:8080/v1" in glued


def test_iter_urls_rejects_invalid_ipv6_brackets():
    assert list(ind._iter_urls("go [gggg::zzzz]:8080/api")) == []


def test_clean_url_keeps_ipv6_closing_bracket():
    assert ind._clean_url("https://[2001:db8::1]") == "https://[2001:db8::1]"
    assert ind._clean_url("https://myservice.com]") == "https://myservice.com"


def test_make_indicator_ipv6_brackets_canonical():
    i = ind.make_indicator("https://[2001:db8::1]:8080/api", "dex", "classes.dex")
    assert i is not None
    assert i["host"] == "2001:db8::1"
    assert i["type"] == "url"
    assert i["rank"] == "biz"
    assert i["canonical"] == "https://[2001:db8::1]:8080/api"
    assert i["port"] == 8080


def test_scan_raw_ipv6_bracket():
    raw = b"pad[2001:db8::1]:8080/v1\x00more"
    got = ind._scan_raw_for_urls(raw)
    assert any("2001:db8::1" in u and "/v1" in u for u in got)


def test_plausible_mobile_subdomain_allowed():
    """P0：m/s/i 等移动端子域不再当假 host。"""
    assert ind._looks_plausible_url("http://m.myservice.com") is True
    assert ind._looks_plausible_url("http://m.api.myservice.com") is True
    assert ind._looks_plausible_url("https://i.myservice.com/v1") is True
    assert ind.is_noise_url("https://m.myservice.com/v1/login") is False


def test_plausible_short_sld_allowed():
    """P0：jd.com 这类两字符 SLD 不再被「全 ≤2」规则误杀。"""
    assert ind._looks_plausible_url("http://jd.com") is True
    assert ind._looks_plausible_url("http://m.jd.com") is True
    assert ind.is_noise_url("https://jd.com/login") is False
    assert ind.url_rank("https://jd.com/login") == "biz"


def test_plausible_single_char_still_rejected():
    """白名单之外的单字母标签仍拒，避免 a.x.info 回流。"""
    assert ind._looks_plausible_url("http://a.myservice.com") is False
    assert ind._looks_plausible_url("http://logger.info") is False


# ---------------------------------------------------------------------------
# P0 修复回归：Go 生态 / 框架 SDK 域名噪音（2026-09-02 批次实测）
# ---------------------------------------------------------------------------
def test_go_module_path_is_noise():
    """P0：google.golang.org 是 Go 模块导入路径，不是业务域名。"""
    assert ind.is_noise_url("http://google.golang.org/grpc/binarylog") is True


def test_go_module_path_with_len_prefix_is_noise():
    """P0 关键形态：Go 串池长度字节粘成数字前缀，实测 4093 条几乎全是这样。

    host 形如 0google.golang.org / 1google.golang.org，靠 endswith('.golang.org')
    后缀匹配全覆盖——这也是用 _NOISE_HOST_ROOTS 而非逐条子串的原因。
    """
    for prefix in ("0google", "1google", "2google", "4google", "7google"):
        assert ind.is_noise_url(f"http://{prefix}.golang.org/protobuf/types") is True


def test_go_uber_org_is_noise():
    """go.uber.org（zap / atomic 模块路径），实测 759 条。"""
    assert ind.is_noise_url("http://go.uber.org/atomic") is True


def test_webrtc_and_flutter_plugin_is_noise():
    """同性质框架字符串：webrtc.org 实测 126 条、plugins.flutter.io 24 条。"""
    assert ind.is_noise_url("http://www.webrtc.org/experiments") is True
    assert ind.is_noise_url("http://plugins.flutter.io/permission") is True


def test_go_rule_does_not_kill_business_domain():
    """补 Go 规则不能误伤真实业务域名（含形似 golang 字样的域名）。"""
    assert ind.is_noise_url("https://api.myservice.com/v1/token") is False
    assert ind.is_noise_url("https://mygolang.org/api") is False


def test_private_ip_is_not_noise():
    """决策锁定：私有网段 IP 是真实硬编码通联地址，不得按 RFC1918 网段过滤。

    反证：192.168.31.38:8080/v1/token 带真实认证接口路径，是内网业务服务；
    不可公网路由 ≠ 无分析价值（还暴露内网部署与开发环境）。
    只有回环 / 公共 DNS / 模拟器 / DNS 端口才算噪音。
    """
    assert ind.is_noise_url("https://192.168.31.38:8080/v1/token") is False
    assert ind.is_noise_url("http://192.168.1.4:20000") is False
    assert ind.is_noise_url("https://10.38.162.35") is False
    # 对照组：回环与模拟器地址仍必须判为噪音
    assert ind.is_noise_url("http://127.0.0.1:8080/x") is True
    assert ind.is_noise_url("http://10.0.2.2:8080/x") is True


@pytest.mark.parametrize("candidate", [
    "https://api.sample.net:99999/api/login",
    "https://api.sample.net:abc/api/login",
    "https://-bad-.com/api/login",
    "https://api..sample.net/api/login",
    "https://api.sample.net/api/%ZZ",
    "https://api.sample.net/api/{id}",
])
def test_make_indicator_rejects_invalid_url_syntax(candidate):
    assert ind.make_indicator(candidate, "dex", "classes.dex") is None
    assert list(ind._iter_urls(candidate)) == []


def test_modern_country_tld_bare_host_is_extracted():
    candidate = "backend.sample.uk/api/login"
    assert list(ind._iter_urls(candidate)) == [candidate]


def test_clean_url_preserves_semantic_trailing_characters():
    for candidate in (
        "https://api.sample.net/v1/",
        "https://api.sample.net/a;",
        "https://api.sample.net/a!",
    ):
        assert ind._clean_url(candidate) == candidate


def test_config_concat_is_bound_by_variable_name():
    text = (
        'const baseUrl="https://one.sample.net"; '
        'const apiUrl="https://two.sample.net"; '
        'const x=baseUrl+"/api/a"; const y=apiUrl+"/v1/b";'
    )
    urls, endpoints = set(), set()
    ind._harvest_config(text, urls, endpoints)
    assert urls == {
        "https://one.sample.net",
        "https://one.sample.net/api/a",
        "https://two.sample.net",
        "https://two.sample.net/v1/b",
    }


def test_raw_binary_long_url_is_never_truncated():
    candidate = "https://api.long-sample.net/api/" + "a" * 260
    assert ind._scan_raw_for_urls(candidate.encode()) == {candidate}
    too_long = "https://api.long-sample.net/api/" + "a" * 2200
    assert ind._scan_raw_for_urls(too_long.encode()) == set()


def test_noise_substring_requires_hostname_boundary():
    assert ind.is_noise_url("https://notgithub.com/api/login") is False
    assert ind.is_noise_url("https://myexample.com/api/login") is False


# ---------------------------------------------------------------------------
# 通联候选收口：源码后缀 / 无协议灰产 TLD / so 降权（2026-09-08）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("token", [
    "allocation.cc",
    "HardwareEarMonitorDaisyJni.cc",
    "androidmediadecoder.cc:183",
    "Api.java",
    "Rect.top",
    "Filled.Cloud",
    "QuicClient.cc:146",
])
def test_source_filename_is_not_a_network_candidate(token):
    assert ind.is_syntax_valid_candidate(token) is False
    assert ind.make_indicator(token, "native", "libx.so") is None
    assert ind.url_rank(token) == "noise"


def test_cargo_debug_path_is_not_a_network_candidate():
    raw = (
        "addr.rs/home/runner/.cargo/registry/src/index.crates.io-6f17d22bba15001f"
        "/tokio-1.44.2/src/net/tcp/listener.rs"
    )
    assert ind.is_syntax_valid_candidate(raw) is False


def test_gray_tld_without_scheme_is_not_biz():
    assert ind.url_rank("yuliaotongxun.vip") == "weak"
    assert ind.weak_worth_listing("yuliaotongxun.vip") is False


def test_gray_tld_with_scheme_is_biz():
    assert ind.url_rank("https://www.yuliaotongxun.vip") == "biz"
    assert ind.url_rank("https://api.grayapp.shop") == "biz"


def test_host_nonstandard_port_is_biz():
    assert ind.url_rank("39.108.101.79:55007") == "biz"
    assert ind.url_rank("admin.ekee.store:1883") == "biz"
    i = ind.make_indicator("39.108.101.79:55007", "native", "libx.so")
    assert i is not None
    assert i["rank"] == "biz"


def test_libcore_icu_and_xiaomi_shortlink_are_noise():
    assert ind.url_rank("http://libcore.icu.icu") == "noise"
    assert ind.url_rank("http://s.mi1.cc") == "noise"


def test_native_scheme_less_gray_host_stays_weak():
    i = ind.make_indicator("ap-prd-jd.grayapp.shop", "native", "libnertc.so")
    assert i is not None
    assert i["rank"] == "weak"


def test_native_https_url_not_demoted():
    i = ind.make_indicator("https://www.xmrhmy.icu", "native", "libx.so")
    assert i is not None
    assert i["rank"] == "biz"


def test_js_property_port_is_not_biz():
    assert ind.url_rank("i.length:16") != "biz"
    assert ind.url_rank("xmp.did:50") != "biz"
    assert ind.url_rank("t.audioBitrate:1") != "biz"
    assert ind.weak_worth_listing("i.length:16") is False


def test_api_prefix_gray_tld_without_scheme_is_biz():
    assert ind.url_rank("api.3aksjgyg.shop") == "biz"
    assert ind.url_rank("yuliaotongxun.vip") == "weak"


def test_sdk_hosts_and_netcheck_are_noise():
    assert ind.url_rank("https://edusuite-song.zego.im") == "noise"
    assert ind.url_rank("https://commercial.kugou.com/v2/commercial/vip/info") == "noise"
    assert ind.url_rank("https://lbs.netease.im/lbs/conf.jsp") == "noise"
    assert ind.url_rank(
        "https://api-access.pangolin-sdk-toutiao.com/v2/inspect/aegis/client/page/"
    ) == "noise"
    assert ind.url_rank(
        "https://developer.mozilla.org/en-US/docs/Web/API/WakeLockSentinel/released"
    ) == "noise"
    assert ind.url_rank(
        "https://cv-tob.bytedance.com/v1/api/sdk/tob_license/getlicense"
    ) == "noise"
    assert ind.url_rank("https://api.telegram.org/bot/sendMessage") == "noise"
    assert ind.url_rank("3478stun.nextcloud.com:3478") == "noise"
    assert ind.url_rank("https://162.14.10.42/netcheck") == "noise"


def test_resources_arsc_path_is_not_a_network_candidate():
    assert ind.is_syntax_valid_candidate("resources.arsc/AndroidManifest.xml") is False
    assert ind.url_rank("resources.arsc/AndroidManifest.xml") == "noise"
