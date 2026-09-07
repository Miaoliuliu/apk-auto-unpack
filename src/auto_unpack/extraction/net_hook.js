// 网络层 URL 观测（试跑用）。不 dump dex，只打印/上报通联地址。
//
// 启动（新进程，推荐）：
//   frida -U -f <包名> -l src/auto_unpack/extraction/net_hook.js --no-pause
// 附加到已运行进程：
//   frida -U <包名> -l src/auto_unpack/extraction/net_hook.js
//
// 点进 App 业务页，控制台会出现 [url] 行。Python 侧可收 send 的 {type:"url",...}。

var seen = {};
var SEEN_MAX = 4000;

function emit(api, url) {
    if (!url) return;
    var s = ("" + url).trim();
    if (s.length < 4 || s.length > 2048) return;
    if (s.indexOf("://") < 0 && s.indexOf(".") < 0 && s.indexOf("[") < 0) return;
    var key = api + "|" + s;
    if (seen[key]) return;
    if (Object.keys(seen).length > SEEN_MAX) seen = {};
    seen[key] = 1;
    console.log("[url] " + api + "  " + s);
    try {
        send({ type: "url", api: api, url: s });
    } catch (e) {}
}

function safeStr(v) {
    if (v === null || v === undefined) return "";
    try {
        return v.toString();
    } catch (e) {
        return "";
    }
}

function hookCtor(cls, api, nArgs) {
    try {
        var overloads = cls.$init.overloads;
        for (var i = 0; i < overloads.length; i++) {
            (function (ov) {
                if (nArgs !== undefined && ov.argumentTypes.length !== nArgs) return;
                ov.implementation = function () {
                    var args = arguments;
                    for (var j = 0; j < args.length; j++) {
                        var a = args[j];
                        if (typeof a === "string") emit(api, a);
                    }
                    return ov.apply(this, args);
                };
            })(overloads[i]);
        }
        return true;
    } catch (e) {
        return false;
    }
}

function hookOkHttp() {
    var names = [
        "okhttp3.Request$Builder",
        "okhttp3.internal.http.RealInterceptorChain",
        "com.android.okhttp.Request$Builder",
        "com.squareup.okhttp.Request$Builder"
    ];
    names.forEach(function (name) {
        try {
            var B = Java.use(name);
            if (B.url) {
                B.url.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var a0 = arguments[0];
                        if (typeof a0 === "string") emit("okhttp.Builder.url", a0);
                        else emit("okhttp.Builder.url", safeStr(a0));
                        return ov.apply(this, arguments);
                    };
                });
                console.log("[*] hook " + name + ".url");
            }
        } catch (e) {}
    });

    ["okhttp3.OkHttpClient", "com.squareup.okhttp.OkHttpClient"].forEach(function (name) {
        try {
            var C = Java.use(name);
            ["newCall"].forEach(function (m) {
                if (!C[m]) return;
                C[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try {
                            var req = arguments[0];
                            if (req && req.url) emit("okhttp.newCall", safeStr(req.url()));
                        } catch (e2) {}
                        return ov.apply(this, arguments);
                    };
                });
            });
            console.log("[*] hook " + name + ".newCall");
        } catch (e) {}
    });

    try {
        var HttpUrl = Java.use("okhttp3.HttpUrl");
        if (HttpUrl.parse) {
            HttpUrl.parse.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    if (typeof arguments[0] === "string") emit("okhttp.HttpUrl.parse", arguments[0]);
                    return ov.apply(this, arguments);
                };
            });
            console.log("[*] hook okhttp3.HttpUrl.parse");
        }
    } catch (e) {}
}

function hookUrlAndHttp() {
    try {
        var URL = Java.use("java.net.URL");
        hookCtor(URL, "java.net.URL");
        if (URL.openConnection) {
            URL.openConnection.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    emit("URL.openConnection", safeStr(this.toString()));
                    return ov.apply(this, arguments);
                };
            });
        }
        console.log("[*] hook java.net.URL");
    } catch (e) {
        console.log("[!] java.net.URL: " + e);
    }

    try {
        var URI = Java.use("java.net.URI");
        hookCtor(URI, "java.net.URI");
        if (URI.create) {
            URI.create.overloads.forEach(function (ov) {
                ov.implementation = function (s) {
                    emit("URI.create", s);
                    return ov.apply(this, arguments);
                };
            });
        }
        console.log("[*] hook java.net.URI");
    } catch (e) {}

    try {
        var Conn = Java.use("java.net.HttpURLConnection");
        if (Conn.connect) {
            Conn.connect.implementation = function () {
                try { emit("HttpURLConnection", safeStr(this.getURL())); } catch (e2) {}
                return this.connect();
            };
        }
        console.log("[*] hook HttpURLConnection.connect");
    } catch (e) {}
}

function hookWebView() {
    try {
        var WV = Java.use("android.webkit.WebView");
        ["loadUrl", "postUrl", "loadDataWithBaseURL"].forEach(function (m) {
            if (!WV[m]) return;
            WV[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    for (var i = 0; i < arguments.length; i++) {
                        if (typeof arguments[i] === "string" && arguments[i].indexOf("://") >= 0)
                            emit("WebView." + m, arguments[i]);
                    }
                    return ov.apply(this, arguments);
                };
            });
        });
        console.log("[*] hook WebView.loadUrl");
    } catch (e) {}

    try {
        var WVC = Java.use("android.webkit.WebViewClient");
        if (WVC.shouldInterceptRequest) {
            WVC.shouldInterceptRequest.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    for (var i = 0; i < arguments.length; i++) {
                        var a = arguments[i];
                        if (typeof a === "string") emit("WebViewClient", a);
                        else {
                            try {
                                if (a && a.getUrl) emit("WebViewClient", safeStr(a.getUrl()));
                            } catch (e2) {}
                        }
                    }
                    return ov.apply(this, arguments);
                };
            });
        }
    } catch (e) {}
}

function hookSocket() {
    try {
        var ISA = Java.use("java.net.InetSocketAddress");
        ISA.$init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = arguments;
                var host = "";
                var port = "";
                for (var i = 0; i < args.length; i++) {
                    if (typeof args[i] === "string") host = args[i];
                    if (typeof args[i] === "number") port = args[i];
                    try {
                        if (args[i] && args[i].getHostAddress) host = args[i].getHostAddress();
                    } catch (e2) {}
                }
                if (host) emit("InetSocketAddress", port !== "" ? host + ":" + port : host);
                return ov.apply(this, args);
            };
        });
        console.log("[*] hook InetSocketAddress");
    } catch (e) {}

    try {
        var Sock = Java.use("java.net.Socket");
        Sock.connect.overloads.forEach(function (ov) {
            ov.implementation = function () {
                try { emit("Socket.connect", safeStr(arguments[0])); } catch (e2) {}
                return ov.apply(this, arguments);
            };
        });
        console.log("[*] hook Socket.connect");
    } catch (e) {}
}

function hookApache() {
    try {
        var URI = Java.use("org.apache.http.client.methods.HttpGet");
        hookCtor(URI, "apache.HttpGet");
        console.log("[*] hook apache HttpGet");
    } catch (e) {}
    try {
        var P = Java.use("org.apache.http.client.methods.HttpPost");
        hookCtor(P, "apache.HttpPost");
    } catch (e) {}
}

function hookNativeConnect() {
    var libc = Process.findModuleByName("libc.so");
    if (!libc) return;
    var addr = Module.findExportByName("libc.so", "connect");
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            try {
                var sa = args[1];
                var family = sa.readU16();
                // AF_INET=2, AF_INET6=10 on Android
                if (family === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." +
                             sa.add(6).readU8() + "." + sa.add(7).readU8();
                    if (port !== 0 && ip !== "0.0.0.0") emit("libc.connect", ip + ":" + port);
                } else if (family === 10) {
                    var port6 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var parts = [];
                    for (var i = 0; i < 8; i++) {
                        var hi = sa.add(8 + i * 2).readU8();
                        var lo = sa.add(9 + i * 2).readU8();
                        parts.push(((hi << 8) | lo).toString(16));
                    }
                    emit("libc.connect", "[" + parts.join(":") + "]:" + port6);
                }
            } catch (e) {}
        }
    });
    console.log("[*] hook libc.connect");
}

function installJavaHooks() {
    hookUrlAndHttp();
    hookOkHttp();
    hookWebView();
    hookSocket();
    hookApache();
}

setImmediate(function () {
    hookNativeConnect();
    if (!Java.available) {
        console.log("[!] Java VM 不可用，仅 native connect");
        return;
    }
    Java.perform(function () {
        installJavaHooks();
        console.log("[*] net_hook 就绪，操作 App 触发请求");
    });
});
