// 网络层通联观测（手工试跑，未接入 pipeline）。
// 目标：启动到登录页也能拿到 host / IP:端口；完整 HTTP URL 能抓到就算赚到。
// 出口层（DNS / connect / TLS）为主，OkHttp / WebView / X5 能挂就挂。
//
// 新进程：
//   frida -U -f <包名> -l src/auto_unpack/extraction/net_hook.js --no-pause
//   frida -H 127.0.0.1:14725 -f <包名> -l src/auto_unpack/extraction/net_hook.js --no-pause
// 已在登录页时 attach（进程容易秒退时优先这条）：
//   frida -H 127.0.0.1:14725 <包名> -l src/auto_unpack/extraction/net_hook.js
//
// 行前缀：[http] 完整 URL  [host] 域名  [ip] IP:端口
// 接入 Python 时把 EMIT_SEND 改 true。

var EMIT_SEND = false;
var SEEN_MAX = 4000;
var seen = {};
var hookedNative = {};
var hookedJava = {};

function logHook(msg) {
    console.log("[*] " + msg);
}

function safeStr(v) {
    if (v === null || v === undefined) return "";
    try {
        return v.toString();
    } catch (e) {
        return "";
    }
}

function v4Mapped(ip6hexParts) {
    // 8 个 hex 段，例如 0:0:0:0:0:ffff:df05:505
    if (!ip6hexParts || ip6hexParts.length !== 8) return null;
    for (var i = 0; i < 5; i++) {
        if (parseInt(ip6hexParts[i], 16) !== 0) return null;
    }
    if (parseInt(ip6hexParts[5], 16) !== 0xffff) return null;
    var hi = parseInt(ip6hexParts[6], 16);
    var lo = parseInt(ip6hexParts[7], 16);
    return ((hi >> 8) & 255) + "." + (hi & 255) + "." + ((lo >> 8) & 255) + "." + (lo & 255);
}

function stripHostPort(s) {
    var t = ("" + s).trim();
    if (!t) return t;
    t = t.replace(/^https?:\/\//i, "");
    t = t.replace(/\/.*$/, "");
    if (t.charAt(0) === "[") {
        var end = t.indexOf("]");
        if (end > 0) t = t.substring(1, end);
    } else {
        var c = t.lastIndexOf(":");
        if (c > 0 && t.indexOf(":") === c) t = t.substring(0, c);
    }
    return t.toLowerCase();
}

function isNoise(raw) {
    var s = ("" + raw).trim();
    if (!s) return true;
    var low = s.toLowerCase();

    if (s.charAt(0) === "/" && low.indexOf("://") < 0 && low.indexOf("/system/") === 0)
        return true;
    if (/\.jar($|\?)/.test(low) && low.indexOf("://") < 0) return true;

    var host = stripHostPort(s);
    if (host === "localhost" || host === "::1" || host === "0.0.0.0" || host === "[::]")
        return true;
    if (host === "127.0.0.1" || host.indexOf("127.0.0.1") === 0) return true;
    if (host.indexOf("7f00:1") >= 0) return true;

    if (/:(53|5353)$/.test(s)) return true;

    var dns = {
        "8.8.8.8": 1, "8.8.4.4": 1, "1.1.1.1": 1, "1.0.0.1": 1,
        "223.5.5.5": 1, "223.6.6.6": 1, "114.114.114.114": 1,
        "119.29.29.29": 1, "9.9.9.9": 1
    };
    if (dns[host]) return true;

    var sdk = [
        "openinstall.com", "deepinstall.com", "umeng.com", "umengcloud.com",
        "jpush.cn", "jiguang.cn", "getui.com", "igexin.com",
        "usertrust.com", "sectigo.com", "pki.goog", "googleapis.com",
        "google.com", "gvt2.com", "gstatic.com", "facebook.com", "fbcdn.net",
        "crashlytics.com", "firebaseio.com", "doubleclick.net"
    ];
    for (var i = 0; i < sdk.length; i++) {
        if (host === sdk[i] || host.substring(host.length - sdk[i].length - 1) === "." + sdk[i])
            return true;
    }
    if (/\b(crl|ocsp)\./.test(low) || /\.(crl|p7c|crt)(\?|$)/.test(low)) return true;
    if (/\/ping(\?|$)/.test(low) && host === "127.0.0.1") return true;
    return false;
}

function inferKind(s) {
    var t = ("" + s).trim();
    if (/^https?:\/\//i.test(t)) return "http";
    if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(t)) return "ip";
    if (t.charAt(0) === "[") return "ip";
    if (/^\[?[0-9a-f:]+\]?:\d+$/i.test(t)) return "ip";
    return "host";
}

function emit(api, url, kind) {
    if (!url) return;
    var s = ("" + url).trim();
    if (s.length < 4 || s.length > 2048) return;
    if (s.indexOf("://") < 0 && s.indexOf(".") < 0 && s.indexOf("[") < 0 && s.indexOf(":") < 0)
        return;
    if (isNoise(s)) return;
    kind = kind || inferKind(s);
    var key = kind + "|" + s.toLowerCase();
    if (seen[key]) return;
    if (Object.keys(seen).length > SEEN_MAX) seen = {};
    seen[key] = 1;
    console.log("[" + kind + "] " + api + "  " + s);
    if (EMIT_SEND) {
        try {
            send({ type: "url", kind: kind, api: api, url: s });
        } catch (e) {}
    }
}

function attachNative(ptr, name, callbacks) {
    if (!ptr || ptr.isNull()) return false;
    var k = ptr.toString();
    if (hookedNative[k]) return false;
    hookedNative[k] = true;
    try {
        Interceptor.attach(ptr, callbacks);
        logHook(name);
        return true;
    } catch (e) {
        console.log("[!] " + name + ": " + e);
        return false;
    }
}

function findExport(modName, exp) {
    try {
        if (modName) return Module.findExportByName(modName, exp);
        return Module.findExportByName(null, exp);
    } catch (e) {
        return null;
    }
}

function parseHttpPlain(api, s) {
    if (!s) return;
    var head = s.substring(0, 2048);
    if (!/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT) /i.test(head) &&
        !/^host:/im.test(head))
        return;
    var first = (head.split("\r\n")[0] || head.split("\n")[0] || "").trim();
    var req = /^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT)\s+(\S+)/i.exec(first);
    var hm = /\r\nHost:\s*([^\r\n]+)/i.exec(head) || /\nHost:\s*([^\r\n]+)/i.exec(head);
    var host = hm ? hm[1].trim() : "";
    if (req) {
        var path = req[2];
        if (/^https?:\/\//i.test(path)) {
            emit(api, path, "http");
            return;
        }
        if (req[1].toUpperCase() === "CONNECT") {
            emit(api, path, inferKind(path));
            return;
        }
        if (host) {
            var slash = path.charAt(0) === "/" ? path : "/" + path;
            emit(api, "https://" + host + slash, "http");
            return;
        }
    }
    if (host) emit(api + ".Host", host, "host");
}

function readMaybeAscii(ptr, len) {
    if (!ptr || ptr.isNull() || len <= 0) return "";
    var n = len > 2048 ? 2048 : len;
    try {
        var buf = ptr.readByteArray(n);
        if (!buf) return "";
        var bytes = new Uint8Array(buf);
        if (bytes.length === 0) return "";
        var c0 = bytes[0];
        if (c0 < 32 || c0 > 126) return "";
        var out = "";
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i];
            if (b === 0) break;
            if (b < 9 || (b > 13 && b < 32)) return "";
            out += String.fromCharCode(b);
        }
        return out;
    } catch (e) {
        return "";
    }
}

function hookGetaddrinfo() {
    ["getaddrinfo", "android_getaddrinfo"].forEach(function (sym) {
        var addr = findExport("libc.so", sym) || findExport(null, sym);
        attachNative(addr, "libc." + sym, {
            onEnter: function (args) {
                try {
                    if (args[0].isNull()) return;
                    var host = args[0].readCString();
                    if (!host) return;
                    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return;
                    emit("dns." + sym, host, "host");
                } catch (e) {}
            }
        });
    });
}

function emitConnectIp(api, ip, port) {
    if (!ip || port === 0) return;
    if (ip === "0.0.0.0" || ip === "::" || ip === "127.0.0.1") return;
    emit(api, ip + ":" + port, "ip");
}

function hookNativeConnect() {
    var addr = findExport("libc.so", "connect") || findExport("libc.so", "__connect") ||
        findExport(null, "connect");
    attachNative(addr, "libc.connect", {
        onEnter: function (args) {
            try {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." +
                             sa.add(6).readU8() + "." + sa.add(7).readU8();
                    emitConnectIp("libc.connect", ip, port);
                } else if (family === 10) {
                    var port6 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var parts = [];
                    for (var i = 0; i < 8; i++) {
                        var hi = sa.add(8 + i * 2).readU8();
                        var lo = sa.add(9 + i * 2).readU8();
                        parts.push(((hi << 8) | lo).toString(16));
                    }
                    var v4 = v4Mapped(parts);
                    if (v4) emitConnectIp("libc.connect", v4, port6);
                    else emitConnectIp("libc.connect", "[" + parts.join(":") + "]", port6);
                }
            } catch (e) {}
        }
    });
}

function hookSslWriteModule(mod) {
    if (!mod) return;
    var writePtr = null;
    var namePtr = null;
    try {
        writePtr = Module.findExportByName(mod.name, "SSL_write");
        namePtr = Module.findExportByName(mod.name, "SSL_get_servername");
    } catch (e) {
        return;
    }
    if (!writePtr) return;
    var getName = null;
    if (namePtr) {
        try {
            getName = new NativeFunction(namePtr, "pointer", ["pointer", "int"]);
        } catch (e2) {}
    }
    attachNative(writePtr, mod.name + "!SSL_write", {
        onEnter: function (args) {
            try {
                if (getName) {
                    var n = getName(args[0], 0);
                    if (!n.isNull()) {
                        var host = n.readCString();
                        if (host) emit("sni." + mod.name, host, "host");
                    }
                }
                var len = args[2].toInt32();
                parseHttpPlain("SSL_write", readMaybeAscii(args[1], len));
            } catch (e) {}
        }
    });
}

function hookSendIfHttp() {
    ["send", "sendto"].forEach(function (sym) {
        var addr = findExport("libc.so", sym) || findExport(null, sym);
        attachNative(addr, "libc." + sym, {
            onEnter: function (args) {
                try {
                    var len = args[2].toInt32();
                    if (len < 8 || len > 8192) return;
                    parseHttpPlain("libc." + sym, readMaybeAscii(args[1], len));
                } catch (e) {}
            }
        });
    });
}

function hookAllSsl() {
    try {
        Process.enumerateModules().forEach(function (m) {
            if (/ssl|conscrypt|boringssl|javacrypto|cronet/i.test(m.name))
                hookSslWriteModule(m);
        });
    } catch (e) {}
}

function hookDlopen() {
    ["android_dlopen_ext", "dlopen"].forEach(function (sym) {
        var addr = findExport("libdl.so", sym) || findExport("libc.so", sym) ||
            findExport(null, sym);
        attachNative(addr, "dlopen:" + sym, {
            onEnter: function (args) {
                try {
                    this.path = args[0].isNull() ? "" : args[0].readCString();
                } catch (e) {
                    this.path = "";
                }
            },
            onLeave: function () {
                if (this.path && /ssl|conscrypt|boringssl|cronet/i.test(this.path))
                    hookAllSsl();
            }
        });
    });
}

function onceJava(name) {
    if (hookedJava[name]) return false;
    hookedJava[name] = true;
    return true;
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

function hookOkHttpClass(name) {
    var key = "okhttp:" + name;
    if (hookedJava[key]) return;
    try {
        var B = Java.use(name);
        hookedJava[key] = true;
        if (B.url) {
            B.url.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var a0 = arguments[0];
                    emit("okhttp.Builder.url", typeof a0 === "string" ? a0 : safeStr(a0), "http");
                    return ov.apply(this, arguments);
                };
            });
            logHook("hook " + name + ".url");
        }
    } catch (e) {}
}

function hookOkHttpClient(name) {
    var key = "okhttpClient:" + name;
    if (hookedJava[key]) return;
    try {
        var C = Java.use(name);
        if (!C.newCall) return;
        hookedJava[key] = true;
        C.newCall.overloads.forEach(function (ov) {
            ov.implementation = function () {
                try {
                    var req = arguments[0];
                    if (req && req.url) emit("okhttp.newCall", safeStr(req.url()), "http");
                } catch (e2) {}
                return ov.apply(this, arguments);
            };
        });
        logHook("hook " + name + ".newCall");
    } catch (e) {}
}

function hookOkHttp() {
    [
        "okhttp3.Request$Builder",
        "com.android.okhttp.Request$Builder",
        "com.squareup.okhttp.Request$Builder"
    ].forEach(hookOkHttpClass);
    ["okhttp3.OkHttpClient", "com.squareup.okhttp.OkHttpClient"].forEach(hookOkHttpClient);
    if (hookedJava["okhttp3.HttpUrl"]) return;
    try {
        var HttpUrl = Java.use("okhttp3.HttpUrl");
        hookedJava["okhttp3.HttpUrl"] = true;
        if (HttpUrl.parse) {
            HttpUrl.parse.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    if (typeof arguments[0] === "string")
                        emit("okhttp.HttpUrl.parse", arguments[0], "http");
                    return ov.apply(this, arguments);
                };
            });
            logHook("hook okhttp3.HttpUrl.parse");
        }
    } catch (e) {}
}

function hookOkHttpEnumerated() {
    try {
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (hookedJava["okhttp:" + name] || hookedJava["okhttpClient:" + name])
                    return;
                if (name.indexOf("okhttp3.") !== 0 && name.indexOf("okhttp.") < 0)
                    return;
                if (name.indexOf("Request$Builder") >= 0) hookOkHttpClass(name);
                else if (/OkHttpClient$/.test(name)) hookOkHttpClient(name);
            },
            onComplete: function () {}
        });
    } catch (e) {}
}

function hookUrlAndHttp() {
    if (!onceJava("java.net.URL")) return;
    try {
        var URL = Java.use("java.net.URL");
        hookCtor(URL, "java.net.URL");
        if (URL.openConnection) {
            URL.openConnection.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    emit("URL.openConnection", safeStr(this.toString()), "http");
                    return ov.apply(this, arguments);
                };
            });
        }
        logHook("hook java.net.URL");
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
        logHook("hook java.net.URI");
    } catch (e) {}

    try {
        var Conn = Java.use("java.net.HttpURLConnection");
        if (Conn.connect) {
            Conn.connect.implementation = function () {
                try { emit("HttpURLConnection", safeStr(this.getURL()), "http"); } catch (e2) {}
                return this.connect();
            };
        }
        logHook("hook HttpURLConnection.connect");
    } catch (e) {}
}

function hookWebViewClass(clsName, tag) {
    if (hookedJava[clsName]) return true;
    try {
        var WV = Java.use(clsName);
        hookedJava[clsName] = true;
        ["loadUrl", "postUrl", "loadDataWithBaseURL"].forEach(function (m) {
            if (!WV[m]) return;
            WV[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    for (var i = 0; i < arguments.length; i++) {
                        if (typeof arguments[i] === "string" && arguments[i].indexOf("://") >= 0)
                            emit(tag + "." + m, arguments[i], "http");
                    }
                    return ov.apply(this, arguments);
                };
            });
        });
        logHook("hook " + clsName);
        return true;
    } catch (e) {
        return false;
    }
}

function hookWebViewClientClass(clsName, tag) {
    var key = clsName + ".client";
    if (hookedJava[key]) return;
    try {
        var WVC = Java.use(clsName);
        hookedJava[key] = true;
        ["shouldInterceptRequest", "shouldOverrideUrlLoading", "onPageStarted"].forEach(function (m) {
            if (!WVC[m]) return;
            WVC[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    for (var i = 0; i < arguments.length; i++) {
                        var a = arguments[i];
                        if (typeof a === "string" && a.indexOf("://") >= 0)
                            emit(tag, a, "http");
                        else {
                            try {
                                if (a && a.getUrl)
                                    emit(tag, safeStr(a.getUrl()), "http");
                            } catch (e2) {}
                        }
                    }
                    return ov.apply(this, arguments);
                };
            });
        });
    } catch (e) {}
}

function hookWebView() {
    hookWebViewClass("android.webkit.WebView", "WebView");
    hookWebViewClientClass("android.webkit.WebViewClient", "WebViewClient");
}

function hookX5() {
    var ok = hookWebViewClass("com.tencent.smtt.sdk.WebView", "X5");
    hookWebViewClass("com.tencent.tbs.core.webkit.WebView", "X5.tbs");
    hookWebViewClientClass("com.tencent.smtt.sdk.WebViewClient", "X5Client");
    if (ok) logHook("X5 WebView 已挂");
}

function hookCronet() {
    if (hookedJava["cronet.UrlRequest.Builder"]) return;
    try {
        var Eng = Java.use("org.chromium.net.CronetEngine");
        hookedJava["cronet.UrlRequest.Builder"] = true;
        if (Eng.newUrlRequestBuilder) {
            Eng.newUrlRequestBuilder.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    if (typeof arguments[0] === "string")
                        emit("cronet.newUrlRequestBuilder", arguments[0], "http");
                    return ov.apply(this, arguments);
                };
            });
            logHook("hook CronetEngine.newUrlRequestBuilder");
        }
    } catch (e) {}
}

function hookSocket() {
    if (!onceJava("InetSocketAddress")) return;
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
                if (host) {
                    var v = port !== "" ? host + ":" + port : host;
                    emit("InetSocketAddress", v, inferKind(v));
                }
                return ov.apply(this, args);
            };
        });
        logHook("hook InetSocketAddress");
    } catch (e) {}

    try {
        var Sock = Java.use("java.net.Socket");
        Sock.connect.overloads.forEach(function (ov) {
            ov.implementation = function () {
                try { emit("Socket.connect", safeStr(arguments[0])); } catch (e2) {}
                return ov.apply(this, arguments);
            };
        });
        logHook("hook Socket.connect");
    } catch (e) {}
}

function hookApache() {
    if (!onceJava("apache.HttpGet")) return;
    try {
        var G = Java.use("org.apache.http.client.methods.HttpGet");
        hookCtor(G, "apache.HttpGet");
        logHook("hook apache HttpGet");
    } catch (e) {}
    try {
        var P = Java.use("org.apache.http.client.methods.HttpPost");
        hookCtor(P, "apache.HttpPost");
    } catch (e) {}
}

function hookJavaDns() {
    if (!onceJava("InetAddress")) return;
    try {
        var IA = Java.use("java.net.InetAddress");
        IA.getByName.overload("java.lang.String").implementation = function (host) {
            if (host && !/^\d{1,3}(\.\d{1,3}){3}$/.test(host))
                emit("InetAddress.getByName", host, "host");
            return this.getByName(host);
        };
        IA.getAllByName.overload("java.lang.String").implementation = function (host) {
            if (host && !/^\d{1,3}(\.\d{1,3}){3}$/.test(host))
                emit("InetAddress.getAllByName", host, "host");
            return this.getAllByName(host);
        };
        logHook("hook InetAddress DNS");
    } catch (e) {}
}

function hookConscryptSni() {
    var names = [
        "com.android.org.conscrypt.ConscryptFileDescriptorSocket",
        "com.android.org.conscrypt.OpenSSLSocketImpl",
        "com.android.org.conscrypt.Java8FileDescriptorSocket",
        "com.android.org.conscrypt.ConscryptEngineSocket"
    ];
    names.forEach(function (name) {
        var key = "sni:" + name;
        if (hookedJava[key]) return;
        try {
            var C = Java.use(name);
            hookedJava[key] = true;
            if (C.setHostname) {
                C.setHostname.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        if (typeof arguments[0] === "string")
                            emit("conscrypt.setHostname", arguments[0], "host");
                        return ov.apply(this, arguments);
                    };
                });
            }
            if (C.startHandshake) {
                C.startHandshake.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try {
                            if (this.getHostname)
                                emit("conscrypt.getHostname", safeStr(this.getHostname()), "host");
                            else if (this.getSession)
                                emit("ssl.peerHost", safeStr(this.getSession().getPeerHost()), "host");
                        } catch (e2) {}
                        return ov.apply(this, arguments);
                    };
                });
            }
            logHook("hook " + name + " SNI");
        } catch (e) {}
    });
}

function hookUriParse() {
    if (!onceJava("android.net.Uri.parse")) return;
    try {
        var Uri = Java.use("android.net.Uri");
        Uri.parse.overload("java.lang.String").implementation = function (s) {
            if (s && (s.indexOf("http://") === 0 || s.indexOf("https://") === 0))
                emit("Uri.parse", s, "http");
            return this.parse(s);
        };
        logHook("hook Uri.parse");
    } catch (e) {}
}

function installJavaHooks() {
    hookUrlAndHttp();
    hookOkHttp();
    hookWebView();
    hookX5();
    hookCronet();
    hookSocket();
    hookApache();
    hookJavaDns();
    hookConscryptSni();
    hookUriParse();
    hookOkHttpEnumerated();
}

function installNative() {
    hookNativeConnect();
    hookGetaddrinfo();
    hookSendIfHttp();
    hookAllSsl();
    hookDlopen();
}

setImmediate(function () {
    installNative();
    if (!Java.available) {
        console.log("[!] Java VM 不可用，仅 native DNS/connect/TLS");
        return;
    }
    Java.perform(function () {
        installJavaHooks();
        console.log("[*] net_hook 就绪（登录页即可；[http]/[host]/[ip]）");
        setTimeout(function () {
            Java.perform(function () {
                hookX5();
                hookOkHttp();
                hookOkHttpEnumerated();
                hookCronet();
                hookConscryptSni();
                hookAllSsl();
            });
        }, 2500);
    });
});
