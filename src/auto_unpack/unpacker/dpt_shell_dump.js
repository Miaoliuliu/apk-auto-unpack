// dpt-shell 脱壳：只 dump 真正的 DexFile，禁止把 ArtMethod*/ClassDef& 当 dex 写盘。
//
// DefineClass(..., DexFile const&, ClassDef const&)  → args[5]，Handle 若占两槽则 args[6]
// LoadMethod(DexFile&, ...)                         → args[1]  Pixel 3 / Android 12
// LoadMethod(Thread*, DexFile&, ...)                → args[2]
//
// Android 8+ mCookie 可能是 long[]（[0]=OatFile*，其余 DexFile*），
// 或单个 jlong（指向 std::vector<DexFile*>）。两种都试。
//
// U1：dpt 的指令回填发生在 LoadMethod 过程中，onEnter 首轮可能抓到未回填的
//     抽取态。主动重扫轮（triggerLoad）允许对同一 DexFile 再 dump 一次
//     （round=2，Python 端按方法体空占比择优保留），不再被去重锁死。
//     ⚠️ 实测（钱包¥ 样本）产物中**没有任何 _r2 文件**，说明该补救通道未生效。
//     已补 stats 计数与收尾断言，重跑即可定位是"枚举不到"还是"字段取不到"。
// U2：每 classloader 主动 loadClass 上限 80 → 500；触发轮 3s/8s → 3s/8s/15s。
// U9：大 dex 分块发送（4MB/块），避免 Frida 单次 send 大 buffer 截断。

var dumped = {};            // key -> 已 dump 轮次数
var MAX_ROUNDS = 2;         // 每个 DexFile 最多 dump 轮数（1=首轮，2=重扫补捞）
var CHUNK_SIZE = 4 * 1024 * 1024;

// U1 诊断计数。triggerLoad 过去可能是静默零产出，没有任何可观测信号，
// 导致"U1 到底有没有生效"无法判断。每轮重扫与收尾都会打印这些数字。
var stats = {
    round1: 0,               // 首轮 dump 次数
    round2: 0,               // 第二轮（重扫补捞）dump 次数
    cookieFieldMissing: 0,   // mCookie / mInternalCookie 都取不到的 DexFile 数
    loaderNoDexFile: 0,      // dexElement 里拿不到 dexFile 的次数
    chooseHit: 0             // DexFile.choose 命中的对象数
};

// 只认 "dex\n"。"dey\n" 曾一并接受，但 Python 端 is_valid_dumped_dex 明确拒收
// （dey/vdex 的 file_size 语义与 dex 不同，repair_dumped_dexes 也不处理），
// 收了只会让大文件白走一遍分块发送再被丢弃 —— 这里同步拒收。
function isDexMagic(begin) {
    try {
        var mag = new Uint8Array(begin.readByteArray(4));
        if (mag.length < 4) return false;
        return mag[0] === 0x64 && mag[1] === 0x65 && mag[2] === 0x78 && mag[3] === 0x0a;
    } catch (e) {
        return false;
    }
}

function sendDexBytes(begin, fileSize, round) {
    var base = { type: "dex", begin: begin.toString(), size: fileSize, round: round };
    if (fileSize <= CHUNK_SIZE) {
        send(base, Memory.readByteArray(begin, fileSize));
        return;
    }
    // U9：分块发送，Python 端 _ChunkAssembler 按 begin 重组
    var total = Math.ceil(fileSize / CHUNK_SIZE);
    send({ type: "dex-begin", begin: begin.toString(), size: fileSize,
           round: round, chunks: total });
    for (var i = 0, off = 0; off < fileSize; i++, off += CHUNK_SIZE) {
        var n = Math.min(CHUNK_SIZE, fileSize - off);
        send({ type: "dex-chunk", begin: begin.toString(), seq: i },
             Memory.readByteArray(begin.add(off), n));
    }
}

function dumpDexFile(dexFilePtr, allowRedump) {
    try {
        if (!dexFilePtr || dexFilePtr.isNull()) return false;
        var begins = [];
        // AOSP art::DexFile 首成员是 const uint8_t* const begin_（偏移 0）；
        // 偏移 8 是 const size_t size_（数值而非指针）。原实现先试偏移 8，
        // 若该次解引用抛错，整个 dumpDexFile 会被外层 catch 吞掉、
        // 偏移 0 反而永远试不到 —— 现改为偏移 0 优先，且两次都各自 try。
        try { begins.push(dexFilePtr.readPointer()); } catch (e0) {}
        try { begins.push(dexFilePtr.add(8).readPointer()); } catch (e1) {}
        for (var c = 0; c < begins.length; c++) {
            var begin = begins[c];
            if (begin.isNull() || !isDexMagic(begin)) continue;
            var fileSize = begin.add(0x20).readU32();
            var headerSize = begin.add(0x24).readU32();
            if (headerSize !== 0x70 || fileSize < 0x70 || fileSize > 0x10000000) continue;
            var key = begin.toString() + "_" + fileSize;
            var rounds = dumped[key] || 0;
            if (rounds >= MAX_ROUNDS) return true;
            if (rounds > 0 && !allowRedump) return true;
            dumped[key] = rounds + 1;
            sendDexBytes(begin, fileSize, rounds + 1);
            if (rounds + 1 === 1) { stats.round1++; } else { stats.round2++; }
            console.log("[+] dump dex " + begin + " size=" + fileSize
                + " round=" + (rounds + 1) + (allowRedump ? " (主动重扫)" : " (hook)"));
            return true;
        }
    } catch (e) {}
    return false;
}

// 与 flow_dpt_shell.dex_file_arg_index 保持一致（主下标）；hook 里再探邻居槽位
function dexFileArgIndex(mangled) {
    if (mangled.indexOf("DefineClass") >= 0) return 5;
    if (mangled.indexOf("LoadMethod") >= 0) {
        if (mangled.indexOf("LoadMethodERKNS_7DexFile") >= 0) return 1;
        return 2;
    }
    return -1;
}

function hookClassLinker(kind) {
    var libart = Process.findModuleByName("libart.so");
    if (!libart) {
        console.log("[!] 找不到 libart.so");
        return;
    }
    var n = 0;
    libart.enumerateExports().forEach(function (exp) {
        if (exp.name.indexOf(kind) < 0 || exp.name.indexOf("ClassLinker") < 0) return;
        var idx = dexFileArgIndex(exp.name);
        if (idx < 0) return;
        console.log("[*] " + kind + " DexFile=args[" + idx + "] " + exp.name);
        Interceptor.attach(exp.address, {
            onEnter: function (args) {
                dumpDexFile(args[idx], false);
                if (kind === "DefineClass") dumpDexFile(args[6], false);
                if (kind === "LoadMethod") {
                    dumpDexFile(args[1], false);
                    dumpDexFile(args[2], false);
                }
            }
        });
        n++;
    });
    if (!n) console.log("[!] 未 hook 到 ClassLinker::" + kind);
}

function javaLongToPtr(jlong) {
    var hex = Java.use("java.lang.Long").toHexString(jlong);
    return ptr("0x" + hex);
}

function dumpStdVectorDex(vecPtr, allowRedump) {
    try {
        var b = vecPtr.readPointer();
        var e = vecPtr.add(Process.pointerSize).readPointer();
        var nbytes = e.sub(b).toInt32();
        if (nbytes <= 0 || nbytes % Process.pointerSize !== 0) return;
        var n = nbytes / Process.pointerSize;
        if (n > 128) return;
        for (var i = 0; i < n; i++) {
            dumpDexFile(b.add(i * Process.pointerSize).readPointer(), allowRedump);
        }
    } catch (e) {}
}

function dumpCookie(cookie, allowRedump) {
    if (cookie === null || cookie === undefined) return;
    function fromLong(v) {
        if (!v) return;
        var p = javaLongToPtr(v);
        dumpDexFile(p, allowRedump);
        dumpStdVectorDex(p, allowRedump);
    }
    try {
        var longArr = Java.cast(cookie, Java.use("[J"));
        for (var i = 0; i < longArr.length; i++) fromLong(longArr[i]);
        return;
    } catch (e) {}
    try {
        fromLong(Java.cast(cookie, Java.use("java.lang.Long")).longValue());
    } catch (e2) {}
}

var _cookieFieldLogged = false;

function dumpJavaDexFileObj(df, allowRedump) {
    if (!df) return;
    var DexFile = Java.use("dalvik.system.DexFile");
    var gotField = false;
    ["mCookie", "mInternalCookie"].forEach(function (name) {
        try {
            var f = DexFile.class.getDeclaredField(name);
            f.setAccessible(true);
            gotField = true;
            dumpCookie(f.get(df), allowRedump);
        } catch (e) {
            // 某版本只存在其中一个字段属预期，故只在首次提示一次，避免刷屏
            if (!_cookieFieldLogged) {
                _cookieFieldLogged = true;
                console.log("[*] DexFile." + name + " 取不到（另一字段通常会命中）: " + e);
            }
        }
    });
    if (!gotField) stats.cookieFieldMissing++;
}

function dumpFromClassLoader(loader, allowRedump) {
    try {
        var PathClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
        var pathListField = PathClassLoader.class.getDeclaredField("pathList");
        pathListField.setAccessible(true);
        var pathList;
        try {
            pathList = pathListField.get(loader);
        } catch (e2) {
            // BootClassLoader 等非 BaseDexClassLoader 没有 pathList 字段，跳过即可，
            // 不必打印错误噪音。
            return;
        }
        if (!pathList) return;
        var DexPathList = Java.use("dalvik.system.DexPathList");
        var elementsField = DexPathList.class.getDeclaredField("dexElements");
        elementsField.setAccessible(true);
        var elements = elementsField.get(pathList);
        var arr = Java.use("java.lang.reflect.Array");
        var len = arr.getLength(elements);
        console.log("[*] ClassLoader 有 " + len + " 个 dexElement");
        for (var i = 0; i < len; i++) {
            var el = arr.get(elements, i);
            // 部分 dexElement 的 dexFile 字段为空，判空避免 TypeError 噪音
            var df = null;
            try {
                if (el.dexFile) {
                    df = el.dexFile.value;
                }
            } catch (e2) {}
            if (!df) { stats.loaderNoDexFile++; continue; }
            dumpJavaDexFileObj(df, allowRedump);
            try {
                var en = df.entries();
                var n = 0;
                // U2：80 → 500。业务 dex 数千类，80 个触发面太小，
                // 未加载的类在 dpt 回填前 dump 会缺方法体。
                var MAX = 500;
                while (en.hasMoreElements() && n < MAX) {
                    try { loader.loadClass(en.nextElement()); } catch (e2) {}
                    n++;
                }
                console.log("[*] 触发 loadClass " + n + " 个类");
            } catch (e2) {}
            dumpJavaDexFileObj(df, true);
        }
    } catch (e) {
        console.log("[!] ClassLoader dump: " + e);
    }
}

function triggerLoad(round) {
    console.log("[*] triggerLoad 第 " + round + " 轮");
    Java.perform(function () {
        try {
            var loaders = 0;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    loaders++;
                    dumpFromClassLoader(loader, true);
                },
                onComplete: function () {
                    console.log("[*] 枚举 ClassLoader " + loaders + " 个");
                }
            });
        } catch (e) {
            console.log("[!] 枚举失败: " + e);
        }
        try {
            var hit = 0;
            Java.choose("dalvik.system.DexFile", {
                onMatch: function (df) {
                    hit++;
                    stats.chooseHit++;
                    dumpJavaDexFileObj(df, true);
                },
                onComplete: function () {}
            });
            console.log("[*] DexFile.choose 命中 " + hit + " 个");
        } catch (e2) {
            console.log("[!] DexFile.choose: " + e2);
        }
        console.log("[*] 统计: 首轮 " + stats.round1 + " / 第二轮 " + stats.round2
            + " / Cookie 字段全缺 " + stats.cookieFieldMissing
            + " / loader 内无 dexFile " + stats.loaderNoDexFile);
    });
}

hookClassLinker("DefineClass");
hookClassLinker("LoadMethod");
setTimeout(function () { triggerLoad(1); }, 3000);
setTimeout(function () { triggerLoad(2); }, 8000);
setTimeout(function () { triggerLoad(3); }, 15000);
// 收尾断言：U1 的目的就是靠第二轮补捞回填态。若第二轮恒为 0，
// 说明补救通道没生效，此时首轮若为抽取态则产物不完整。
setTimeout(function () {
    console.log("[*] 最终统计: 首轮 " + stats.round1 + " / 第二轮 " + stats.round2
        + " / Cookie 字段全缺 " + stats.cookieFieldMissing
        + " / loader 内无 dexFile " + stats.loaderNoDexFile
        + " / choose 命中 " + stats.chooseHit);
    if (stats.round2 === 0) {
        console.log("[!] 第二轮 dump 为 0：U1 重扫补捞未生效。请对照上面的"
            + "「枚举 ClassLoader N 个 / DexFile.choose 命中 M 个 / Cookie 字段全缺 K」"
            + " 定位是枚举空、字段取不到、还是 allowRedump 被绕过。");
    }
}, 20000);
console.log("[*] dpt-shell dump 脚本就绪");
