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
// U2：每 classloader 主动 loadClass 上限 80 → 500；触发轮 3s/8s → 3s/8s/15s。
// U9：大 dex 分块发送（4MB/块），避免 Frida 单次 send 大 buffer 截断。

var dumped = {};            // key -> 已 dump 轮次数
var MAX_ROUNDS = 2;         // 每个 DexFile 最多 dump 轮数（1=首轮，2=重扫补捞）
var CHUNK_SIZE = 4 * 1024 * 1024;

function isDexMagic(begin) {
    try {
        var mag = new Uint8Array(begin.readByteArray(4));
        if (mag.length < 4) return false;
        return (mag[0] === 0x64 && mag[1] === 0x65 && mag[2] === 0x78 && mag[3] === 0x0a)
            || (mag[0] === 0x64 && mag[1] === 0x65 && mag[2] === 0x79 && mag[3] === 0x0a);
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
        var begins = [dexFilePtr.add(8).readPointer()];
        try { begins.push(dexFilePtr.readPointer()); } catch (e0) {}
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
            console.log("[+] dump dex " + begin + " size=" + fileSize
                + " round=" + (rounds + 1));
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

function dumpJavaDexFileObj(df, allowRedump) {
    if (!df) return;
    var DexFile = Java.use("dalvik.system.DexFile");
    ["mCookie", "mInternalCookie"].forEach(function (name) {
        try {
            var f = DexFile.class.getDeclaredField(name);
            f.setAccessible(true);
            dumpCookie(f.get(df), allowRedump);
        } catch (e) {}
    });
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
            if (!df) continue;
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
    Java.perform(function () {
        try {
            Java.enumerateClassLoaders({
                onMatch: function (loader) { dumpFromClassLoader(loader, true); },
                onComplete: function () {}
            });
        } catch (e) {
            console.log("[!] 枚举失败: " + e);
        }
        try {
            Java.choose("dalvik.system.DexFile", {
                onMatch: function (df) { dumpJavaDexFileObj(df, true); },
                onComplete: function () {}
            });
        } catch (e2) {
            console.log("[!] DexFile.choose: " + e2);
        }
    });
}

hookClassLinker("DefineClass");
hookClassLinker("LoadMethod");
setTimeout(function () { triggerLoad(1); }, 3000);
setTimeout(function () { triggerLoad(2); }, 8000);
setTimeout(function () { triggerLoad(3); }, 15000);
console.log("[*] dpt-shell dump 脚本就绪");
