// dpt-shell 脱壳：只 dump 真正的 DexFile，禁止把 ArtMethod*/ClassDef& 当 dex 写盘。
//
// DefineClass(..., DexFile const&, ClassDef const&)  → args[5]，Handle 若占两槽则 args[6]
// LoadMethod(DexFile&, ...)                         → args[1]  Pixel 3 / Android 12
// LoadMethod(Thread*, DexFile&, ...)                → args[2]
//
// Android 8+ mCookie 可能是 long[]（[0]=OatFile*，其余 DexFile*），
// 或单个 jlong（指向 std::vector<DexFile*>）。两种都试。

var dumped = {};

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

function dumpDexFile(dexFilePtr) {
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
            if (dumped[key]) return true;
            dumped[key] = 1;
            var bytes = Memory.readByteArray(begin, fileSize);
            send({ type: "dex", begin: begin.toString(), size: fileSize }, bytes);
            console.log("[+] dump dex " + begin + " size=" + fileSize);
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
                dumpDexFile(args[idx]);
                if (kind === "DefineClass") dumpDexFile(args[6]);
                if (kind === "LoadMethod") {
                    dumpDexFile(args[1]);
                    dumpDexFile(args[2]);
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

function dumpStdVectorDex(vecPtr) {
    try {
        var b = vecPtr.readPointer();
        var e = vecPtr.add(Process.pointerSize).readPointer();
        var nbytes = e.sub(b).toInt32();
        if (nbytes <= 0 || nbytes % Process.pointerSize !== 0) return;
        var n = nbytes / Process.pointerSize;
        if (n > 128) return;
        for (var i = 0; i < n; i++) {
            dumpDexFile(b.add(i * Process.pointerSize).readPointer());
        }
    } catch (e) {}
}

function dumpCookie(cookie) {
    if (cookie === null || cookie === undefined) return;
    function fromLong(v) {
        if (!v) return;
        var p = javaLongToPtr(v);
        dumpDexFile(p);
        dumpStdVectorDex(p);
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

function dumpJavaDexFileObj(df) {
    if (!df) return;
    var DexFile = Java.use("dalvik.system.DexFile");
    ["mCookie", "mInternalCookie"].forEach(function (name) {
        try {
            var f = DexFile.class.getDeclaredField(name);
            f.setAccessible(true);
            dumpCookie(f.get(df));
        } catch (e) {}
    });
}

function dumpFromClassLoader(loader) {
    try {
        var PathClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
        var pathListField = PathClassLoader.class.getDeclaredField("pathList");
        pathListField.setAccessible(true);
        var pathList = pathListField.get(loader);
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
            var df = el.dexFile.value;
            if (!df) continue;
            dumpJavaDexFileObj(df);
            try {
                var en = df.entries();
                var n = 0;
                var MAX = 80;
                while (en.hasMoreElements() && n < MAX) {
                    try { loader.loadClass(en.nextElement()); } catch (e2) {}
                    n++;
                }
                console.log("[*] 触发 loadClass " + n + " 个类");
            } catch (e2) {}
            dumpJavaDexFileObj(df);
        }
    } catch (e) {
        console.log("[!] ClassLoader dump: " + e);
    }
}

function triggerLoad() {
    Java.perform(function () {
        try {
            Java.enumerateClassLoaders({
                onMatch: dumpFromClassLoader,
                onComplete: function () {}
            });
        } catch (e) {
            console.log("[!] 枚举失败: " + e);
        }
        try {
            Java.choose("dalvik.system.DexFile", {
                onMatch: dumpJavaDexFileObj,
                onComplete: function () {}
            });
        } catch (e2) {
            console.log("[!] DexFile.choose: " + e2);
        }
    });
}

hookClassLinker("DefineClass");
hookClassLinker("LoadMethod");
setTimeout(triggerLoad, 3000);
setTimeout(triggerLoad, 8000);
console.log("[*] dpt-shell dump 脚本就绪");
