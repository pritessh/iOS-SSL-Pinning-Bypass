setTimeout(function () {
    console.log("[*] SSL Bypass Starting...");

    function findExport(sym) {
        var result = null;
        Process.enumerateModules().forEach(function (mod) {
            if (result) return;
            try {
                var addr = mod.findExportByName(sym);
                if (addr) { result = addr; }
            } catch (e) {}
        });
        return result;
    }

    function safeHook(label, fn) {
        try { fn(); } catch (e) { console.log("[-] " + label + ": " + e.message); }
    }

    // ===== All confirmed working hooks =====
    safeHook("SecTrustEvaluate", function () {
        var addr = findExport("SecTrustEvaluate");
        if (!addr) return;
        Interceptor.replace(addr, new NativeCallback(function (trust, result) {
            try { if (result && !result.isNull()) result.writeU32(1); } catch(e) {}
            return 0;
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] SecTrustEvaluate");
    });

    safeHook("SecTrustEvaluateWithError", function () {
        var addr = findExport("SecTrustEvaluateWithError");
        if (!addr) return;
        Interceptor.replace(addr, new NativeCallback(function (trust, error) {
            try { if (error && !error.isNull()) error.writePointer(ptr("0x0")); } catch(e) {}
            return 1;
        }, 'bool', ['pointer', 'pointer']));
        console.log("[+] SecTrustEvaluateWithError");
    });

    safeHook("SecTrustGetTrustResult", function () {
        var addr = findExport("SecTrustGetTrustResult");
        if (!addr) return;
        Interceptor.replace(addr, new NativeCallback(function (trust, result) {
            try { if (result && !result.isNull()) result.writeU32(1); } catch(e) {}
            return 0;
        }, 'int', ['pointer', 'pointer']));
        console.log("[+] SecTrustGetTrustResult");
    });

    safeHook("SecTrustSetExceptions", function () {
        var addr = findExport("SecTrustSetExceptions");
        if (!addr) return;
        Interceptor.attach(addr, {
            onLeave: function (retval) { retval.replace(ptr(1)); }
        });
        console.log("[+] SecTrustSetExceptions");
    });

    safeHook("SSL_CTX_set_custom_verify", function () {
        var addr = findExport("SSL_CTX_set_custom_verify");
        if (!addr) return;
        var cb = new NativeCallback(function (ssl, out_alert) { return 0; }, 'int', ['pointer', 'pointer']);
        Interceptor.attach(addr, { onEnter: function (args) { args[2] = cb; } });
        console.log("[+] SSL_CTX_set_custom_verify");
    });

    safeHook("SSL_set_custom_verify", function () {
        var addr = findExport("SSL_set_custom_verify");
        if (!addr) return;
        var cb = new NativeCallback(function (ssl, out_alert) { return 0; }, 'int', ['pointer', 'pointer']);
        Interceptor.attach(addr, { onEnter: function (args) { args[2] = cb; } });
        console.log("[+] SSL_set_custom_verify");
    });

    // ===================================================
    // KEY FIX: sec_protocol_options_set_verify_block
    // "expected an integer" = bool type wrong on ARM64
    // Fix: try all possible complete() call signatures
    // ===================================================
    safeHook("sec_protocol_options_set_verify_block", function () {
        var addr = findExport("sec_protocol_options_set_verify_block");
        if (!addr) return;

        var alwaysTrueCb = new NativeCallback(function (metadata, trust, completeBlock) {
            console.log("[+] sec_protocol verify block called");
            try {
                var invokePtr = completeBlock.add(16).readPointer();
                console.log("[DBG] completeBlock invokePtr = " + invokePtr);

                if (invokePtr.isNull()) {
                    console.log("[-] invokePtr is null");
                    return;
                }

                // Try 1: (pointer, int) — ARM64 bool = int
                try {
                    var fn1 = new NativeFunction(invokePtr, 'void', ['pointer', 'int']);
                    fn1(completeBlock, 1);
                    console.log("[+] complete(true) via int -> success");
                    return;
                } catch(e) { console.log("[DBG] int attempt: " + e.message); }

                // Try 2: (pointer, uint32)
                try {
                    var fn2 = new NativeFunction(invokePtr, 'void', ['pointer', 'uint32']);
                    fn2(completeBlock, 1);
                    console.log("[+] complete(true) via uint32 -> success");
                    return;
                } catch(e) { console.log("[DBG] uint32 attempt: " + e.message); }

                // Try 3: (pointer, uint8)
                try {
                    var fn3 = new NativeFunction(invokePtr, 'void', ['pointer', 'uint8']);
                    fn3(completeBlock, 1);
                    console.log("[+] complete(true) via uint8 -> success");
                    return;
                } catch(e) { console.log("[DBG] uint8 attempt: " + e.message); }

                // Try 4: (pointer) only — maybe the bool is implicit
                try {
                    var fn4 = new NativeFunction(invokePtr, 'void', ['pointer']);
                    fn4(completeBlock);
                    console.log("[+] complete() via pointer-only -> success");
                    return;
                } catch(e) { console.log("[DBG] pointer-only attempt: " + e.message); }

                // Try 5: use ARM64 registers directly via inline hook on invokePtr
                // Write 1 (true) directly to w1 register before calling
                try {
                    var fn5 = new NativeFunction(invokePtr, 'void', ['pointer', 'pointer']);
                    fn5(completeBlock, ptr(1));
                    console.log("[+] complete(true) via pointer+ptr(1) -> success");
                    return;
                } catch(e) { console.log("[DBG] ptr(1) attempt: " + e.message); }

            } catch(e) {
                console.log("[-] verify block outer error: " + e.message);
            }
        }, 'void', ['pointer', 'pointer', 'pointer']);

        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var blockPtr = args[1];
                    if (!blockPtr || blockPtr.isNull()) return;
                    blockPtr.add(16).writePointer(alwaysTrueCb);
                    console.log("[+] sec_protocol verify block patched");
                } catch(e) {
                    console.log("[-] patch error: " + e.message);
                }
            }
        });
        console.log("[+] sec_protocol_options_set_verify_block hooked");
    });

    // ===================================================
    // Alamofire.SessionDelegate — confirmed working
    // ===================================================
    safeHook("Alamofire.SessionDelegate", function () {
        if (!ObjC.available) return;
        var sels = [
            "- URLSession:didReceiveChallenge:completionHandler:",
            "- URLSession:task:didReceiveChallenge:completionHandler:"
        ];
        sels.forEach(function (sel) {
            var cls = ObjC.classes["Alamofire.SessionDelegate"];
            if (!cls || !cls[sel]) return;
            var isTask = sel.indexOf("task:") !== -1;
            Interceptor.attach(cls[sel].implementation, {
                onEnter: function (args) {
                    try {
                        var challengeArg = isTask ? args[4] : args[3];
                        var handlerArg   = isTask ? args[5] : args[4];
                        var invokePtr    = handlerArg.add(16).readPointer();
                        if (invokePtr.isNull()) return;
                        var challenge = new ObjC.Object(challengeArg);
                        var trust     = challenge.protectionSpace().serverTrust();
                        var cred      = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                        var fn        = new NativeFunction(invokePtr, 'void', ['pointer', 'long', 'pointer']);
                        fn(handlerArg, 0, cred.handle);
                        console.log("[+] Alamofire challenge bypassed");
                    } catch (e) {
                        console.log("[-] Alamofire challenge: " + e.message);
                    }
                }
            });
            console.log("[+] Alamofire.SessionDelegate " + sel);
        });
    });

    // ===================================================
    // AKCertificatePinning + AACertificatePinner
    // ===================================================
    ["AKCertificatePinning", "AACertificatePinner", "AAFCertificateTrustValidator"].forEach(function (clsName) {
        safeHook(clsName, function () {
            if (!ObjC.available) return;
            var cls = ObjC.classes[clsName];
            if (!cls) return;
            cls.$ownMethods.forEach(function (m) {
                try {
                    Interceptor.attach(cls[m].implementation, {
                        onLeave: function (retval) {
                            try { retval.replace(ptr(1)); } catch(e) {}
                        }
                    });
                } catch(e) {}
            });
            console.log("[+] " + clsName);
        });
    });

    console.log("[*] All hooks active.\n");

}, 0);