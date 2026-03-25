# Bypassing iOS Application (17.x) SSL Pinning via Frida

> Bypass SSL certificate pinning on iOS 17.x via Frida - covers Security.framework, BoringSSL, Network.framework, Alamofire, and Apple private pinning classes.

---

## 🔍 The Problem

Modern iOS apps layer multiple pinning mechanisms on top of each other. Bypassing a single layer is not enough.

| Pinning Layer | Framework | Standard Bypass Tools Work? |
|---|---|---|
| `SecTrustEvaluate` / `SecTrustEvaluateWithError` | Security.framework | ✅ Yes (if targeted) |
| `SSL_CTX_set_custom_verify` | BoringSSL (bundled) | ⚠️ Often missed |
| `sec_protocol_options_set_verify_block` | Network.framework | ❌ Rarely handled |
| Alamofire `SessionDelegate` challenge | Third-party lib | ❌ Not covered by generic tools |
| `AKCertificatePinning` / `AACertificatePinner` | Apple private | ❌ Undocumented, often missed |

This script hooks **all layers simultaneously** so traffic flows through your proxy regardless of which mechanism the app relies on.

---

## ⚙️ How It Works

The bypass operates at multiple levels inside the iOS TLS stack:

### 1. Security.framework - `SecTrust` Family

`SecTrustEvaluate`, `SecTrustEvaluateWithError`, and `SecTrustGetTrustResult` are **fully replaced** with `NativeCallback` functions that write a trusted result directly into the output pointer and return success codes, making the OS believe the certificate chain is valid.

### 2. BoringSSL - `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify`

Apps that bundle their own BoringSSL register a custom certificate verification callback. The script **swaps that callback** at hook time with a no-op that always returns `SSL_VERIFY_OK (0)`.

### 3. Network.framework - `sec_protocol_options_set_verify_block`

This is the trickiest hook. On **ARM64**, calling a block's `complete()` function with a `bool` argument throws a Frida *"expected an integer"* error. The script resolves this by trying five type signatures in sequence until one succeeds at runtime:

```
complete(block, int)       → Try 1
complete(block, uint32)    → Try 2
complete(block, uint8)     → Try 3
complete(block)            → Try 4
complete(block, ptr(1))    → Try 5
```

### 4. Alamofire `SessionDelegate`

Both session-level and task-level `URLAuthenticationChallenge` delegate methods are hooked. The handler block is invoked directly with `.useCredential` disposition and a credential built from the server trust, bypassing the app's own challenge logic entirely.

### 5. Apple Private Pinning Classes

`AKCertificatePinning`, `AACertificatePinner`, and `AAFCertificateTrustValidator` are Apple-internal classes used in first-party and system-adjacent apps. All instance methods are hooked to return `ptr(1)` (truthy).

---

## 🏗️ Architecture

```
App makes HTTPS request
         ↓
iOS TLS stack evaluates server certificate
         ↓
[HOOK] SecTrustEvaluate / SecTrustEvaluateWithError
  → Result pointer overwritten → kSecTrustResultProceed (1)
  → Returns errSecSuccess (0)
         ↓
[HOOK] SSL_CTX_set_custom_verify (BoringSSL)
  → Callback replaced with no-op → returns SSL_VERIFY_OK
         ↓
[HOOK] sec_protocol_options_set_verify_block (Network.framework)
  → Verify block patched → complete(true) called via ARM64-safe fallback
         ↓
[HOOK] Alamofire SessionDelegate challenge handler
  → .useCredential dispatched with server trust credential
         ↓
[HOOK] AKCertificatePinning / AACertificatePinner
  → All methods forced to return truthy
         ↓
✅ TLS handshake completes - full decrypted traffic visible in proxy
```

---

## 📋 Prerequisites

- Jailbroken iOS device (tested on **iOS 17.4.1**)
- [Frida](https://frida.re) **17.8.3** installed on your machine
- `frida-server` (matching version) running on the iOS device
- Burp Suite, mitmproxy, or any MITM proxy

---

## 🚀 Setup

### 1. Start frida-server on the iOS device

```bash
# On the iOS device via SSH
frida-server -l 0.0.0.0 &
```

### 2. Configure your proxy

```
Burp Suite → Proxy → Options → Edit Listener:
  ✅ Bind to port: 8080
  ✅ Bind to address: All interfaces
  ✅ Support invisible proxying: ENABLED
```

Install the Burp CA certificate as a trusted root on the device (Settings → General → About → Certificate Trust Settings).

### 3. Run the script

```
1. Attach mode (-n)
frida -l ios-ssl-pinning-bypass.js -n <AppName> -H <device-ip> --timeout=60

// -n : attach to already running app using app/process name (app must be opened manually before running Frida)

                            or

2. Spawn mode (-f)
frida -l ios-ssl-pinning-bypass.js -f <bundle-id> -H <device-ip>

// -f : spawn (launch) the app via Frida using bundle identifier (package name of iOS application)
```

Replace `<AppName>` with the target app's display name (process name used with -n) and `<device-ip>` with your device's IP address.

If using spawn mode (`-f`), replace `<bundle-id>` with the app's bundle identifier (package name on iOS).


---

## ✅ Expected Output

```
[*] SSL Bypass Starting...
[+] SecTrustEvaluate
[+] SecTrustEvaluateWithError
[+] SecTrustGetTrustResult
[+] SecTrustSetExceptions
[+] SSL_CTX_set_custom_verify
[+] SSL_set_custom_verify
[+] sec_protocol_options_set_verify_block hooked
[+] Alamofire.SessionDelegate - URLSession:task:didReceiveChallenge:completionHandler:
[+] AKCertificatePinning
[+] AACertificatePinner
[+] AAFCertificateTrustValidator
[*] All hooks active.
```

Hooks not present in the target app are silently skipped. `[-]` lines are non-fatal debug output.

---

## 📄 Script Overview

```
ios-ssl-pinning-bypass.js
├── findExport()                          - Scans all loaded modules for a symbol
├── safeHook()                            - Wraps hooks in try/catch; failures are logged, not fatal
│
├── SecTrustEvaluate                      - Replace → writes trust result 1, returns 0
├── SecTrustEvaluateWithError             - Replace → returns true, clears error pointer
├── SecTrustGetTrustResult                - Replace → writes kSecTrustResultProceed
├── SecTrustSetExceptions                 - Attach onLeave → retval forced to ptr(1)
│
├── SSL_CTX_set_custom_verify             - Attach onEnter → args[2] swapped with no-op cb
├── SSL_set_custom_verify                 - Attach onEnter → args[2] swapped with no-op cb
│
├── sec_protocol_options_set_verify_block - Attach onEnter → verify block patched in-place
│   └── ARM64 bool fix                    - Tries 5 type signatures for complete() call
│
├── Alamofire.SessionDelegate             - Attach to both challenge selectors
│   └── Invokes handler block directly with .useCredential (0) + server trust credential
│
└── AKCertificatePinning                  - All $ownMethods → onLeave retval.replace(ptr(1))
    AACertificatePinner
    AAFCertificateTrustValidator
```

---

## ❓ Why Not Standard Approaches?

| Approach | Why It May Fall Short |
|---|---|
| SSL Kill Switch 2 | Targets `SecTrustEvaluate` only; misses BoringSSL and Network.framework layers |
| Objection SSL bypass | Good coverage but may not handle `sec_protocol_options_set_verify_block` on iOS 17 |
| Proxyman / Charles magic cert | Requires system trust; fails if app uses cert/public key pinning independently |
| Manual `SecTrustEvaluate` hook only | App may fall through to Alamofire or BoringSSL path |
| Generic community bypass scripts | Often outdated for iOS 17.x ARM64 `bool` type handling |

---

## 🛠️ Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `[-] sec_protocol verify block called` but no success line | Unusual block memory layout | Check `[DBG] invokePtr` address; ensure it is non-null |
| Alamofire hooks not firing | App uses URLSession directly, not Alamofire | Check if raw `URLSessionDelegate` hook is needed |
| `frida: unable to connect` | `frida-server` not running or wrong IP | Restart `frida-server`; verify `-H` IP and port 27042 |
| Hooks active but traffic still blocked | App uses `WKWebView` or `NEURLSession` | Additional hooks needed for those subsystems |
| `expected an integer` error | ARM64 bool type mismatch | Already handled by the 5-signature fallback in this script |

---

## 🧪 Tested Environment

| Component | Value |
|---|---|
| iOS version | 17.4.1 |
| Architecture | ARM64 |
| Frida version | 17.8.3 |
| Script version | ios-ssl-pinning-bypass.js |
| Jailbreak required | Yes |

---
