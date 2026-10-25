---
name: mobile
description: Mobile app security playbook for Android APK/IPA analysis, API backend testing, cert pinning bypass guidance, hardcoded secrets, deep links, and mobile-specific auth flaws. Use when the bug bounty scope includes mobile apps, React Native/Flutter bundles, or mobsf-style static analysis on binaries the user provides.
allowed-tools:
  - shell
  - http
  - file_read
  - grep
  - glob
  - web_search
  - confirm_finding
  - file_write
---

# Mobile security playbook

Mobile bugs often live in the **API layer** the app calls, not only in the binary. Test both: static review of the APK/IPA the user provides, and dynamic replay of captured traffic against `/target`.

Execution rule: use real package names, bundle IDs, and endpoints from the scoped app. Never write literal `<PACKAGE>` placeholders to disk.

## 1. Scope and assets
Confirm:
- Package name / bundle ID in scope
- Backend API hosts (often differ from web `*.com`)
- Out-of-scope: third-party SDKs, app store listing only, physical device theft scenarios

Ask the user for the APK/IPA or a decompiled tree if not already present.

## 2. Static analysis (APK/IPA on disk)
If the user supplied a binary or extracted folder:

```sh
# Android — list attack surface quickly
APK="app-release.apk"
unzip -l "$APK" | grep -E 'AndroidManifest|classes.dex|\.so|assets/|res/raw'
strings "$APK" | grep -Ei 'api[_-]?key|secret|password|Bearer|aws_|AKIA|firebase|supabase' | head -50
```

Check for:
- **Hardcoded API keys** (Firebase, Google Maps, Stripe, AWS, Supabase anon keys)
- **Exported components** in AndroidManifest (`android:exported="true"` on activities/services/receivers)
- **Deep link / intent filters** (`scheme`, `host`, `pathPrefix`) — hijack via malicious app
- **Network security config** allowing cleartext HTTP
- **Backup enabled** (`android:allowBackup="true"`) exposing local DB via adb backup

For IPA: inspect `Info.plist` URL schemes, ATS exceptions, embedded API endpoints in JS bundles (React Native/Hybrid).

## 3. API replay (highest ROI for bug bounty)
Capture traffic from Burp/`browser_capture_*` or user-provided HAR. Map:
- Login / refresh token endpoints
- Object IDs in JSON bodies
- Missing certificate pinning on staging builds

Replay with curl using mobile User-Agent and app-specific headers:

```sh
TARGET="https://api.example.com"
curl -ksS -X POST "$TARGET/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: MyApp/3.2.1 Android' \
  -d '{"email":"user@example.com","password":"..."}'
```

Test **BOLA/IDOR** on every `{id}` route — mobile APIs often skip auth checks present on web.

## 4. Mobile-specific bug classes
| Class | What to test |
|-------|----------------|
| IDOR on mobile-only routes | `/v1/mobile/user/{id}/wallet` |
| Weak refresh tokens | Long-lived, no binding to device_id |
| OTP bypass | Rate limit, predictable codes, response tampering |
| Biometric bypass | Client-side flag `biometricVerified:true` in JSON |
| Deep link hijack | `myapp://reset-password?token=...` open in browser |
| WebView XSS | `loadUrl` with attacker-controlled URL in hybrid screens |
| Insecure local storage | Tokens in SharedPreferences/UserDefaults without encryption |

## 5. Certificate pinning
If traffic is pinned, note it for the report but pivot to:
- Staging builds without pinning
- API endpoints discovered in strings/decompiled code
- Web fallback URLs in the same app

Do not ask the user to bypass pinning on production without explicit authorization.

## 6. Report
Map to VRT (e.g. `Sensitive Data Exposure > Hardcoded Credentials`, `Broken Authentication`). Include:
- Exact file/line or string evidence from static analysis
- Or curl replay proving API impact
- Affected app version and platform (Android/iOS)

Call `confirm_finding` only after reproducible proof.
