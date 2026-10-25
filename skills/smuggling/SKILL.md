---
name: smuggling
description: HTTP request smuggling and desync playbook (CL.TE, TE.CL, TE.TE, H2→H1). Use when the target sits behind reverse proxies (nginx, Apache, Cloudflare, AWS ALB) and you need to bypass front-end access controls, poison other users' requests, or reach internal routes.
allowed-tools:
  - shell
  - http
  - web_search
  - web_fetch
  - confirm_finding
  - file_write
---

# HTTP request smuggling playbook

Smuggling exploits **disagreement** between front-end and back-end servers on where one request ends and the next begins. High complexity — confirm architecture before investing time.

## 0. Prerequisites
- Authorized testing only; smuggling can affect other users — coordinate with program rules.
- Identify stack: `Server`, `Via`, `X-Cache`, CDN headers from baseline `http` GET.
- Search `web_search "PortSwigger request smuggling <CDN name>"` for known bypasses.

## 1. Detect vulnerable TE/CL handling
Send ambiguous requests with **raw TCP** via openssl or netcat (curl alone may normalize):

```sh
HOST="app.example.com"
printf 'POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' \
  | openssl s_client -connect "$HOST:443" -quiet 2>/dev/null | head -20
```

Watch for:
- Timeout vs immediate response on malformed TE
- Different status on CL.TE vs TE.CL variants
- Duplicate `Transfer-Encoding` headers (TE.TE obfuscation)

## 2. CL.TE probe pattern
Front-end uses Content-Length, back-end uses chunked:

```
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

If smuggling works, a second request in the same connection may hit `/admin` or return foreign user's response.

## 3. Impact paths (bug bounty)
| Impact | Proof |
|--------|-------|
| Access control bypass | Smuggle request to internal `/admin` path blocked at edge |
| Cache poisoning | Smuggle response that lands in shared cache |
| Request hijacking | Capture another user's request in keep-alive pool |
| H2 downgrade | HTTP/2 front → HTTP/1 back desync (research latest Kettle techniques) |

## 4. Safety and confirmation
- Use a **canary header** (`X-RaOS: <unique>`) in smuggled prefix — prove it reaches backend in logs if user has access.
- Do not run destructive smuggling against production without program approval.
- One reproducible desync with captured raw response > theoretical CL mismatch.

## 5. Report
Reference PortSwigger research. Include raw request bytes (hex or escaped), architecture diagram in prose, and concrete impact (e.g. "smuggled GET /admin returned 200 with admin HTML").

VRT: often `Server Security Misconfiguration > HTTP Request Smuggling` or access control bypass depending on impact.

Call `confirm_finding` only with end-to-end proof.
