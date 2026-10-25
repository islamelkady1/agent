---
name: waf-bypass
description: Web Application Firewall and bot-protection bypass playbook — encoding chains, HTTP parameter pollution, chunked transfer abuse, method override, JSON/XML smuggling edges, and CDN origin discovery. Use when responses show Cloudflare/Akamai/AWS WAF blocks or bounty scope allows WAF testing on in-scope apps.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - ask_user
---

# WAF bypass playbook

Goal: prove **underlying vulnerability exists** behind WAF — not to disable WAF globally. Stay in scope; low rate.

## 1. Fingerprint WAF
Signals in body/headers:
- `cf-ray`, `__cfduid`, `AkamaiGHost`, `X-Amzn-RequestId` + `403` patterns
- `ModSecurity`, `Request rejected`, `Attention Required`

Log WAF vendor guess in coverage notes.

## 2. Origin discovery (authorized)
- Historical DNS (`securitytrails` if user has API)
- Subdomains not behind CDN: `direct`, `origin`, `api-old`, `dev`
- Certificate SAN mismatches from `osint` / crt.sh
- `Host` header to internal IP **only** if program allows and IP is in scope

## 3. Encoding & parser differentials
Try on **same** vulnerable parameter (one at a time):
| Technique | Example |
|-----------|---------|
| Double URL encode | `%252e%252e%252f` |
| Unicode normalize | `%c0%ae%c0%ae/` |
| Case / comment SQLi | `SeLeCt`, `/*!50000SELECT*/` |
| JSON Unicode escapes | `\u0061lert` |
| Overlong UTF-8 | legacy servers only |

Pair with `sqli`, `xss`, `ssti` skills — WAF bypass is a means, not the finding.

## 4. HTTP semantics
- Method tampering: `GET` with `X-HTTP-Method-Override: DELETE`
- Content-Type flip: `application/json` vs `application/x-www-form-urlencoded`
- Path normalization: `/api/../admin`, `//admin`, `/./admin`
- `smuggling` skill for front/back desync

## 5. Parameter pollution
```
?id=1&id=2' OR '1'='1
```
Compare which value backend vs WAF inspects.

## 6. Rate & ethics
- Throttle; WAF bypass spray can lock out legit users — `ask_user` if 429/503 spikes
- Document **minimal** payload that proves vuln through WAF
- Finding title: "SQLi in /api/user (WAF bypass via double encoding)" not "WAF broken"

## 7. Remediation
Recommend fixing root cause + virtual patch rules, not reliance on obscurity.
