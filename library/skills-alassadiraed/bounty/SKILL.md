---
name: bounty
description: End-to-end bug bounty hunting workflow. Use when starting a new program, planning test coverage, triaging findings for submission, or when the user mentions HackerOne, Bugcrowd, Intigriti, or bug bounty scope/rules.
allowed-tools:
  - shell
  - http
  - scope_check
  - coverage
  - confirm_finding
  - web_search
  - web_fetch
  - file_write
---

# Bug bounty hunting playbook

You are hunting inside an authorized bug bounty program. Stay inside scope, produce platform-ready reports, and track what you have already tested.

## 0. Program setup
If no program is configured, ask the user for:
- Program name and platform (HackerOne, Bugcrowd, Intigriti, etc.)
- In-scope assets (`*.target.com`, specific apps)
- Out-of-scope assets (staging, third-party, mobile stores if excluded)
- Special rules (no DoS, no social engineering, rate limits)

Guide them to configure with:
```
/program name Acme Corp
/program platform hackerone
/program url https://hackerone.com/acme
/program in *.acme.com api.acme.com
/program out staging.acme.com
/program enforce on
```

Set `/target` to the primary web/API base URL.

## 1. Recon → inventory
- Map subdomains, APIs, auth flows, roles, and upload points.
- Load `recon` skill if surface mapping is incomplete.
- Record endpoints with the `coverage` tool as you discover them.

## 2. Scope discipline
Before probing any new host:
```
scope_check url="https://new-host.example.com/path"
```
If out of scope, stop and ask the user. Never test excluded assets.

## 3. Test matrix (high ROI order)
Work endpoint × parameter × vulnerability class. Mark each attempt with `coverage`.

| Priority | Class | Skill |
|----------|-------|-------|
| 0 | Recon / secrets | recon, secrets |
| 1 | IDOR / BOLA / BAC | webvuln, api-auth |
| 2 | Auth / OAuth / SAML / JWT | oauth, jwt, saml |
| 3 | SSRF / cloud metadata | ssrf, cloud |
| 4 | Injection (SQLi, SSTI, XSS) | sqli, ssti, xss |
| 5 | CSRF / CORS / WS | csrf, websocket |
| 6 | Upload / cache / smuggling | file-upload, cache-poison, smuggling |
| 7 | GraphQL / gRPC / race | graphql, grpc, race |
| 8 | Logic / payments | business-logic, payment |
| 9 | Mobile / takeover / cloud SaaS | mobile, takeover, supabase |
| 10 | AI / MCP features | llm |
| 11 | Deserialize / prototype pollution | deserialize, proto-pollution |
| 12 | WAF / supply chain / crypto | waf-bypass, supply-chain, crypto-attacks |

**Red team / internal (RoE required — often out of bounty scope):**

| Tier | Class | Skill |
|------|-------|-------|
| R1 | OSINT / planning | osint, redteam |
| R2 | AD / lateral / post-exploit | active-directory, lateral, post-exploit |
| R3 | Phishing / C2 narrative | phishing |
| R4 | Research / hardware | zeroday, exploit-dev, firmware |

Use `/next` when unsure what to test next.

## 4. Confirm findings (platform-ready)
Only after manual reproduction with request + response evidence:

```
confirm_finding(
  title="...",
  severity="high",
  url="https://...",
  vrt_category="Broken Access Control > Insecure Direct Object References (IDOR)",
  cwe="CWE-639",
  steps_to_reproduce=["Login as user A", "Request /api/orders/123", "Observe user B data"],
  impact="An attacker can read any order by changing the ID.",
  curl="curl -ksS ...",
  response_excerpt="..."
)
```

Map severity to Bugcrowd VRT: P1→critical, P2→high, P3→medium, P4→low, P5→info.

## 5. Export submissions
When the user is ready to submit:
- `/findings` — review confirmed bugs
- `/export` — engagement summary
- `/export hackerone` or `/export bugcrowd` — platform submission bundle under `./findings/submissions-<platform>/`

## 6. Rules of engagement
- No theoretical bugs. No scanner-only hits without manual proof.
- No destructive testing (DoS, mass deletion) unless explicitly allowed.
- Prefer curl/http over noisy scanners.
- Two-account testing for access control whenever possible.
