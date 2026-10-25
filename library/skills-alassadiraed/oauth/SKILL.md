---
name: oauth
description: OAuth/OIDC/SAML authentication flaw playbook. Use when testing login flows, SSO, redirect_uri handling, state/nonce, token exchange, or account linking features.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - web_fetch
---

# OAuth / OIDC playbook

Focus on redirect validation, token leakage, and account takeover chains.

## 1. Map the flow
Identify authorization URL, token endpoint, redirect_uri whitelist, response_type, scopes, PKCE usage.

## 2. redirect_uri bypass
Test parser differentials:
- Path: `https://evil.com/callback/../@target.com`
- Subdomain: `https://target.com.evil.com`
- Fragment: `https://target.com/callback#@evil.com`
- Open redirect chaining: `redirect_uri=https://target.com/open?url=https://evil.com`

## 3. state / nonce
- Missing state → CSRF on OAuth login
- Predictable state
- state not bound to session

## 4. Token issues
- Access token in URL fragment leaking via Referer
- Missing audience (`aud`) validation
- Refresh token reuse / rotation flaws
- `response_type=token` implicit flow token theft

## 5. Account linking
Link attacker IdP to victim account, or swap email/identifier in callback.

## 6. Report
VRT: `Authentication & Authorization > OAuth Misconfiguration`. Include full auth URL, callback capture, and impact (ATO). CWE-287/306 as appropriate.
