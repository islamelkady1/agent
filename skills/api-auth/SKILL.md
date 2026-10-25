---
name: api-auth
description: API authorization testing playbook (BOLA/IDOR, BFLA, mass assignment, excessive data exposure). Use for REST/JSON APIs, mobile backends, GraphQL-adjacent REST, and microservice endpoints.
allowed-tools:
  - shell
  - http
  - scope_check
  - coverage
  - confirm_finding
---

# API authorization playbook

Screen every `/api/.../{id}` route with two accounts. APIs fail open more often than web UIs.

## 1. Dual-account setup
Get two sessions: USER_A and USER_B. Note object IDs owned by each.

## 2. BOLA / IDOR sweep
For each `{id}` route:
```
# As USER_B, request USER_A's object ID
curl -ksS -H "Authorization: Bearer $TOKEN_B" "$TARGET/api/orders/USER_A_ORDER_ID"
```
Swap IDs in path, query, and nested resources (`/orders/{id}/items/{itemId}`).

## 3. BFLA (function level)
As low-priv user, call admin-only methods:
- Change GET → PUT/DELETE/PATCH
- Hit `/admin/`, `/internal/`, `/v1/manage/` discovered in JS bundle

## 4. Mass assignment
POST/PATCH extra JSON fields the UI never sends:
```json
{"email":"a@b.com","role":"admin","isVerified":true,"balance":9999}
```

## 5. Excessive data exposure
Inspect JSON responses for hidden fields (tokens, PII, internal flags, other tenants).

## 6. Mark coverage + report
Use `coverage` after each tuple. Confirm with VRT paths like `Broken Access Control > Insecure Direct Object References (IDOR)` or API-specific categories. CWE-639/285.
