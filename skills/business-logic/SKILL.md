---
name: business-logic
description: Business logic and workflow abuse playbook — coupon stacking, race on balances, negative quantities, state machine bypass, referral fraud, and trust-boundary violations. Use when testing checkout, subscriptions, credits, votes, invitations, or multi-step flows where rules matter more than injection.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - ask_user
  - file_write
---

# Business logic playbook

Logic bugs need **domain understanding**. Read terms of service / program rules — some flows (coupon brute force) may be out of scope.

## 1. Model the workflow
Draw states for the feature under test:
```
cart → apply_coupon → payment → confirm
invite → accept → reward
withdraw → pending → completed
```

Identify:
- Which step validates balance, role, or limit?
- Client-side only checks?
- Idempotency keys / race windows?

## 2. Invariant testing
For each invariant, try to violate it:

| Invariant | Attack |
|-----------|--------|
| One coupon per order | Apply same code twice, parallel requests |
| Non-negative price | `-1` quantity, `-100` discount |
| Single vote | Replay vote POST, parallel race |
| Withdraw ≤ balance | Concurrent withdraws |
| Free tier limits | Reset counter via API parameter |

```sh
# Parallel coupon apply (race) — lab only
for i in $(seq 1 10); do
  curl -ksS -X POST "$TARGET/api/coupon/apply" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"code":"SAVE50"}' &
done
wait
```

Load `race` skill for single-packet techniques on high-value endpoints.

## 3. Parameter tampering
Hidden fields from JS/mobile API:
- `price`, `plan_id`, `role`, `verified`, `country` (geo pricing)
- Skip steps: call `/checkout/complete` without `/payment`

## 4. Time and sequence
- Use expired trial after downgrade
- Cancel subscription after consuming premium feature
- Replay webhooks (`/stripe/webhook`) without signature (if exposed)

## 5. Trust boundaries
- Internal `isAdmin` flag in JSON body
- `X-Internal: true` header honored by backend
- Debug endpoints enabling features in prod

Ask user for second account when testing cross-user logic.

## 6. Report
Explain **business impact in dollars or fraud terms**, not just HTTP 200.

VRT: `Sensitive Data Exposure` / `Improper Input Validation` / program-specific "Business Logic" categories.

Include exact sequence, before/after balances, and curl timeline. Call `confirm_finding` when financial or access impact is proven.
