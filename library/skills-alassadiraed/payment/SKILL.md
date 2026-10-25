---
name: payment
description: Payment and checkout abuse playbook — price manipulation, currency bypass, coupon/limit races, negative amounts, IDOR on invoices, and webhook replay. Use when testing e-commerce, subscriptions, wallets, credits, or Stripe/PayPal integrations.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - ask_user
  - file_write
---

# Payment / checkout playbook

Payment bugs are **high severity** — test on staging when available; minimize real charges on production.

## 1. Map payment flow
Trace:
- Add to cart → checkout → payment intent → confirm
- Subscription upgrade/downgrade
- Wallet top-up / withdraw
- Refund / partial capture APIs

Capture normal flow in Burp — note which fields are server-authoritative.

## 2. Price tampering
Intercept JSON:
```json
{"product_id":"123","quantity":1,"unit_price":9999}
```
Change to `0.01`, `0`, negative values, wrong `currency`.

```sh
curl -ksS -X POST "$TARGET/api/checkout" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"sku":"PRO","price":0.01}],"currency":"USD"}'
```

Success = order created below catalog price.

## 3. Coupon / gift card
- Reuse single-use codes (replay, race — see `race` skill)
- Stack incompatible promotions
- Apply expired codes by manipulating client date (if server trusts client)

## 4. IDOR on orders/invoices
```sh
curl -ksS -H "Authorization: Bearer $TOKEN_B" "$TARGET/api/invoices/INVOICE_ID_A"
curl -ksS -X POST -H "Authorization: Bearer $TOKEN_B" \
  "$TARGET/api/orders/ORDER_A/refund"
```

## 5. Webhook abuse
If `/webhooks/stripe` lacks signature verification:
- Forge `payment_intent.succeeded` event
- Mark order paid without charge

Check for idempotency — replay same event ID.

## 6. Currency / tax bypass
Switch `currency` to lower-cost region, or set `tax=0`, `vat_exempt=true` in hidden fields.

## 7. Report
Quantify: "Attacker purchases $999 item for $0.01" with order ID and response.

VRT: `Improper Input Validation > Price Manipulation` / `Payment Bypass`

Never include full PAN or live payment tokens. Call `confirm_finding` with order proof and business impact.
