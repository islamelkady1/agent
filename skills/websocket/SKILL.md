---
name: websocket
description: WebSocket and Server-Sent Events security playbook — missing Origin checks (CSWSH), auth after handshake only, message-level IDOR, subscription hijacking, and sensitive data over unencrypted WS. Use when the app uses realtime chat, live feeds, trading tickers, or collaborative editing.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - file_write
---

# WebSocket / SSE playbook

WebSockets often **skip** the same auth middleware as HTTP routes. Test handshake, Origin, and per-message authorization separately.

## 1. Discover endpoints
From JS bundles and Burp:
- `wss://host/ws`, `/socket.io/`, `/graphql` subscriptions
- SSE: `text/event-stream` on `/events`, `/stream`

```sh
# Handshake probe (may need session cookie)
curl -ksS -i -N \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: https://evil.com' \
  -H 'Cookie: session=...' \
  'https://app.example.com/ws'
```

## 2. Cross-Site WebSocket Hijacking (CSWSH)
If server validates session cookie but **not Origin**:
- Victim visits attacker page; browser sends cookies on WS handshake
- Attacker reads sensitive messages over hijacked socket

PoC: host `wss` connection from evil origin with victim's cookie (user tests in lab). Confirm program allows CSWSH demo.

## 3. Auth after connect
Some apps authenticate only via first message `{type:"auth", token:"..."}`:
- Skip auth message — do you still receive data?
- Reuse expired token
- Subscribe to channels without joining room: `{"action":"subscribe","channel":"admin"}`

## 4. Message-level IDOR
Replay JSON templates swapping IDs:
```json
{"type":"get_message","room_id":"victim-room-uuid"}
{"type":"edit_doc","doc_id":"other-user-doc"}
```

Compare responses between USER_A and USER_B sessions.

## 5. SSE-specific
- Can you read `/events?userId=OTHER` without auth?
- Last-Event-ID manipulation leaking older events

## 6. Report
VRT: `Cross-Site WebSocket Hijacking`, `Broken Access Control` on subscription channels.

Include handshake headers, message JSON, and data leaked. Call `confirm_finding` with reproducible steps.
