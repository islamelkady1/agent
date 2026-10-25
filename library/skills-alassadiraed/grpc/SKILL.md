---
name: grpc
description: gRPC and Protocol Buffer security playbook — server reflection in production, missing auth on RPC methods, metadata injection, and message size DoS. Use when ports expose gRPC (often :50051), `grpc-web` in browser, or `.proto` files leak from repos.
allowed-tools:
  - shell
  - http
  - grep
  - file_read
  - web_search
  - confirm_finding
  - file_write
---

# gRPC / Protobuf playbook

gRPC endpoints are often **unauthenticated** on internal ports exposed by misconfig.

## 1. Discovery
- Port scan in scope: 50051, 443 with `content-type: application/grpc`
- JS bundles referencing `@grpc/grpc-js`, `grpc-web`
- `.proto` files in GitHub/repos: `grep -r 'service ' . --include='*.proto'`

```sh
# grpcurl reflection (if installed and in scope)
grpcurl -plaintext TARGET:50051 list
grpcurl -plaintext TARGET:50051 describe package.Service
```

If user lacks grpcurl, use `web_search` for raw HTTP/2 framing tools or ask user to run grpcurl.

## 2. Server reflection
If `grpc.reflection.v1alpha.ServerReflection` is enabled in prod:
- List all services/methods — map hidden admin RPCs
- Call sensitive methods with empty/minimal messages

## 3. Auth gaps
Test each RPC with:
- No metadata
- Wrong `:authority`
- Stolen bearer in `authorization` metadata vs HTTP API token

Compare `UserService/GetUser` with swapped user IDs — BOLA on gRPC.

## 4. Metadata injection
Custom headers: `x-user-id`, `x-internal`, `bin` metadata — backend may trust them over JWT.

## 5. grpc-web via HTTP
Some gateways expose POST with `application/grpc-web+proto`:
```sh
curl -ksS -X POST 'https://api.example.com/package.Service/Method' \
  -H 'Content-Type: application/grpc-web+proto' \
  --data-binary @request.bin
```

Decode protobuf if `.proto` available; otherwise fuzz field tags (1: string, 2: varint).

## 6. Report
Include service/method name, request metadata, and sensitive response fields.

VRT: `Broken Access Control` / `Security Misconfiguration > Exposed Internal API`

Call `confirm_finding` when unauthenticated RPC returns privileged data or performs state change.
