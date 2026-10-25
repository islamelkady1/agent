---
name: crypto-attacks
description: Cryptographic weakness playbook — weak TLS configs, JWT alg confusion, padding oracles, nonce reuse, weak randomness, homemade crypto, and certificate validation bugs. Use when reviewing crypto in web apps, APIs, firmware, or custom encryption in authorized assessments.
allowed-tools:
  - shell
  - http
  - file_write
  - grep
  - coverage
  - confirm_finding
  - ask_user
---

# Cryptographic attacks playbook

Focus on **misimplementation** and **misconfiguration** — not breaking AES-256 by brute force.

## 1. TLS / transport
```sh
# TestTLS or openssl (user environment)
openssl s_client -connect target:443 -tls1 </dev/null 2>&1 | head -30
curl -vkI https://target/ 2>&1 | grep -iE 'ssl|tls|cipher'
```

Flag: TLS 1.0/1.1, NULL/export ciphers, cert expiry, hostname mismatch, self-signed on prod.

## 2. JWT / JOSE
Coordinate with `jwt` skill; crypto-specific checks:
- `alg: none` or `HS256` with public key as secret (confusion)
- Weak HMAC secret (`secret`, `< 128 bit`)
- Missing `exp` / `aud` validation
- JWK embedded `d` (private) parameter in response

Never crack user passwords — test with tokens user provides or lab-generated.

## 3. Symmetric misuse
- ECB mode on structured data (block patterns visible)
- Static IV across messages
- Password-derived keys without salt/KDF (PBKDF2/bcrypt/scrypt missing)

## 4. Asymmetric pitfalls
- RSA PKCS#1 v1.5 padding oracle (legacy apps)
- Small RSA exponent/key size (<2048)
- ECDSA nonce reuse (blockchain/signing contexts in scope)

## 5. Randomness
```sh
# Sample multiple session IDs / tokens if user captured
grep -oE '[a-f0-9]{32}' captures.txt | sort | uniq -d
```

Predictable `Math.random()` session tokens in JS apps.

## 6. Custom crypto
Red flags in source/uploads:
- `XOR` with static key
- `AES/ECB/PKCS5Padding` for large JSON blobs
- Rolling your own MAC

Recommend standard libs + AEAD (AES-GCM, ChaCha20-Poly1305).

## 7. Proof & severity
Demonstrate:
- Forge token / decrypt sample / downgrade TLS in lab
- Business impact: account takeover, data disclosure

`confirm_finding` with CWE-327, CWE-326, CWE-347 as appropriate.

## 8. Ethics
Do not perform chosen-ciphertext floods on production HSMs. Rate-limit oracle tests.
