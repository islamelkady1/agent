---
name: secrets
description: Secret and credential hunting playbook — exposed API keys in JS bundles, .git/.env leaks, GitHub dorking, CI artifacts, source maps, and backup files. Use during recon or when the program rewards credential exposure with clear impact proof.
allowed-tools:
  - shell
  - http
  - grep
  - glob
  - web_search
  - web_fetch
  - file_read
  - scope_check
  - confirm_finding
  - file_write
---

# Secrets hunting playbook

Finding a key string is **not** a report — prove the key **works** and what it accesses (within scope).

## 1. On-target asset mining
```sh
TARGET="https://app.example.com"
# JS bundles
curl -ksS "$TARGET" | grep -oE 'src="[^"]+\.js"' | head -20
# Fetch each bundle and scan
curl -ksS "$TARGET/static/main.js" | grep -oE '(sk_live|AKIA|AIza|ghp_|xox[baprs]-)[A-Za-z0-9_-]+' | head
```

Check:
- `/static/js/*.map` source maps for embedded secrets
- `/.env`, `/.git/HEAD`, `/config.json`, `/backup.zip`, `/docker-compose.yml`
- `/swagger.json`, `/openapi.json` for internal hosts

```sh
for path in .env .git/HEAD config.json api/config backup.sql swagger.json; do
  code=$(curl -ksS -o /dev/null -w '%{http_code}' "$TARGET/$path")
  echo "$path $code"
done
```

## 2. Pattern library
| Pattern | Service |
|---------|---------|
| `AKIA` / `ASIA` | AWS access key |
| `sk_live_` / `rk_live_` | Stripe |
| `AIza` | Google API |
| `ghp_`, `gho_` | GitHub |
| `xoxb-` | Slack bot |
| `eyJ` + long JWT | May be live session |

Redact in reports; validate with **least-privilege** test call.

## 3. Validate impact (required)
```sh
# Example: AWS key — sts GetCallerIdentity only
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  aws sts get-caller-identity 2>&1 | head -5
```

Document what principal the key assumes — do not exfiltrate customer data.

## 4. GitHub / public repos (program permitting)
`web_search` org name + `github dork password filename:env` — only report repos clearly belonging to target org.

## 5. Out of scope
- Keys in **other customers'** public forks unrelated to target
- Keys with no proven access
- Historical leaked keys already rotated (note as informational only)

## 6. Report
VRT: `Sensitive Data Exposure > Hardcoded Credentials` / `Cloud Credentials`

Include: location (URL/file), key prefix (redacted), validation command output proving role/access.

Call `confirm_finding` when live key access is demonstrated.
