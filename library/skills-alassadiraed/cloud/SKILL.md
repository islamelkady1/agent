---
name: cloud
description: Cloud and infrastructure misconfiguration playbook — AWS S3/GCS/Azure public buckets, IMDS/metadata SSRF, IAM policy gaps, exposed Lambda URLs, Cognito misconfig, and subdomain/CDN origin leaks. Use when scope includes cloud assets, `*.s3.amazonaws.com`, Azure blob URLs, or SSRF-to-metadata chains.
allowed-tools:
  - shell
  - http
  - web_search
  - web_fetch
  - scope_check
  - confirm_finding
  - file_write
---

# Cloud misconfiguration playbook

Cloud bugs combine **asset discovery** + **permission testing**. Stay in program scope — do not scan arbitrary AWS accounts.

## 1. Discover cloud assets
From target recon, JS bundles, and DNS:
- `*.s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`
- CloudFront/Cloudflare URLs in `src=` attributes
- `amzn-`, `azure`, `googleapis` in CNAME chains

```sh
# Predictable bucket names (manual, low noise)
ORG="acme"
for name in "$ORG-prod" "$ORG-backup" "$ORG-dev" "$ORG-uploads" "$ORG-static" "$ORG-logs"; do
  code=$(curl -ksS -o /dev/null -w '%{http_code}' "https://${name}.s3.amazonaws.com/")
  echo "$name $code"
done
```

ListBucketResult or `AccessDenied` vs `NoSuchBucket` tells you if bucket exists.

## 2. Public bucket / blob testing
```sh
curl -ksS 'https://BUCKET.s3.amazonaws.com/?list-type=2' | head -50
curl -ksS 'https://BUCKET.s3.amazonaws.com/sensitive-backup.zip' -w '\nHTTP %{http_code}\n'
```

For GCS: `https://storage.googleapis.com/BUCKET/`  
For Azure: `https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list`

Confirm **unauthenticated read** of non-public data — not just existence of bucket.

## 3. SSRF → cloud metadata
When any SSRF exists, chain to:
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- IMDSv2 requires PUT token — test if app blocks it
- GCP: `http://metadata.google.internal/computeMetadata/v1/` + `Metadata-Flavor: Google`
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

Prove role/credential exposure with redacted excerpt — never paste live keys into findings verbatim; use placeholders in reports.

## 4. Cognito / Firebase / Supabase
- Cognito user pool self-signup with excessive IAM via identity pool
- Firebase rules `".read": true`
- Supabase anon key + missing RLS (see `supabase` skill)

## 5. Exposed admin panels
Probe (single host, in scope only):
- `/actuator/env`, `/actuator/heapdump` (Spring)
- `/debug/pprof`, `/metrics`
- Kubernetes dashboard, Grafana, Kibana without auth

## 6. Report
Quantify impact: records exposed, write access, role assumed. VRT examples:
- `Sensitive Data Exposure > Cloud Storage`
- `Server Security Misconfiguration > Misconfigured AWS S3 Bucket`
- `SSRF > Internal High Impact`

Call `confirm_finding` with list/download PoC and scope-checked URLs.
