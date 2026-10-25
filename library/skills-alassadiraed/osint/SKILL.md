---
name: osint
description: Advanced open-source intelligence playbook — persona mapping, infrastructure correlation, breach corpus review, social graph hints, document metadata, and passive asset discovery. Use when hunting attack surface before engagement, verifying program scope, or investigating leaked credentials for authorized programs.
allowed-tools:
  - shell
  - http
  - web_search
  - web_fetch
  - file_write
  - grep
  - glob
---

# OSINT playbook

Passive collection only unless program explicitly allows active probing. Respect robots, rate limits, and local law.

## 1. Target decomposition
From apex or company name derive:
- Legal entities, acquisitions, brands
- ASN / netblocks (whois, RIPE, ARIN — via curl/API)
- MX/NS/SPF/DMARC/DKIM (email infra leaks)
- Job posts (tech stack, internal tool names)

Save artifacts under `recon/<target>/osint/`.

## 2. Infrastructure correlation
```sh
# Certificate transparency (validate JSON before jq)
curl -fsS "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Reverse WHOIS / passive DNS — use public APIs the user authorizes
```

Cross-reference subdomains with `recon` skill output. Flag dev/staging/admin hostnames.

## 3. People & org (high-level)
- LinkedIn job titles → guess SaaS stack (Okta, Salesforce, Jira subdomain)
- GitHub org search: `"companyname" password OR api_key OR secret` (public repos only)
- Paste sites / breach indexes **only** for emails in program scope — verify with `secrets` skill

Never doxx individuals; focus on **organizational** attack surface.

## 4. Document & media metadata
If user uploads PDFs/images to `.raos/uploads/`:
```sh
exiftool file.pdf 2>/dev/null || true
strings file.pdf | head -200
```

Extract: author usernames, internal paths, software versions.

## 5. Threat intel cross-check
Search for:
- Prior breaches (haveibeenpwned domain search if API available)
- Shodan/Censys **only** if user provides API keys and scope includes IPs
- VirusTotal passive DNS for domains in scope

## 6. Deliverable
Produce `recon/<target>/osint/report.md`:
- Asset inventory (hosts, SaaS, cloud buckets named)
- High-value entry points ranked
- Recommended next skills (`secrets`, `cloud`, `takeover`)
- Explicit out-of-scope notes

Do not submit OSINT alone as a vulnerability unless misconfiguration is exploitable (e.g. public bucket).
