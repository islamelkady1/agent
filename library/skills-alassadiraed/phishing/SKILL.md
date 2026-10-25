---
name: phishing
description: Authorized social engineering and phishing simulation playbook — pretext design, landing page cloning boundaries, credential capture in lab, security awareness metrics, and safe email testing. Use only when RoE explicitly permits phishing against in-scope employees or training cohorts.
allowed-tools:
  - shell
  - http
  - file_write
  - ask_user
  - coverage
  - confirm_finding
---

# Phishing simulation playbook

**Requires explicit written authorization.** Simulations only — no credential reuse against personal accounts or out-of-scope services.

## 1. Authorization gates
Before any send, confirm with `ask_user`:
- Approved sender domains / subdomains in scope
- Target population (all staff vs red team cell)
- Capture goals: click rate, credential submit, MFA bypass demo?
- Legal/compliance sign-off reference

Stop immediately if user cannot confirm RoE.

## 2. Pretext design
| Level | Example (generic) |
|-------|---------------------|
| Awareness | IT password expiry notice |
| Spear | Project name from public press release |
| Vishing | Callback number to operator-controlled line |

Avoid: health scares, termination threats, real executive impersonation without approval.

## 3. Infrastructure (operator-owned)
- Dedicated sending domain with SPF/DKIM/DMARC aligned
- Landing on isolated host; TLS cert for simulation domain only
- No typosquat of unrelated brands (Microsoft/Google) — use **look-alike in your own domain** or vendor-approved templates

## 4. Payload safety
Landing pages:
- Capture to **local encrypted store** only
- Display "This was a simulation" on submit
- Never store real passwords in plaintext logs
- Do not auto-forward creds to third parties

## 5. Metrics & purple team
Track with `coverage`:
- Sent / delivered / opened / clicked / submitted
- Time-to-report (did user forward to security?)
- MFA prompt rate if applicable

Hand metrics to blue team for detection tuning — not public shaming lists.

## 6. Findings
Reportable outcomes (pentest report):
- Lack of MFA on VPN after simulated cred harvest
- Missing DMARC on corporate domain enabling real attackers
- No user reporting channel

Use `confirm_finding` only for **technical** misconfigs proven outside the simulation narrative.

## 7. Cleanup
- Take down landing pages within 24h of exercise end
- Delete captured credentials
- Debrief users per HR/security policy
