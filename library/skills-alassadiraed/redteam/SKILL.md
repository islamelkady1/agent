---
name: redteam
description: Full-spectrum adversary simulation playbook mapped to MITRE ATT&CK — objectives, OPSEC, kill-chain planning, detection evasion awareness, and executive reporting. Use when the user requests red team exercise, TIBER-style assessment, purple team, or "think like APT" within authorized scope.
allowed-tools:
  - shell
  - http
  - coverage
  - confirm_finding
  - file_write
  - scope_check
  - ask_user
---

# Red team / adversary simulation playbook

Simulate realistic threat actors **only** under signed rules of engagement (RoE). No out-of-scope targets, no production destruction, no real victim phishing without approval.

## 1. Rules of engagement
Confirm in writing:
- In-scope CIDRs, domains, apps, physical locations
- Out-of-scope: third parties, production payment, PII exfil limits
- Allowed TTPs: phishing? C2? physical? social engineering?
- Hours, emergency stop contact, data handling

Use `scope_check` before every new asset.

## 2. Objectives (pick one primary)
| Objective | Example success criteria |
|-----------|-------------------------|
| Domain dominance | DA or cloud admin in lab |
| Data access | Read specific dataset (flag file) |
| Persistence demo | Maintain access 7 days undetected (sandbox) |
| Detection test | Trigger 3 specific SIEM alerts |

## 3. MITRE ATT&CK pass (plan before execute)
1. **Recon** — `osint`, `recon` skills
2. **Resource development** — payloads in operator-controlled infra only
3. **Initial access** — phish, VPN creds, web RCE (program scope)
4. **Execution / persistence** — lab hosts only
5. **Privilege escalation** — `active-directory`, `exploit-dev`
6. **Defense evasion** — document controls bypassed, don't teach evasion of unrelated orgs
7. **Credential access** — Kerberos, dumps (authorized)
8. **Discovery / lateral** — `lateral` skill
9. **Collection / exfil** — synthetic data only unless RoE allows
10. **Impact** — **never** ransomware or destructive actions unless isolated clone

Track each technique with `coverage` (e.g. `T1558.003 Kerberoasting on svc_sql`).

## 4. OPSEC defaults
- Use operator-owned C2 infra; label callbacks in RoE
- Prefer low-and-slow over spray-and-pray
- Redact secrets in logs; use `./findings/` for sanitized evidence
- Stop on blue-team request or scope ambiguity — `ask_user`

## 5. Purple team handoff
For each successful TTP, record:
- ATT&CK ID + name
- Procedure (sanitized)
- Timestamp, source host, target
- Detection opportunity (log source, rule idea)

## 6. Executive report skeleton
1. Engagement summary & objectives
2. Attack narrative (timeline)
3. Critical findings (business impact)
4. ATT&CK heatmap (techniques used vs detected)
5. Remediation prioritized by risk
6. Appendices: IOCs (sanitized), tool list

Export with `/export` when findings are confirmed via `confirm_finding`.
