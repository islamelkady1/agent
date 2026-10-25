# Claude Code Skills — Offensive Security Suite

Drop-in [Claude Code](https://claude.com/claude-code) Skills for authorized penetration testing and bug bounty. Each is a hypothesis-driven **operating doctrine** (think like an attacker, break the developer's assumptions, chase the non-obvious, chain findings) followed by an **executable arsenal** of copy-paste commands and payloads, backed by current public research (PortSwigger, HackTricks, PayloadsAllTheThings, OWASP, The Hacker Recipes, Embrace The Red, et al.).

> Every skill opens with a **mandatory authorization & scope gate** — these are for assets you are authorized to test. Verify any cited CVE against its source before client use.

## Install

```bash
# global (available everywhere)
cp -R skills/<name> ~/.claude/skills/
# or project-scoped
cp -R skills/<name> /path/to/project/.claude/skills/
```
Then invoke explicitly with `/<name>`, or let Claude auto-trigger when a task matches.

## The skills

| Skill | Scope |
|-------|-------|
| `web-pentest` | OWASP WSTG + modern web: injection, access control, SSRF, request smuggling/desync, cache poisoning & deception, prototype-pollution→RCE, OAuth/SAML/JWT |
| `api-pentest` | OWASP API Top 10: BOLA/BFLA, mass assignment, JWT/JWKS, GraphQL/gRPC/SOAP/WS, gateway↔service parser differentials, race/idempotency |
| `mobile-pentest` | Android + iOS (MASTG): static reversing, Frida/objection pinning bypass, IPC/deep-link/WebView, → backend API |
| `network-pentest` | Infra + Active Directory: nmap/nxc/impacket, coerce+relay, Certipy ESC1–16, shadow creds/RBCD, lateral + pivot |
| `cloud-pentest` | AWS/GCP/Azure + k8s: IMDS SSRF, IAM privesc chains, OIDC federation trust, pod→node escape |
| `llm-appsec` | LLM/agent apps: direct + indirect prompt injection, output→RCE, excessive-agency/confused-deputy, RAG/memory poisoning, MCP; garak/promptfoo/PyRIT configs |
| `source-code-review` | White-box SAST + manual: source→sink taint, missing-authz hunting, custom Semgrep rules, SCA/secrets |
| `pentest-report` | Findings → CVSS-scored report, exec summary, bug-bounty write-ups |

## Design

- **Doctrine first, not a checklist** — coverage comes from adversarial thinking, not ticking boxes.
- **Executable layer** — real commands, payload libraries, tool configs; adapt to the target's parser/WAF/framework.
- **Chains over parts** — medium + medium = critical; the skills push toward impact and novel classes.

