---
name: zeroday
description: Zero-day and unknown-vulnerability research playbook — variant analysis, patch diffing, crash triage, fuzzing strategy, and responsible disclosure workflow. Use when hunting novel bugs in in-scope software, analyzing vendor patches, or preparing coordinated disclosure — never for exploiting unrelated third-party products.
allowed-tools:
  - shell
  - http
  - file_write
  - grep
  - glob
  - coverage
  - confirm_finding
  - ask_user
---

# Zero-day research playbook

Research **in-scope** targets only. Follow coordinated disclosure; no public weaponization before vendor fix window.

## 1. Scope the binary / service
Collect from user:
- Exact version/build, commit hash, or Docker image digest
- Source available? (open core vs closed)
- Previous CVEs for same product line

Create `research/<target>/notes.md` with hypothesis list.

## 2. Patch diffing (when update breaks exploit)
```sh
# Example: two vendor JARs or nginx versions in uploads/
diff -ru old/ new/ | head -500
strings old/binary | diff - strings new/binary | head -100
```

Map changed functions → attack surface shrink/expand.

## 3. Fuzzing strategy (lab only)
| Surface | Approach |
|---------|----------|
| File parsers | AFL/libFuzzer on user-supplied corpus |
| Network protocols | Boofuzz / custom mutator with cap |
| Web APIs | OpenAPI-driven generation + `http` tool |
| JS engines | restricted — use vendor test suites |

Always fuzz **local copies**. Never fuzz production SaaS without explicit permission.

## 4. Crash triage
For core dumps / ASAN output user provides:
- Classify: exploitable vs DoS vs benign
- Identify: overflow, UAF, type confusion, logic bug
- Minimal PoC steps in isolated VM

Do not publish full exploit chains in chat — store redacted PoC in `./findings/`.

## 5. Variant hunting
After public CVE on in-scope product:
- Search similar sinks (same function family)
- Check sibling endpoints / plugins
- Test configuration defaults others miss

## 6. Responsible disclosure
1. Reproduce on latest version
2. `confirm_finding` with severity rationale
3. Draft report: impact, affected versions, fix recommendation, timeline
4. `ask_user` before any external submission

## 7. Bug bounty nuance
Many programs exclude zero-days in **third-party** libs unless proven impact on in-scope asset. Tie every claim to demonstrable effect on program app.
