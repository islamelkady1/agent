---
name: supply-chain
description: Software supply chain security playbook — dependency confusion, typosquatting, compromised npm/PyPI packages, CI/CD pipeline abuse, artifact signing gaps, and SBOM review. Use when auditing repos, CI configs, package managers, or investigating build pipeline in authorized bug bounty / SSDLC assessments.
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

# Supply chain playbook

Assess build and dependency trust boundaries. No publishing malicious packages to public registries.

## 1. Repository inventory
```sh
# From cloned repo root
find . -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'Pipfile.lock' -o -name 'go.sum' | head -50
grep -rE 'npm install|curl.*\\| bash|wget.*\\| sh' .github/ .gitlab-ci/ Jenkinsfile 2>/dev/null | head -30
```

Flag: unpinned actions, `curl | bash`, secrets in CI logs, fork PR workflows with write tokens.

## 2. Dependency risks
| Check | Command / action |
|-------|------------------|
| Known vulns | `npm audit`, `pip audit`, `govulncheck` if available |
| Typosquat | Compare package names to official docs |
| Confusion | Internal `@corp/pkg` publishable publicly? |
| Postinstall scripts | `grep -r postinstall package.json` |

## 3. CI/CD abuse paths
- **Poisoned PR**: can fork PR exfiltrate `GITHUB_TOKEN`?
- **Artifact substitution**: unsigned releases, mutable `:latest` tags
- **Cache poisoning**: shared runner caches between tenants
- **OIDC misconfig**: cloud deploy role too broad

Review `.github/workflows/*.yml` for `pull_request_target`, `workflow_run`, excessive permissions.

## 4. Provenance & signing
- Sigstore/cosign present on container images?
- npm `--provenance` / SLSA level claims vs reality
- Maven/Gradle dependency verification plugins disabled?

## 5. In-scope bounty angles
Reportable when demonstrable on program asset:
- Dependency confusion leading to code execution in **their** build
- Public CI secret exposure with proven access
- Unsigned update channel allowing MITM on **their** users

Not reportable: generic "you should pin dependencies" without exploit path.

## 6. Remediation
- Pin hashes, enable Dependabot/Renovate with review
- OIDC least privilege, environment protection rules
- Artifact signing + verify in deploy pipeline
- Private registry namespace reservation

Export confirmed issues via `/export` with CWE-829 / CWE-494 references where applicable.
