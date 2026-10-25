---
name: source-code-review
description: >-
  Adversarial, hypothesis-driven secure code review (white-box) of a codebase or pull request you
  are authorized to review. Not a SAST-triage tool — it makes you read code like an attacker:
  trace untrusted data from source to dangerous sink, map trust boundaries, and find the bug that
  is usually what's MISSING (an authz check, a validation) — invisible to pattern scanners. Covers
  taint analysis, auth/authz design flaws, injection/deserialization/SSRF/path sinks, crypto &
  secrets, mass assignment, race/TOCTOU, language-specific footguns (JS/Python/Java/Go/PHP/Ruby/
  .NET/C/C++), dependency & IaC issues, and systemic/class bugs. Uses semgrep/CodeQL/gitleaks/SCA
  for breadth, manual reasoning for depth. Use when reviewing source, auditing a repo, or vetting a
  PR/diff for security. Reading code is low-touch; confirm findings dynamically via the other skills.
---

# Secure Code Review — Read Like an Attacker, Find What's Missing

You review code the way an attacker reads it: not "does this line look risky," but **"where does untrusted data enter, where does it reach something dangerous, and what stops it in between — and what if nothing does?"** The most valuable bugs are *absences* — a missing authorization check, an unvalidated input, a forgotten boundary — and a pattern scanner literally cannot see an absence. You find those by understanding what the code is *supposed* to guarantee and where it fails to. Tools give breadth; your reasoning gives the findings that matter.

If no code is given, ask for the repo/PR, the language/framework, how it's run, and whether this is a full audit or a diff review.

---

## Phase 0 — Authorization & Scope Gate (MANDATORY)

Confirm: **authorization to access and review this code** (owned / client engagement / OSS / signed NDA — none → stop), **confidentiality** (proprietary source stays in scope; don't exfiltrate or paste it to external services), and **scope** (whole codebase vs. a specific PR/module). Reading code is low-touch, but *confirming* a finding by running an exploit against a live system is active testing — gate that under the relevant dynamic skill's authorization.

---

## Operating Doctrine

1. **Source → sink, taint in between.** The core mental model: identify **sources** (where attacker-controlled data enters — request params/body/headers, file uploads, message queues, CLI args, deserializers, third-party callbacks, DB rows that were once user input → stored/second-order) and **sinks** (SQL, shell, `eval`, template render, file path, HTTP client, deserializer, HTML output). Follow each tainted path; the bug is where data reaches a sink without correct neutralization.
2. **Understand the design before the lines.** Read for *intent and trust boundaries* first: how is authn/authz enforced (middleware vs per-handler), where are security decisions made, what does each layer assume the previous one validated. The worst bugs are design flaws (the whole access-control model is wrong), not single lines.
3. **Hunt absences, not just patterns.** Scanners find dangerous calls; you find the *missing* check — the endpoint with no ownership verification, the admin route without a role guard, the input that's never validated, the error path that skips the check. Ask of every privileged action: "what proves the caller is allowed?" If you can't find it, that's the finding.
4. **Trust the code path, not the comments or the names.** A function called `validate()` may not. Follow actual control/data flow, including error/exception paths, early returns, and framework magic (auto-binding, default routes, implicit deserialization).
5. **Think in classes, not instances.** One bad pattern is usually repeated — find the root and grep the whole repo for siblings. Report the class with a representative instance and the systemic fix, so they don't whack-a-mole.
6. **Tools for breadth, brain for depth.** Run SAST/SCA/secret scanners to triage and find low-hanging fruit fast, then spend your hours manually on the security-critical modules (auth, crypto, access control, money, multi-tenancy, anything handling untrusted input). Most scanner output is noise — triage ruthlessly, never paste it as findings.
7. **Stay current.** Recall recent CVEs and footguns for the exact framework/library/runtime versions in `package.json`/`go.mod`/`pom.xml`/`requirements.txt`, and current research on the patterns you see.
8. **Skeptic before reporter.** Confirm reachability (is the sink actually reachable with attacker-controlled data?) and impact; mark anything you couldn't prove reachable as "needs validation," and confirm dynamically via `web-pentest`/`api-pentest` where possible.

---

## Phase 1 — Orient (low-touch)

Map the app: entrypoints (routes/controllers/handlers, message consumers, CLI, webhooks, deserializers), frameworks, the auth/session model, the data layer, config, and dependencies. Read `README`/build files to understand how it runs and what it trusts. Run breadth tooling early:

```bash
semgrep --config=auto .                 # patterns + framework rules (add custom rules for this app)
gitleaks detect / trufflehog filesystem .   # secrets in code AND git history
osv-scanner . / grype dir:.             # vulnerable + outdated dependencies (SCA)
# language linters: bandit (py), gosec (go), brakeman (ruby), eslint-plugin-security (js), CodeQL (deep)
```

Treat all of it as *leads*. Build a list of trust boundaries and privileged actions to verify by hand.

---

## Hunting Grounds (read these flows like an attacker)

### Authentication & authorization (top value — mostly absences)
Where is authz enforced, and is it enforced *everywhere*? Per-object ownership checks (IDOR/BOLA), function/role checks on privileged routes (BFLA), middleware that's bypassable or not applied to all routes, JWT verification correctness (signature actually checked? `alg`/`exp`/`aud`?), session fixation/invalidation, password reset & MFA logic. Grep every privileged handler for its guard.

### Injection & dangerous sinks
SQL (string-concatenated queries, ORM raw/`fmt.Sprintf`), command exec (`shell=True`, `exec`, backticks), SSTI, LDAP/NoSQL, **path traversal** (file ops with user-controlled paths), and **deserialization** (Python `pickle`/`yaml.load`, Java `readObject`/`XMLDecoder`, .NET `BinaryFormatter`, Ruby `YAML.load`, PHP `unserialize`, Node). Trace user input into each.

### Output & request sinks
XSS (template autoescaping disabled, `dangerouslySetInnerHTML`, raw HTML building), **SSRF** (HTTP clients fed user URLs without an allowlist → metadata/internal; pivot to `cloud-pentest`), open redirect, XXE (parser defaults), CRLF/header injection.

### Crypto & secrets
Hardcoded keys/secrets/credentials (and in git history), weak algorithms (MD5/SHA1/DES/ECB), static IV/keys, predictable RNG for tokens (`Math.random`, `rand()`), weak password hashing (vs bcrypt/scrypt/argon2), JWT alg/secret handling, custom crypto.

### Logic, state & binding
Mass assignment / over-binding (ORM auto-binds request → model, exposing `is_admin`/`role`), **TOCTOU / race conditions** (check-then-act without locking/transaction on balance/limits), integer overflow, insecure-by-default config, missing rate limits, replay/idempotency gaps. (Confirm races dynamically via `api-pentest`.)

### Language-specific footguns
- **JS/TS** — prototype pollution, `eval`/`Function`, `child_process`, ReDoS, `==`/type coercion, unsafe `JSON`/deep-merge.
- **Python** — `pickle`, `yaml.load`, `subprocess(shell=True)`, `eval`/`exec`, format-string, Flask/Django debug & `SECRET_KEY`.
- **Java** — deserialization (`readObject`/`XMLDecoder`), XXE defaults, SpEL/OGNL, reflection, Spring mass binding.
- **Go** — SQLi via `fmt.Sprintf`, SSRF, path traversal, missing context/error checks.
- **PHP** — `include`/`require` user input (LFI/RCE), `unserialize`, `==` type juggling, `extract()`.
- **Ruby** — `YAML.load`, `send`/`public_send`, mass assignment (strong params missing).
- **.NET/C#** — `BinaryFormatter`/`Json.NET` type handling, SQL, XXE.
- **C/C++** — memory safety: buffer overflow, use-after-free, integer overflow, format string, unchecked `memcpy`/`strcpy`.

### Dependencies & supply chain
Vulnerable/outdated packages (SCA), dependency confusion (private packages resolvable from public registries), typosquatting, unpinned/lockfile-missing deps, malicious postinstall scripts.

### Config, IaC & CI/CD
CORS misconfig, missing security headers, secrets in env/CI variables, Dockerfile/k8s/Terraform misconfig (→ `cloud-pentest`), and overly-broad CI permissions/OIDC trust.

---

## PR / Diff Review Mode

For a pull request: review the diff *in context* — understand the surrounding code, not just changed lines. Ask what the change **removes or weakens** (a deleted check, a loosened regex, a new sink, a widened scope, a new untrusted input), whether new code reuses existing safe patterns or reinvents them unsafely, and whether new dependencies/permissions are introduced. A diff's danger is often in what it quietly stops doing.

---

## Verify & Report

Per finding: file:line, the **source → sink path** (or the missing check), reachability, **demonstrated/likely impact**, whether it's an isolated bug or a repeated class, and a concrete fix (parameterize, enforce authz at the boundary, safe deserializer, allowlist, secret to a vault, the class-level remediation). Confirm dynamically where you can, mark unproven items as "needs validation," and hand off to `pentest-report`. Completeness pass: *which entrypoint's taint did I not trace? which privileged action has no guard I verified? which scanner lead did I dismiss without checking? what class of the bug I found exists elsewhere?*

---

# Executable Arsenal — SAST + Manual Recipes (2024–2026)

> The doctrine decides *what to read for*; this is the command/rule/grep layer. Use `rg` (ripgrep); patterns are PCRE2 (`rg -P`). **Treat every SAST hit as a lead, not a finding** — confirm source→sink reachability by hand. The high-severity bugs (missing authz, IDOR, logic) are invisible to scanners; §4–7 are manual.

## 0. Tooling Setup

```bash
pip install semgrep bandit checkov            # SAST(py) + IaC
# CodeQL CLI: download codeql-bundle-*.tar.gz from github/codeql-action releases; export PATH
brew install gitleaks osv-scanner trivy       # secrets + SCA + IaC
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
go install github.com/securego/gosec/v2/cmd/gosec@latest   # Go
gem install brakeman                          # Rails
npm i -D eslint eslint-plugin-security && pip install njsscan && npm i -g retire   # JS/Node
```

## 1. Breadth Scan (run all, triage later)

```bash
semgrep scan --config=auto .
semgrep scan --config p/owasp-top-ten --config p/security-audit --config p/secrets --sarif -o semgrep.sarif .
# CodeQL (deepest taint; compiled langs need a build)
codeql database create cdb --language=python --source-root=.          # py/js/ruby: no build cmd
codeql database create cdb --language=java --command='mvn -B clean install -DskipTests' --source-root=.
codeql database analyze cdb codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=codeql.sarif
# secrets (filesystem + FULL git history)
gitleaks detect --source . --redact -v --report-path gitleaks.json
trufflehog git file://. --only-verified --json                        # live-verifies creds
# SCA + IaC
osv-scanner scan -r . ; grype dir:. ; trivy fs --scanners vuln,secret,misconfig .
trivy config . ; checkov -d . --compact --quiet
```

## 2. Orient — Find Entrypoints (taint sources)

```bash
# routes / handlers
rg -nP '@(app|router|blueprint)\.(get|post|put|patch|delete)\(' --type py        # Flask/FastAPI
rg -nP '@(GetMapping|PostMapping|RequestMapping|PutMapping)' --type java
rg -nP '(app|router)\.(get|post|put|delete|use)\(' --type js                      # Express
rg -nP 'func .*\(w http\.ResponseWriter, r \*http\.Request\)' --type go
rg -nP 'Route::(get|post|put|delete|any)\(' --type php ; rg -nP '^\s*(get|post|resources)\b' config/routes.rb
# raw request access (sources)
rg -nP 'request\.(args|form|values|json|data|files|cookies|headers)' --type py
rg -nP 'req\.(query|params|body|headers|cookies)' --type js
rg -nP '@RequestParam|@PathVariable|@RequestBody|getParameter\(' --type java
rg -nP '\$_(GET|POST|REQUEST|COOKIE|FILES)\b' --type php ; rg -nP 'params\[|r\.(URL\.Query|FormValue|Body)' 
# out-of-band sources: deserializers, queue/event consumers, lambdas
rg -nP '@(KafkaListener|RabbitListener|JmsListener|SqsListener)|on_message|@app\.task|boto3\.'
```

## 3. Source → Sink Taint Hunting (grep per sink)

```bash
# SQLi — string-built queries
rg -nP '(execute|query|exec|raw|rawQuery)\s*\(.*(\+|%s|\$\{|f["'\'']|\.format\(|sprintf)'
rg -nP 'fmt\.Sprintf\(.*(SELECT|INSERT|UPDATE|DELETE).*\)' --type go        # gosec G201
rg -nP 'createQuery\(|createNativeQuery\(|@Query\(.*\+' --type java ; rg -nP '(where|find_by_sql)\(["'\''].*#\{' --type ruby
# command / code exec
rg -nP 'subprocess\.(run|Popen|call)\(.*shell\s*=\s*True|os\.(system|popen)\(|\beval\(|\bexec\(' --type py
rg -nP 'child_process\.(exec|execSync|spawn)\(|\beval\(|new Function\(|`[^`]*\$\{' --type js
rg -nP 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(|ScriptEngine' --type java ; rg -nP 'exec\.Command\(' --type go
rg -nP '\b(system|exec|shell_exec|passthru|popen|proc_open)\b|\beval\(' --type php
# SSTI / path traversal / deserialization / XXE / SSRF / XSS
rg -nP 'render_template_string\(|Template\([^)]*(\+|request)|Environment\(\)\.from_string\(' --type py
rg -nP '(open|read|sendFile|readFile|File\(|os\.path\.join|Paths\.get|ioutil\.ReadFile)\(.*(req|request|params|input|\$_)'
rg -nP 'pickle\.(load|loads)|yaml\.load\((?!.*Loader=)|marshal\.loads' --type py
rg -nP 'readObject\(|XMLDecoder|XStream|ObjectInputStream|SnakeYaml.*\.load\(' --type java
rg -nP 'BinaryFormatter|LosFormatter|TypeNameHandling\s*=' --type cs ; rg -nP '\bunserialize\(' --type php ; rg -nP 'Marshal\.load|YAML\.load\b' --type ruby
rg -nP 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory' --type java   # then confirm hardening ABSENT
rg -nP 'etree\.(parse|fromstring)|XMLParser\(' --type py                        # use defusedxml
rg -nP '(requests\.(get|post)|urllib|httpx|axios|fetch|http\.Get)\(.*(req|request|params|url=)'   # SSRF
rg -nP 'innerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|bypassSecurityTrust|mark_safe|\| ?raw\b|Html\.Raw'  # XSS
```

## 4. Auth / AuthZ — Absence Hunting (the bug is what's MISSING)

```bash
# 1. list privileged routes ; 2. find the guards that SHOULD wrap them ; 3. diff
rg -nP '(admin|internal|delete|approve|payout|refund|impersonate)' -t py -t js -t java -t go -t rb
rg -nP '@(login_required|requires_auth|permission_required|PreAuthorize|Authorize|Secured|RolesAllowed)|before_action|verifyToken|hasRole'
# IDOR / missing ownership: object fetched by user id with NO owner scoping
rg -nP '(findById|find_by_id|get_object_or_404|FindOne|\.find\(params\[:id\]\))'   # -> confirm .where(user_id=current_user)
# JWT verification misuse
rg -nP 'algorithms?\s*=\s*\[?["'\'']?none|verify\s*[:=]\s*(false|False)|verify_signature\s*=\s*False|jwt\.decode\((?!.*verify)'
rg -nP 'jwt\.decode\([^,)]+\)\s*$' --type js          # jsonwebtoken decode() never verifies
```

## 5. Crypto & Secrets

```bash
rg -nP '\b(MD5|SHA1|SHA-1|DES|3DES|RC4|ECB|MD4)\b'
rg -nP 'Cipher\.getInstance\("(DES|RC4|.*ECB)|hashlib\.(md5|sha1)\(|MODE_ECB|crypto\.createHash\(["'\''](md5|sha1)'
rg -nP '(IV|iv|key|secret|salt)\s*[:=]\s*["'\''][A-Za-z0-9+/=]{8,}|new\s+(IvParameterSpec|SecretKeySpec)\(\s*["'\''{]'  # static key/IV
rg -nP 'Math\.random\(\)|\brandom\.(random|randint)\(|mt_rand|new Random\('     # insecure RNG for tokens
rg -nP 'password.{0,20}(md5|sha1|sha256\()|hashpw|bcrypt|scrypt|argon2|pbkdf2'  # weak vs strong pw hashing
rg -nP '(api[_-]?key|secret|token|password|aws_access_key_id)\s*[:=]\s*["'\''][^"'\'' ]{8,}|-----BEGIN .*PRIVATE KEY-----'
git log -p --all -S 'BEGIN PRIVATE KEY' | head -50    # deleted secrets still in history
```

## 6. Mass Assignment / Race

```bash
# mass assignment — confirm allowlist EXISTS; absence = vuln
rg -nP '\.(new|create|update|assign_attributes)\(params(\[|\.)' --type ruby ; rg -nP 'params\.permit\(|params\.require\('
rg -nP '(create|update)\(\s*req\.body\s*\)|\.\.\.req\.body|Object\.assign\([^,]+,\s*req\.body' --type js
rg -nP 'fields\s*=\s*["'\'']__all__["'\'']' --type py ; rg -nP 'BeanUtils\.copyProperties\(|@ModelAttribute' --type java ; rg -nP '\$guarded\s*=\s*\[\]|->fill\(\$request' --type php
# TOCTOU / non-atomic money ops — confirm locking EXISTS on these paths
rg -nP '(balance|amount|quantity|stock|credit)\s*=\s*\1\s*[-+]' ; rg -nP 'SELECT .* FOR UPDATE|with_lock|transaction\.atomic|synchronized|idempotency'
```

## 7. Language Footgun Packs + native linters

```bash
# JS/TS: eval/Function, dynamic require, prototype pollution, vm
rg -nP '\beval\(|new Function\(|require\(req|__proto__|constructor\.prototype|vm\.runInNewContext'; njsscan .
# Python: eval/exec/pickle/yaml/shell=True/debug
rg -nP '\beval\(|\bexec\(|__import__\(|flask.*debug\s*=\s*True'; bandit -r . -ll
# Java: Runtime/readObject/SpEL/OGNL ; Go: text/template, InsecureSkipVerify, math/rand
rg -nP 'Runtime\.getRuntime|class\.forName\(|ScriptEngineManager'; rg -nP 'InsecureSkipVerify\s*:\s*true|text/template'; gosec ./...
# PHP: eval/assert/unserialize/include $_  ; Ruby: send/Marshal/eval ; .NET: BinaryFormatter/SqlCommand+; C/C++: gets/strcpy/sprintf/format-string
rg -nP '\beval\(|\bassert\(|\bunserialize\(|include\s*\(\$'; brakeman -A .
rg -nP '\b(gets|strcpy|strcat|sprintf|scanf)\s*\(|printf\s*\(\s*[a-z_]+\s*\)' 
```

## 8. Dependencies / Supply Chain

```bash
osv-scanner scan -r . --call-analysis=all ; grype dir:. --fail-on high
git diff HEAD~5 -- package-lock.json yarn.lock      # unexpected lockfile churn (Shai-Hulud era)
rg -nP '"(pre|post)?install"\s*:' package.json ; npm ci --ignore-scripts    # vet lifecycle scripts
rg -nP '"@?[a-z0-9-]+/[a-z0-9-]+":' package.json ; rg -n 'registry\s*=' .npmrc   # dependency-confusion: scoped pkgs pinned to private registry?
```

## 9. Custom Semgrep Rules (examples)

```yaml
# (a) taint-mode — Python request -> shell (RCE), with sanitizer
rules:
  - id: flask-request-to-os-system
    mode: taint
    languages: [python]
    severity: ERROR
    message: Untrusted Flask data flows into a shell command (RCE).
    metadata: { cwe: "CWE-78" }
    pattern-sources: [{pattern: flask.request.$ANY}, {pattern: request.args.get(...)}, {pattern: request.form.get(...)}]
    pattern-sanitizers: [{pattern: shlex.quote(...)}, {pattern: int(...)}]
    pattern-sinks: [{pattern: os.system(...)}, {pattern: 'subprocess.$F(..., shell=True, ...)'}, {pattern: os.popen(...)}]
```
```yaml
# (b) search-mode — insecure JWT verification (alg=none / verify off)
rules:
  - id: jwt-verification-disabled
    languages: [python, javascript, typescript]
    severity: ERROR
    message: JWT verification disabled or 'none' allowed — auth bypass.
    patterns:
      - pattern-either:
          - pattern: jwt.decode(..., options={"verify_signature": False}, ...)
          - pattern: jwt.verify($T, $K, {algorithms: ["none", ...]})
          - pattern: jwt.decode($T)       # node decode() never verifies
```
```bash
semgrep scan --config ./rules/ --validate && semgrep scan --config ./rules/ --sarif -o custom.sarif .
```

## 10. PR / Diff Review

```bash
semgrep ci --baseline-commit $(git merge-base origin/main HEAD)     # only NEW findings
gitleaks protect --staged -v                                        # pre-commit secret gate
git diff origin/main...HEAD -- '*.py' '*.js' '*.go' ; git log -p -S 'password' origin/main...HEAD
```
In a diff hunt for: a **removed** `@login_required`/guard on an existing route; new raw-SQL/`exec`/deserialization sinks; validation/auto-escape *removed* (`raw`, `mark_safe`, `dangerouslySetInnerHTML`); config flips (`verify=False`, `InsecureSkipVerify`, `DEBUG=True`, `0.0.0.0/0`, CORS `*`, dropped cookie flags); new deps/lifecycle scripts; new secrets; crypto downgrades. A diff's danger is often in what it quietly *stops* doing.

### Primary Sources
Semgrep docs (taint mode, registry) · GitHub CodeQL docs · OWASP Code Review Guide · gitleaks/trufflehog · OSV-Scanner/grype/Trivy · bandit/gosec/brakeman/eslint-plugin-security · per-language secure-coding refs (MS .NET deser, PHP object injection, C/C++ dangerous functions). **Confirm reachability before reporting; SAST is breadth, your reasoning is depth.**
