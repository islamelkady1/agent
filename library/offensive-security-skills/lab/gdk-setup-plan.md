# Local GDK (GitLab Development Kit) Setup Plan

Purpose: stand up a local, fully-controlled GitLab instance as an IDOR/BOLA research lab,
per GitLab's HackerOne policy that **strongly recommends local GDK testing**. Findings are
reproduced against in-scope hosted assets only, human-in-the-loop, before reporting.

Host: Apple Silicon (arm64), macOS 26.4, 16 GB RAM (floor), 259 GB free.

---

## Phase 0 — Pre-flight (5 min)

- [ ] Close memory-heavy apps (browsers w/ many tabs, Docker, etc.). 16 GB is GDK's minimum;
      GDK + a Rails app + Postgres + Redis will use most of it.
- [ ] Confirm Homebrew is healthy: `brew doctor` (warnings OK, errors not).
- [ ] Pick install location. Plan uses `~/Desktop/beg-bounty/gdk` (clone lands here).
- [ ] Free disk check: need ~40 GB headroom. (Have 259 GB ✅)

## Phase 1 — Bootstrap install (~45–90 min, mostly unattended)

GDK's one-line bootstrap installs `mise` (version manager), the correct Ruby/Node/etc.,
clones `gitlab-org/gitlab`, and runs `gdk install`.

```bash
cd ~/Desktop/beg-bounty
# Official one-line installer (clones into ./gitlab-development-kit by default):
curl "https://gitlab.com/gitlab-org/gitlab-development-kit/-/raw/main/support/install" | bash
```

Notes:
- It will prompt for the install directory and to add `mise`/GDK shell hooks to your shell rc.
- This compiles native gems; the long pole is `bundle install` + `gdk install` asset compile.
- If it stalls on a gem (common: `gpgme`, `pg`, `charlock_holmes` on arm64), the installer
  prints the brew package to install, then re-run `gdk install` in the clone dir.

## Phase 2 — First start & verify (10 min)

```bash
cd ~/Desktop/beg-bounty/gitlab-development-kit
gdk start                 # boots Rails, Postgres, Redis, Workhorse, etc.
gdk status                # all services should be 'run'
gdk tail rails-web        # watch until "Listening on http://127.0.0.1:3000"
```

- Open http://localhost:3000
- Log in as **root**. Retrieve/seed the root password:
  - `gdk` seeds an admin `root` account; if login fails, reset:
    `cd gitlab && bundle exec rails runner "u=User.find_by_username('root'); u.password=u.password_confirmation='Researcher!2026'; u.password_automatically_set=false; u.save!"`
- `gdk doctor` to catch config issues.

## Phase 3 — Configure as a BOLA/IDOR lab (15 min)

The whole point: many tenants/roles so you can test object-level authorization.

1. **Disable outbound email / signup friction** (already local, but lock it down):
   - Admin → Settings → General → Sign-up restrictions: leave open *locally* so you can
     self-register the test users below.
2. **Seed a realistic multi-tenant topology** via Rails console
   (`cd gitlab && bundle exec rails console`) or the UI:
   - Users: `alice` (attacker), `bob` (victim), `carol` (third party), each its own session/token.
   - Groups: `group-a` (owned by alice), `group-b` (owned by bob), with private projects in each.
   - Issues, MRs, snippets, packages, CI artifacts under each — these are the IDOR objects.
3. **Generate Personal Access Tokens** for alice/bob (Profile → Access Tokens, `api` scope) so
   you can hit the REST/GraphQL API directly with each identity.
4. **Capture baseline**: record each object's numeric/global ID and the owning user. The test is:
   *does alice's token reach bob's object by ID?*

## Phase 4 — Testing workflow (ongoing)

- Read source first: GDK gives you the full codebase. Grep for authorization gaps —
  `Ability`/policy classes, `can?`, `authorize!`, `find_by(id:)` without scope.
  Endpoints missing a `current_user` ownership check are the candidates.
- Reproduce over API with alice's token against bob's object IDs (REST + GraphQL).
- Use Burp (already in your stack) as the proxy; point it at `localhost:3000`.
- When something looks real locally → **stop, confirm gitlab.com asset is in live H1 scope,
  use HackerOne email-alias test accounts, keep it human-in-the-loop**, then reproduce minimally
  on prod before writing the report.

## Scope guardrails (from GitLab H1 policy)

- ✅ In scope: privacy breaches exposing confidential data (this is the IDOR/BOLA class).
- ❌ Out: metadata/enumeration-only, DoS (except unauth persistent app-layer), standalone prompt injection.
- Production gitlab.com testing only when necessary, with HackerOne-aliased test accounts.
- DoS demos (if ever) must run on a self-managed instance, never prod.

## Day-to-day GDK commands

```bash
gdk start | gdk stop | gdk restart
gdk status
gdk update            # pull latest gitlab + re-migrate (do periodically)
gdk tail <service>
gdk doctor
```

## Teardown

```bash
gdk stop
# Remove clone dir to reclaim ~40 GB:
rm -rf ~/Desktop/beg-bounty/gitlab-development-kit
# mise + brew deps remain; remove separately if desired.
```
