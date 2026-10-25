# GitLab IDOR/BOLA Endpoint Hitlist (passive — from disclosed history)

Ranked by disclosed-report frequency + payout. Test pattern is always the same:
**alice's token tries to reach bob's private object by id/path → expect 404/403; a 200 is a finding.**
All testing runs against the **local GDK** (`localhost:3000`) first; hosted scope only after human-in-the-loop.

Legend: 🟥 high (repeatedly paid / recent CVE) · 🟧 medium · ⬜ EE-only or niche.

| # | Class | Endpoint(s) to probe as alice on bob's private project/group | Disclosed precedent |
|---|---|---|---|
| 1 🟥 | Project core | `GET /api/v4/projects/:id` | base IDOR — should 404 for alice |
| 2 🟥 | Issues | `GET /api/v4/projects/:id/issues`, `.../issues/:iid` | #502593 (comments leak) |
| 3 🟥 | Merge requests | `GET /api/v4/projects/:id/merge_requests`, `.../:iid`, `.../:iid/diffs` | #195134 guest→private MR; #692252 group search leaks MRs |
| 4 🟥 | CI pipelines / vars | `GET /api/v4/projects/:id/pipelines`, `.../pipelines/:pid/variables` | **CVE-2025-14594** (pipeline values via API IDOR) |
| 5 🟥 | Job artifacts | `GET /api/v4/projects/:id/jobs`, `.../jobs/:jid/artifacts` | **CVE-2024-10219** (download private artifacts) |
| 6 🟥 | Repo files/tree | `GET /api/v4/projects/:id/repository/tree`, `.../files/:path/raw?ref=` | #446585 ($11k exfil repo data) |
| 7 🟥 | ML models | `GET /api/v4/projects/:id/ml/models`, GraphQL `mlModels` | #2528293 ($1,160 — all ML models) |
| 8 🟧 | Labels | `GET /api/v4/projects/:id/labels`, `GET /api/v4/groups/:id/labels` | #439729 (add+read labels of private) |
| 9 🟧 | Members | `GET /api/v4/projects/:id/members`, `.../members/all` | enumerates private collaborators |
| 10 🟧 | Snippets | `GET /api/v4/snippets/:id`, `.../raw` | personal private snippet leak |
| 11 🟧 | Group + subgroups | `GET /api/v4/groups/:id`, `.../subgroups`, `.../projects` | #692252 group-scope leaks |
| 12 🟧 | Notes/comments | `GET /api/v4/projects/:id/issues/:iid/notes` | #502593 team-member comments |
| 13 🟧 | User private email | `GET /api/v4/users?username=bob` (check `email` field) | #972355 (private email by username) |
| 14 ⬜ | External status checks | `GET /api/v4/projects/:id/external_status_checks` | #1372216 ($610) — **EE only** |
| 15 ⬜ | Security dashboard | `GET /api/v4/projects/:id/vulnerabilities` | #853355 — **EE only** |
| 16 🟥 | GraphQL project | `POST /api/graphql` `project(fullPath:){issues,mergeRequests,...}` | #1192460 (deactivated user via GraphQL); GraphQL recurs across reports |

## Cross-cutting techniques the disclosed reports used (worth replicating)
- **Import/export & project templates** as a data-exfil channel — #743953 / #767770 ($20k each), #689314 ($12k).
  Copying a private project into one you own can drag private objects across the boundary. (Heavier to script — manual.)
- **Search scope leakage** — global/group search returning private MRs/code/commits the searcher can't otherwise see (#692252).
  Probe `GET /api/v4/search?scope=...&search=` and `GET /api/v4/groups/:id/search` as alice for bob's private terms.
- **GraphQL > REST for authz gaps** — several reports found the REST endpoint correctly denied but the GraphQL resolver did not.
  Always test both surfaces for the same object.
- **State-based bypass** — deactivated/guest/blocked users still reaching data (#1192460, #195134). Test with a downgraded carol.

## Mapping to the harness
`bola-lab.py setup` seeds bob's private project/group/issue/label/snippet.
`bola-lab.py test` runs the **REST battery (#1–13)** + **GraphQL (#16)** as alice vs bob, baseline-checked with bob's token.
EE-only rows (#14,#15) print as `n/a (EE)` on a CE GDK. Import/export + search-scope are flagged for manual follow-up.
