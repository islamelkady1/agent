#!/usr/bin/env python3
"""
GDK BOLA/IDOR lab harness — local GitLab only (http://localhost:3000).

Phases:
  setup : as BOB (victim) create a private group + private project + issue + note +
          label + personal snippet. Records ids to lab-objects.json.
  test  : as ALICE (attacker) run the endpoint battery from gitlab-idor-hitlist.md.
          Two kinds of checks:
            (A) isolation  -> alice should get 404/403; a 200 = 🚨 IDOR/BOLA.
            (B) leak-probe -> 200 expected, but inspect payload for bob's private data
                              (private email by username; search-scope leakage).
          Every isolation target is baseline-checked with bob's own token first.

Reads tokens from lab-users.json (seed-users.rb). Pure stdlib — no pip installs.

Usage:
  python3 bola-lab.py setup
  python3 bola-lab.py test
  python3 bola-lab.py setup --base http://localhost:3000
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(HERE, "lab-users.json")
OBJECTS_FILE = os.path.join(HERE, "lab-objects.json")
VICTIM_ISSUE_TITLE = "VICTIM secret issue"
VICTIM_SNIPPET_MARKER = "TOP SECRET bob value"


def api(base, method, path, token, body=None):
    """Return (status, parsed_json_or_text)."""
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"PRIVATE-TOKEN": token}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except urllib.error.URLError as e:
        return 0, f"CONN-ERROR: {e}"
    try:
        return r.status, json.loads(raw)
    except json.JSONDecodeError:
        return r.status, raw


def load_users():
    if not os.path.exists(USERS_FILE):
        sys.exit(f"missing {USERS_FILE} — run seed-users.rb first")
    with open(USERS_FILE) as f:
        return json.load(f)


# ---------------------------------------------------------------- setup
def cmd_setup(args):
    users = load_users()
    bob = users["bob"]["token"]
    base = args.base
    o = {}

    st, g = api(base, "POST", "/api/v4/groups", bob,
                {"name": "Group B", "path": f"group-b-{users['bob']['id']}",
                 "visibility": "private"})
    if st not in (200, 201):
        _, gl = api(base, "GET",
                    f"/api/v4/groups?search=group-b-{users['bob']['id']}", bob)
        g = gl[0] if isinstance(gl, list) and gl else {}
    o["group"] = {"id": g.get("id"), "full_path": g.get("full_path")}

    st, p = api(base, "POST", "/api/v4/projects", bob,
                {"name": "Secret B", "path": "secret-b",
                 "namespace_id": o["group"]["id"], "visibility": "private",
                 "initialize_with_readme": True})
    if st not in (200, 201):
        _, pl = api(base, "GET", "/api/v4/projects?search=secret-b&owned=true", bob)
        p = pl[0] if isinstance(pl, list) and pl else {}
    o["project"] = {"id": p.get("id"), "path_with_namespace": p.get("path_with_namespace")}

    pid = o["project"]["id"]
    st, i = api(base, "POST", f"/api/v4/projects/{pid}/issues", bob,
                {"title": VICTIM_ISSUE_TITLE, "description": "bob-only data"})
    o["issue"] = {"project_id": pid, "iid": i.get("iid")}
    api(base, "POST", f"/api/v4/projects/{pid}/issues/{i.get('iid')}/notes", bob,
        {"body": "private internal comment"})

    api(base, "POST", f"/api/v4/projects/{pid}/labels", bob,
        {"name": "victim-label", "color": "#ff0000"})

    st, s = api(base, "POST", "/api/v4/snippets", bob,
                {"title": "bob secret snippet", "file_name": "secret.txt",
                 "content": VICTIM_SNIPPET_MARKER, "visibility": "private"})
    o["snippet"] = {"id": s.get("id")}

    with open(OBJECTS_FILE, "w") as f:
        json.dump(o, f, indent=2)
    print("seeded victim (bob) objects:")
    print(json.dumps(o, indent=2))
    print(f"\nWROTE {OBJECTS_FILE}")


# ---------------------------------------------------------------- test
def cmd_test(args):
    users = load_users()
    if not os.path.exists(OBJECTS_FILE):
        sys.exit(f"missing {OBJECTS_FILE} — run `setup` first")
    with open(OBJECTS_FILE) as f:
        o = json.load(f)
    alice, bob = users["alice"]["token"], users["bob"]["token"]
    base = args.base
    pid, gid = o["project"]["id"], o["group"]["id"]
    iid, sid = o["issue"]["iid"], o["snippet"]["id"]
    fp = o["project"]["path_with_namespace"]

    # (label, path, ee_only) — isolation targets: alice must NOT get 200
    battery = [
        ("project",            f"/api/v4/projects/{pid}", False),
        ("issues-list",        f"/api/v4/projects/{pid}/issues", False),
        ("issue-detail",       f"/api/v4/projects/{pid}/issues/{iid}", False),
        ("issue-notes",        f"/api/v4/projects/{pid}/issues/{iid}/notes", False),
        ("merge_requests",     f"/api/v4/projects/{pid}/merge_requests", False),
        ("pipelines",          f"/api/v4/projects/{pid}/pipelines", False),
        ("pipeline-vars-cfg",  f"/api/v4/projects/{pid}/variables", False),
        ("jobs",               f"/api/v4/projects/{pid}/jobs", False),
        ("repo-tree",          f"/api/v4/projects/{pid}/repository/tree", False),
        ("repo-readme-raw",    f"/api/v4/projects/{pid}/repository/files/README.md/raw?ref=main", False),
        ("ml-models",          f"/api/v4/projects/{pid}/ml/models", False),
        ("project-labels",     f"/api/v4/projects/{pid}/labels", False),
        ("project-members",    f"/api/v4/projects/{pid}/members/all", False),
        ("group",              f"/api/v4/groups/{gid}", False),
        ("group-labels",       f"/api/v4/groups/{gid}/labels", False),
        ("group-projects",     f"/api/v4/groups/{gid}/projects", False),
        ("snippet",            f"/api/v4/snippets/{sid}", False),
        ("snippet-raw",        f"/api/v4/snippets/{sid}/raw", False),
        ("external-status",    f"/api/v4/projects/{pid}/external_status_checks", True),
        ("vulnerabilities",    f"/api/v4/projects/{pid}/vulnerabilities", True),
    ]

    findings = []
    print(f"\n(A) ISOLATION BATTERY — alice vs bob's private objects")
    print(f"{'OBJECT':<20}{'BOB':<7}{'ALICE':<8}VERDICT")
    print("-" * 72)
    for label, path, ee in battery:
        bst, _ = api(base, "GET", path, bob)
        ast, abody = api(base, "GET", path, alice)
        if ast in (200, 201):
            v = "🚨 POTENTIAL IDOR/BOLA (reachable!)"
            findings.append({"object": label, "path": path, "status": ast,
                             "sample": str(abody)[:240]})
        elif ee and bst in (403, 404) and ast in (403, 404):
            v = "n/a (EE / feature off)"
        elif ast in (401, 403, 404):
            v = "✅ isolated"
        else:
            v = f"⚠️  unexpected ({ast})"
        print(f"{label:<20}{bst:<7}{ast:<8}{v}")

    # (B) leak-probes — 200 expected, inspect payload for bob's private data
    print(f"\n(B) LEAK PROBES — 200 ok, but payload must not contain bob's private data")
    print("-" * 72)

    # B1: private email by username (#972355)
    _, ub = api(base, "GET", "/api/v4/users?username=bob", alice)
    leaked_email = None
    if isinstance(ub, list) and ub:
        leaked_email = ub[0].get("email") or ub[0].get("public_email")
    if leaked_email:
        print(f"users?username=bob  -> 🚨 email field exposed to alice: {leaked_email}")
        findings.append({"object": "user-email", "leak": leaked_email})
    else:
        print(f"users?username=bob  -> ✅ no private email field for alice")

    # B2: search-scope leakage (#692252) — alice searches for bob's private issue title
    _, sr = api(base, "GET",
                f"/api/v4/search?scope=issues&search={VICTIM_ISSUE_TITLE.replace(' ', '+')}",
                alice)
    hit = isinstance(sr, list) and any(
        VICTIM_ISSUE_TITLE in (x.get("title") or "") for x in sr)
    if hit:
        print(f"search scope=issues -> 🚨 alice's search returned bob's private issue")
        findings.append({"object": "search-scope-issues", "term": VICTIM_ISSUE_TITLE})
    else:
        print(f"search scope=issues -> ✅ bob's private issue not in alice's results")

    # (C) GraphQL — same object, second surface (#1192460 + recurring)
    print(f"\n(C) GRAPHQL — alice reading bob's project via resolver")
    print("-" * 72)
    gql = {"query": "query($fp:ID!){project(fullPath:$fp)"
                    "{name issues{nodes{title}} mergeRequests{nodes{title}}}}",
           "variables": {"fp": fp}}
    gst, gbody = api(base, "POST", "/api/graphql", alice, gql)
    proj = gbody.get("data", {}).get("project") if isinstance(gbody, dict) else None
    if proj is not None:
        print(f"graphql project    -> 🚨 POTENTIAL BOLA — project visible to alice: {json.dumps(proj)[:200]}")
        findings.append({"object": "graphql-project", "sample": json.dumps(proj)[:240]})
    else:
        print(f"graphql project    -> ✅ resolver returned null for alice")

    # summary
    print("\n" + "=" * 72)
    if findings:
        print(f"🚨 {len(findings)} POTENTIAL finding(s) — verify by hand before reporting:")
        print(json.dumps(findings, indent=2))
        print("\nNEXT: trace the missing authz in source "
              "(grep -rn 'find_by(id' / Ability / can? / DeclarativePolicy),"
              "\nthen — only if real on hosted scope — reproduce with H1-aliased accounts, human-in-the-loop.")
    else:
        print("✅ Clean: GitLab isolated every one of bob's objects from alice across REST, search, and GraphQL.")
    print("\nManual follow-ups (not auto-scripted): project import/export & template copy "
          "(#743953/#767770/#689314), broader search scopes, downgraded/blocked-user state bypass.")


def main():
    ap = argparse.ArgumentParser(description="GDK BOLA/IDOR API harness (local only)")
    ap.add_argument("cmd", choices=["setup", "test"])
    ap.add_argument("--base", default="http://localhost:3000")
    args = ap.parse_args()
    {"setup": cmd_setup, "test": cmd_test}[args.cmd](args)


if __name__ == "__main__":
    main()
