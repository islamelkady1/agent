---
name: subdomain-enum-workflow
description: End-to-end subdomain enumeration and attack-surface mapping for authorized security testing and bug bounty. Use this skill whenever the user wants to enumerate, discover, brute-force, permute, resolve, or consolidate subdomains for a target domain — or mentions any of subfinder, amass, assetfinder, dnscan, github-subdomains, gitlab-subdomains, gau, crt.sh, shuffledns, cewl, gospider, SubDomainizer, gotator, puredns, dnsx, cero, httpx, or "passive/active recon". Runs passive + active + recursive + permutation + relationship + scraping phases, DNS-resolves everything, and produces a clean deduplicated live-host list. Trigger it even when the user only says "find subdomains for X" or "map the attack surface of X" without naming tools.
metadata:
  version: 1.0.0
  platforms: [linux]
  tags: [recon, subdomains, enumeration, bug-bounty, pentest, dns]
---

# Subdomain Enumeration Workflow

A repeatable, phased methodology to discover as many valid subdomains as possible for a
target, then narrow down to the live ones. It chains passive sources, active brute-force,
recursive enumeration, permutations, relationship discovery, and JS scraping — resolving
everything through `puredns`/`dnsx` so the final output is trustworthy.

The commands below are a reference baseline. Tool flags and versions change, so run
**adaptively**: if a command errors, diagnose and fix it (see *Adaptive execution* below)
rather than skipping the source — the objective is to get each tool running and its output
merged, not to match this file's exact syntax.

## Scope and authorization (read first)

Only run this against domains the user **owns or is explicitly authorized to test**
(their own asset, a signed engagement, or an in-scope bug-bounty program). Enumeration is
noisy and generates real DNS/HTTP traffic. If the target's authorization is unclear, ask
before running active phases (brute-force, permutations, scraping) — passive-only sources
are lower impact but still confirm scope first. Respect each program's scope rules and rate
limits.

## Prerequisites

Set these once and reuse across phases. Fix any missing tool before starting the phase that
needs it rather than mid-run.

```bash
# ---- Variables (set per engagement) ----
TARGET="example.com"                 # root domain
WORKDIR="subs/${TARGET}"             # output tree for this target
RESOLVERS="$HOME/wordlists/resolvers.txt"   # trusted resolvers for puredns/shuffledns
DNS_WORDLIST="$HOME/wordlists/subdomains-10000.txt"

mkdir -p "$WORKDIR"/{horizontal,vertical/passive,vertical/active,scrap,perms}
cd "$WORKDIR"

# ---- Wordlists ----
# Brute-force list (DNS names)
# e.g. SecLists: Discovery/DNS/subdomains-top1million-110000.txt
# Permutation words (~1K common tokens: admin, demo, api, backup, ftp, dev, stage ...)
wget -q https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw \
  -O dns_permutations_list.txt
```

### Config & credential files

These tools read API keys / tokens from fixed config paths. Fuller keys = more results;
a missing file just thins the output, it's never fatal.

| Tool | Config path(s) | Holds |
|------|----------------|-------|
| subfinder | `~/.config/subfinder/provider-config.yaml`, `~/.config/subfinder/config.yaml` | provider API keys + settings |
| amass | `~/.config/amass/config.yaml`, `~/.config/amass/datasources.yaml` | data sources + API keys |
| findomain | `~/.config/findomain/config.toml` | source API keys |
| github-subdomains / gitlab-subdomains | `~/.tokens` | GitHub/GitLab personal access tokens |

```bash
# Quick sanity check before running passive sources
for f in ~/.config/subfinder/provider-config.yaml ~/.config/amass/config.yaml \
         ~/.config/findomain/config.toml ~/.tokens; do
  [ -s "$f" ] && echo "[ok]   $f" || echo "[warn] missing/empty: $f"
done
```

Tools used across phases: `subfinder`, `amass`, `assetfinder`, `findomain`, `dnscan`,
`github-subdomains`, `gitlab-subdomains`, `gau`, `curl`+`jq` (crt.sh), `shuffledns`,
`cewl`, `gospider`, `SubDomainizer`, `gotator`, `puredns`, `dnsx`, `cero`, `httpx`,
`anew`, `unfurl`.

---

## Adaptive execution (self-correct — don't give up)

**The commands in this skill are reference defaults, not gospel.** Tool versions change,
flags get renamed, and syntax drifts. Treat every command as a starting point and adapt it
until the tool actually runs and produces output. Never abandon a source just because the
first invocation errored — diagnose and fix it.

When a command fails or behaves unexpectedly, work this loop:

1. **Read the actual error.** A non-zero exit or an empty output file is a signal, not a
   dead end. Capture stderr (`cmd 2>&1 | tee err.log`) and read what it says — unknown flag,
   missing arg, bad path, no results, rate-limit, auth error each need a different fix.
2. **Ask the tool how it works now.** Check `TOOL -h` / `TOOL --help` and `TOOL -version`.
   Confirm the flag names, required args, and I/O options for the *installed* version rather
   than assuming this skill's flags are current (e.g. `-o` vs `-oJ`, `-d` vs `-domain`,
   input via `-l file` vs stdin).
3. **Correct and retry.** Rebuild the command from what `--help` showed, then run again.
   Iterate a few times if needed — small flag/syntax fixes usually resolve it.
4. **Search when stuck.** If `--help` isn't enough, search the web for the tool's current
   usage / the exact error string (official repo README, `-h` output, recent issues). Use
   the corrected syntax you find.
5. **Handle the common cases directly:**
   - *Tool not found* → try to install it (its documented `go install` / `pip install` /
     package method), or substitute an equivalent that reaches the same goal (e.g. another
     passive source) and note the swap.
   - *Missing/empty config or token* → run the tool without that source and record that the
     result is thinner; don't block the whole phase.
   - *Rate-limited / transient network error* → back off and retry, reduce concurrency
     (`-t`), or move on and revisit.
   - *No results but exit 0* → verify the flag that actually emits output, confirm the
     target/scope, and re-run before concluding "nothing found."
6. **Only skip after a genuine failure**, and when you do, log which source was skipped and
   why so the run stays auditable. Missing one source is fine; silently producing a
   command that never ran is not.

**Goal over syntax:** each step has an objective (this source's hostnames landed in its
output file, and got merged into the running list). As long as you reach that objective, a
command that differs from what's written here is not just acceptable — it's expected.

---

## Completion rule (STRICT — account for every tool, ignore nothing)

**No phase is "done" until every tool in it has been accounted for.** For each tool there
are exactly two acceptable end states:

- ✅ **RAN + OUTPUT** — the tool executed and its output file exists and is **non-empty**.
- ⚠️ **FAILED/SKIPPED + LOGGED** — after genuinely exhausting the *Adaptive execution* loop
  (fixed flags, checked `--help`, searched, tried install/alternative), it still could not
  produce output — and you recorded the tool name + the concrete reason.

Anything else is not allowed. **Never** silently drop a source, never assume it ran, and
never move to the next phase leaving a tool unverified. An empty output file counts as
**not done** — investigate why (wrong flag, no results, auth) before accepting it.

### Keep a run ledger

Track every tool's status in a single file so the run is auditable end to end.

```bash
LEDGER="$WORKDIR/run_status.tsv"
: > "$LEDGER"   # reset at start of a fresh run

# Call this after each tool. Marks RAN if the output file is non-empty, else FAILED.
# Usage: check_tool <tool-name> <output-file> [reason-if-known]
check_tool() {
  local tool="$1" out="$2" reason="${3:-}"
  if [ -s "$out" ]; then
    printf '%s\tRAN\t%s\t%s lines\n' "$tool" "$out" "$(wc -l < "$out")" >> "$LEDGER"
  else
    printf '%s\tFAILED\t%s\t%s\n' "$tool" "$out" "${reason:-empty/no output — investigate}" >> "$LEDGER"
    echo "[!] $tool produced no output ($out) — apply Adaptive execution before accepting"
  fi
}

# Example after each source:
#   subfinder ... | tee subfinder.txt ; check_tool subfinder subfinder.txt
```

### Per-phase gate

Before merging a phase and moving on, verify every expected output is present and non-empty:

```bash
# List the tools you expected to run in THIS phase and confirm each has real output.
for f in subfinder.txt amass.txt assetfinder.txt gau.txt crtsh.txt \
         github_subdomains.txt gitlab_subdomains.txt findomain.txt; do
  [ -s "$f" ] && echo "[ok]   $f ($(wc -l < "$f") lines)" \
              || echo "[MISSING/EMPTY] $f  <-- do not proceed until resolved or logged"
done
```

Do not run the phase's merge/`sort -u` step until every entry is either `[ok]` or has a
logged reason in the ledger. If something is empty, go back through the adaptive loop.

### Final accounting (before Phase 7 consolidation)

```bash
echo "==== RUN STATUS ===="; column -t -s$'\t' "$WORKDIR/run_status.tsv"
FAILS=$(grep -c $'\tFAILED\t' "$WORKDIR/run_status.tsv" || true)
echo "Tools with no output: ${FAILS:-0} (each MUST have a logged reason above)"
```

Only consolidate once the ledger shows every tool as RAN, or FAILED with an explicit
reason. Report this summary to the user at the end so nothing is hidden.

Cheap, quiet sources first. Each writes to `vertical/passive/`. Run them in whatever
combination is available; more sources = better coverage. Keep going even if one tool is
missing or a token is absent.

```bash
cd "$WORKDIR/vertical/passive"

# 1. subfinder (all sources; provider-config holds the API keys)
subfinder -d "$TARGET" -all -v \
  -config ~/.config/subfinder/config.yaml \
  -pc ~/.config/subfinder/provider-config.yaml \
  | tee subfinder.txt

# 2. amass (config.yaml = settings, datasources.yaml = sources + API keys)
amass enum -config ~/.config/amass/config.yaml \
  -dir amass_out -d "$TARGET" -o amass.txt

# 3. assetfinder
echo "$TARGET" | assetfinder -subs-only > assetfinder.txt

# 4. gau (URLs -> hostnames)
gau "$TARGET" --subs --providers wayback \
  | unfurl -u domains | sort -u > gau.txt

# 5. crt.sh (certificate transparency)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt

# 6. GitHub subdomains (needs a tokens file with PATs)
github-subdomains -d "$TARGET" -t ~/.tokens -e -o github_subdomains.txt

# 7. GitLab subdomains
gitlab-subdomains -d "$TARGET" -t ~/.tokens -e -raw > gitlab_subdomains.txt

# 8. findomain (fast passive; auto-reads ~/.config/findomain/config.toml for API keys)
findomain -t "$TARGET" -u findomain.txt
```

Merge passive output:

```bash
cat "$WORKDIR"/vertical/passive/*.txt | sort -u > "$WORKDIR/vertical/passive.txt"
```

---

## Phase 2 — Active / brute-force enumeration

Guessing names against a wordlist, then DNS-resolving. Higher traffic — confirm scope.

```bash
cd "$WORKDIR/vertical/active"

# dnscan (dictionary brute-force with recursion)
python3 dnscan.py -d "$TARGET" -w "$DNS_WORDLIST" -t 1000 -N -r -o dnscan.txt

# shuffledns (mass brute-force via massdns)
shuffledns -d "$TARGET" -w "$DNS_WORDLIST" -r "$RESOLVERS" \
  -mode bruteforce -o shuffledns.txt

# cewl (build a target-specific wordlist from the site's own words,
#        then feed it back into brute-force for context-aware guesses)
cewl "https://${TARGET}" -d 2 -m 5 -c --with-numbers -w cewl_words.txt

cat "$WORKDIR"/vertical/active/*.txt | sort -u > "$WORKDIR/vertical/active.txt"
```

---

## Phase 3 — Recursive enumeration on top domains

Look at everything found so far, find the most common second- and third-level domain
names, and re-run passive enumeration on those. Acquisitions and internal naming patterns
surface here. Read `subdomains.txt` = the merged list so far.

```bash
cd "$WORKDIR"
cat vertical/passive.txt vertical/active.txt | sort -u > subdomains.txt

# Top-10 Second-Level Domains (e.g. example.com from a.b.example.com)
rev subdomains.txt | cut -d '.' -f1,2 | rev \
  | sort | uniq -c | sort -rn | head -10 | awk '{print $2}' > top_sld.txt

# Top-10 Third-Level Domains (e.g. b.example.com)
rev subdomains.txt | cut -d '.' -f1,2,3 | rev \
  | sort | uniq -c | sort -rn | head -10 | awk '{print $2}' > top_tld.txt

# Re-run passive sources on each top domain, appending to one recursive file
while read -r d; do
  subfinder -d "$d" -all -silent   >> passive_recursive.txt
  assetfinder -subs-only "$d"      >> passive_recursive.txt
  amass enum -passive -config ~/.config/amass/config.yaml -d "$d" -silent >> passive_recursive.txt
  findomain -t "$d" -q             >> passive_recursive.txt
done < <(cat top_sld.txt top_tld.txt | sort -u)

sort -u passive_recursive.txt -o passive_recursive.txt

# Resolve the recursive finds to keep only live names
puredns resolve passive_recursive.txt -r "$RESOLVERS" \
  > vertical/passive/recursive_resolved.txt
```

---

## Phase 4 — Permutations / alterations

Generate mutations of known names (dev-api, api2, backup-admin …) and resolve them. This
catches predictable-but-unlinked hosts. Feeding the **invalid/unresolved** names back in
often surfaces rare valid subdomains others miss.

```bash
cd "$WORKDIR/perms"

# Generate permutations from the current subdomain list
gotator -sub "$WORKDIR/subdomains.txt" -perm "$WORKDIR/dns_permutations_list.txt" \
  -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt

# DNS-resolve permutations, keep valid ones
puredns resolve perms.txt -r "$RESOLVERS" -w resolved_perms.txt

# Second pass: permute names that DID NOT resolve — sometimes yields hard-to-find hosts
gotator -sub not_valid_subs.txt -perm "$WORKDIR/dns_permutations_list.txt" \
  -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms_round2.txt
puredns resolve perms_round2.txt -r "$RESOLVERS" -w resolved_perms_round2.txt
```

---

## Phase 5 — Relationship discovery

Pivot from one asset to related ones through shared signals. Great for finding acquisitions
and hidden infrastructure.

### Google Analytics relationships
Organizations often reuse one Analytics ID across all their properties. Reverse-searching it
reveals sibling domains.

```bash
git clone https://github.com/Josue87/AnalyticsRelationships.git
cd AnalyticsRelationships/Python
pip3 install -r requirements.txt
python3 analyticsrelationships.py -u "https://www.${TARGET}"
```

### TLS / CSP / CNAME probing
SSL certs, Content-Security-Policy headers, and CNAME chains all leak related hostnames.

```bash
cd "$WORKDIR"

# TLS: pull SANs from the cert (cero), strip wildcards
cero "$TARGET" | sed 's/^\*\.//' | grep -e "\." | sort -u > tls_names.txt

# CSP: probe live hosts and harvest domains referenced in CSP headers
cat subdomains.txt | httpx -csp-probe -status-code -retries 2 -no-color \
  | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains \
  | anew -q csp_subdomains.txt

# CNAME: follow CNAME records for the list
dnsx -retry 3 -cname -l subdomains.txt -o cname_records.txt
```

### Search-engine sourcing
Write targeted Google/Bing dorks (`site:*.${TARGET} -www`, nested `site:` exclusions to
paginate past the first results, `inurl:`, etc.) and use available search capability to
pull additional hostnames. Feed anything found back into the merge in Phase 7.

---

## Phase 6 — Scraping (JS / source code)

Crawl live sites; JS bundles, sitemaps, and robots files frequently reference internal
subdomains.

```bash
cd "$WORKDIR/scrap"

# 1. Web-probe the current list to get reachable URLs
cat "$WORKDIR/subdomains.txt" | httpx -random-agent -retries 2 -no-color \
  -o probed_tmp_scrap.txt

# 2. Crawl those URLs (follow JS, sitemap, robots)
gospider -S probed_tmp_scrap.txt --js -t 50 -d 3 --sitemap --robots -w -r > gospider.txt

# 3. Extract in-scope hostnames and clean overly long lines
sed -i '/^.\{2048\}./d' gospider.txt
grep -Eo 'https?://[^ ]+' gospider.txt | sed 's/]$//' \
  | unfurl -u domains | grep "\.${TARGET}$" | sort -u > scrap_subs.txt

# Also run SubDomainizer against a page for secrets + subdomains in JS
python3 SubDomainizer.py -u "https://${TARGET}" -o subdomainizer.txt

# 4. Resolve scraped names
puredns resolve scrap_subs.txt -r "$RESOLVERS" -w scrap_subs_resolved.txt
```

---

## Phase 7 — Consolidate and probe live hosts

Merge every source, dedupe, resolve, then web-probe to get the final live set.

```bash
cd "$WORKDIR"

# Horizontal finds (e.g. reverse-DNS / PTR from ASN work, if you did any)
cat horizontal/*.txt 2>/dev/null | sort -u > horizontal.txt

# Vertical passive + active
cat vertical/passive/*.txt vertical/passive.txt | sort -u > vertical/passive_all.txt
cat vertical/active/*.txt   vertical/active.txt  | sort -u > vertical/active_all.txt

# Everything, deduplicated
cat horizontal.txt \
    vertical/passive_all.txt vertical/active_all.txt \
    perms/resolved_perms*.txt \
    scrap/scrap_subs_resolved.txt \
    csp_subdomains.txt tls_names.txt \
  2>/dev/null | sort -u > all_subs.txt

# Final DNS resolution pass (source of truth for "exists")
puredns resolve all_subs.txt -r "$RESOLVERS" -w all_subs_resolved.txt

# Final web probe: which resolved hosts actually serve HTTP(S)
cat all_subs_resolved.txt | httpx -random-agent -retries 2 -no-color \
  -o filtered_subs.txt

echo "[*] Resolved subdomains: $(wc -l < all_subs_resolved.txt)"
echo "[*] Live web hosts:      $(wc -l < filtered_subs.txt)"
```

---

## Output structure

```
subs/<target>/
├── vertical/
│   ├── passive/          # per-tool passive outputs
│   ├── active/           # brute-force outputs
│   ├── passive.txt       # merged passive
│   └── active.txt        # merged active
├── perms/                # permutation outputs
├── scrap/                # crawling / JS scraping outputs
├── horizontal.txt        # PTR / reverse-DNS / ASN finds
├── subdomains.txt        # working merged list (grows across phases)
├── all_subs.txt          # everything, deduped, pre-resolve
├── all_subs_resolved.txt # DNS-valid subdomains (source of truth)
└── filtered_subs.txt     # FINAL: live HTTP(S) hosts
```

## Operating notes

- **`subdomains.txt` is the running list.** Re-merge it after each phase so later phases
  (permutations, scraping, CSP) operate on everything found so far.
- **Always resolve before trusting.** Passive sources return stale/dead names; `puredns`
  and `dnsx` are what confirm a host exists. `filtered_subs.txt` (live web) is usually the
  handoff to the next stage (screenshots, port scan, content discovery).
- **Save the unresolved names.** Names that fail resolution feed the Phase-4 second pass —
  don't discard them.
- **Tokens and configs matter.** subfinder/amass want API keys in their config files;
  github/gitlab-subdomains need a tokens file. Missing tokens means thinner results, not a
  hard failure — but log it in the run ledger (see *Completion rule*); never skip silently.
- **Account for every tool.** Do not finish a run with any source unverified. Each tool must
  end as RAN (non-empty output) or FAILED-with-reason in `run_status.tsv`, and you report
  that summary to the user.
- **Tune to scope.** For a single in-scope root, you may skip recursive (Phase 3) and
  relationship (Phase 5) pivots, which tend to pull in out-of-scope siblings.
