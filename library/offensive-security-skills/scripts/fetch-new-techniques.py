#!/usr/bin/env python3
"""
fetch-new-techniques.py
Fetches new bug bounty writeups from multiple sources and appends
unique techniques to TECHNIQUES-MASTER.md via Claude API.

Sources:
  - KingOfBugbounty GitHub (README)
  - shahjerry33 Medium RSS
  - lostsec Medium RSS
  - HackerOne Hacktivity (public disclosures)
  - infosecwriteups Medium RSS
  - Pentester.land RSS

Usage:
  pip install anthropic requests feedparser
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 scripts/fetch-new-techniques.py [--dry-run]

GitHub Actions sets ANTHROPIC_API_KEY via repo secret.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
MASTER_FILE = REPO_ROOT / "TECHNIQUES-MASTER.md"
SEEN_FILE = REPO_ROOT / "scripts" / ".seen-hashes.json"
LOG_FILE = REPO_ROOT / "scripts" / "fetch.log"

# ── Sources ──────────────────────────────────────────────────────────────────

SOURCES = [
    {
        "name": "KingOfBugBountyTips",
        "type": "raw",
        "url": "https://raw.githubusercontent.com/KingOfBugbounty/KingOfBugBountyTips/master/README.md",
    },
    {
        "name": "shahjerry33-medium",
        "type": "rss",
        "url": "https://shahjerry33.medium.com/feed",
    },
    {
        "name": "lostsec-medium",
        "type": "rss",
        "url": "https://lostsec.medium.com/feed",
    },
    {
        "name": "infosecwriteups",
        "type": "rss",
        "url": "https://infosecwriteups.com/feed",
    },
    {
        "name": "pentesterland",
        "type": "rss",
        "url": "https://pentester.land/blog/index.xml",
    },
    {
        "name": "hackerone-hacktivity",
        "type": "url",
        "url": "https://hackerone.com/hacktivity?querystring=&filter=type%3Apublic&order_direction=DESC&order_field=latest_disclosable_activity_at",
    },
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "bb-skills-bot/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  [WARN] fetch failed {url}: {e}")
        return ""


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def load_seen() -> set:
    if SEEN_FILE.exists():
        return set(json.loads(SEEN_FILE.read_text()))
    return set()


def save_seen(seen: set):
    SEEN_FILE.write_text(json.dumps(sorted(seen), indent=2))


def parse_rss_items(xml: str) -> list[dict]:
    """Very lightweight RSS parser — no external deps."""
    items = []
    for item in re.findall(r"<item>(.*?)</item>", xml, re.DOTALL):
        title = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", item)
        link  = re.search(r"<link>(.*?)</link>", item)
        desc  = re.search(r"<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>", item, re.DOTALL)
        if title and link:
            items.append({
                "title": title.group(1).strip(),
                "url": link.group(1).strip(),
                "text": re.sub(r"<[^>]+>", " ", (desc.group(1) if desc else ""))[:2000],
            })
    return items


def gather_new_content(seen: set) -> list[dict]:
    """Returns list of {source, title, url, text} for unseen content."""
    new_items = []
    for src in SOURCES:
        print(f"  Fetching {src['name']} …")
        raw = fetch(src["url"])
        if not raw:
            continue

        if src["type"] == "rss":
            items = parse_rss_items(raw)
            for item in items:
                h = content_hash(item["url"])
                if h not in seen:
                    seen.add(h)
                    new_items.append({"source": src["name"], **item})
        else:
            h = content_hash(raw[:500])
            if h not in seen:
                seen.add(h)
                new_items.append({
                    "source": src["name"],
                    "title": src["name"],
                    "url": src["url"],
                    "text": raw[:8000],
                })

    return new_items


# ── Claude extraction ─────────────────────────────────────────────────────────

def extract_techniques_via_claude(items: list[dict]) -> list[dict]:
    """Call Claude API to extract structured techniques from raw content."""
    try:
        import anthropic
    except ImportError:
        print("  [ERROR] pip install anthropic")
        return []

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("  [ERROR] ANTHROPIC_API_KEY not set")
        return []

    client = anthropic.Anthropic(api_key=api_key)

    # Batch items into chunks of max 5 to stay within context
    all_techniques = []
    chunk_size = 5
    for i in range(0, len(items), chunk_size):
        chunk = items[i : i + chunk_size]
        combined = "\n\n---\n\n".join(
            f"SOURCE: {it['source']}\nURL: {it['url']}\nTITLE: {it['title']}\n\n{it['text']}"
            for it in chunk
        )

        prompt = f"""You are a bug bounty expert. Extract unique, actionable vulnerability techniques from the content below.

For each technique return JSON with these fields:
- category: one of [Recon, IDOR/BOLA, SSRF, XSS, SQLi, Authentication, ATO, Business Logic, API Security, GraphQL, CORS, Cloud, Info Disclosure, Automation, JWT, OAuth, File Upload, Header Injection, IP/WAF Bypass, Miscellaneous]
- name: short descriptive name (max 60 chars)
- description: what the technique does (1-2 sentences)
- steps: array of numbered steps
- payload_or_curl: exact command or HTTP request
- impact: what an attacker can achieve
- severity: Critical | High | Medium | Low
- source: URL or source name
- payout: bounty amount if mentioned

Only include techniques that are:
1. Technically specific (not generic advice)
2. Have a concrete reproduction step
3. Are new / not obvious OWASP basics

Return: {{"techniques": [...]}}

CONTENT:
{combined[:12000]}"""

        try:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            text = msg.content[0].text
            # Extract JSON
            m = re.search(r'\{.*"techniques".*\}', text, re.DOTALL)
            if m:
                data = json.loads(m.group())
                techniques = data.get("techniques", [])
                print(f"    Extracted {len(techniques)} techniques from chunk {i//chunk_size + 1}")
                all_techniques.extend(techniques)
        except Exception as e:
            print(f"    [WARN] Claude call failed: {e}")

    return all_techniques


# ── Append to master file ─────────────────────────────────────────────────────

def load_existing_names() -> set:
    """Get all existing technique names for dedup."""
    if not MASTER_FILE.exists():
        return set()
    names = set()
    for line in MASTER_FILE.read_text().splitlines():
        if line.startswith("### "):
            names.add(re.sub(r"[^a-z0-9]", "", line[4:].lower()))
    return names


def append_techniques(techniques: list[dict], dry_run: bool = False) -> int:
    existing = load_existing_names()
    new_techs = []

    for t in techniques:
        key = re.sub(r"[^a-z0-9]", "", (t.get("name") or "").lower())
        if key and key not in existing:
            existing.add(key)
            new_techs.append(t)

    if not new_techs:
        print(f"  No new unique techniques to add.")
        return 0

    print(f"  Adding {len(new_techs)} new techniques to TECHNIQUES-MASTER.md")

    if dry_run:
        for t in new_techs:
            print(f"    [DRY RUN] Would add: {t.get('name')} [{t.get('category')}]")
        return len(new_techs)

    # Group by category and append to relevant sections
    from collections import defaultdict
    by_cat = defaultdict(list)
    for t in new_techs:
        by_cat[t.get("category", "Miscellaneous")].append(t)

    content = MASTER_FILE.read_text()

    for cat, techs in by_cat.items():
        block = "\n"
        for t in techs:
            sev = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(t.get("severity", ""), "⚪")
            block += f"### {t.get('name','Unnamed')}\n\n"
            block += f"{t.get('description','')}\n\n"
            meta = []
            if t.get("severity"): meta.append(f"**Severity:** {sev} {t['severity']}")
            if t.get("payout"):   meta.append(f"**Payout:** {t['payout']}")
            if t.get("source"):   meta.append(f"**Source:** {t['source']}")
            if meta: block += " · ".join(meta) + "\n\n"
            if t.get("steps"):
                block += "**Steps:**\n"
                for i, s in enumerate(t["steps"], 1):
                    block += f"{i}. {s}\n"
                block += "\n"
            if t.get("payload_or_curl"):
                block += f"```bash\n{t['payload_or_curl']}\n```\n\n"
            if t.get("impact"):
                block += f"**Impact:** {t['impact']}\n\n"
            block += "---\n\n"

        # Find the category section and append before next ##
        cat_header = f"## {cat}\n"
        if cat_header in content:
            # Find end of this section (next ## or EOF)
            idx = content.index(cat_header) + len(cat_header)
            next_sec = content.find("\n## ", idx)
            if next_sec == -1:
                content += block
            else:
                content = content[:next_sec] + block + content[next_sec:]
        else:
            # New category — append at end
            content += f"\n## {cat}\n{block}"

    MASTER_FILE.write_text(content)
    return len(new_techs)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Show what would be added without writing")
    parser.add_argument("--force", action="store_true", help="Re-fetch all sources ignoring seen cache")
    args = parser.parse_args()

    print(f"[{datetime.now(timezone.utc).isoformat()}] bb-skills technique fetcher starting")

    seen = set() if args.force else load_seen()
    print(f"  Known hashes: {len(seen)}")

    print("\nGathering new content from sources…")
    new_items = gather_new_content(seen)
    print(f"  New items found: {len(new_items)}")

    if not new_items:
        print("Nothing new. Exiting.")
        save_seen(seen)
        return

    print(f"\nExtracting techniques via Claude ({len(new_items)} items)…")
    techniques = extract_techniques_via_claude(new_items)
    print(f"  Raw techniques extracted: {len(techniques)}")

    print("\nAppending to TECHNIQUES-MASTER.md…")
    added = append_techniques(techniques, dry_run=args.dry_run)

    if not args.dry_run:
        save_seen(seen)

    print(f"\nDone. Added {added} new techniques.")

    # Write log
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "new_items": len(new_items),
            "extracted": len(techniques),
            "added": added,
        }) + "\n")


if __name__ == "__main__":
    main()
