# Hunter Arsenal — bug bounty skills + agents pack

A portable arsenal of 70 active skills, 66 specialist agents, and a 22-source reference library (~1300 skills) for AI-driven bug bounty hunting. Plain Markdown (`SKILL.md` / agent `.md`) — works with any harness that reads the Claude-style skills format (ZCode, Claude Code, OpenCode, etc.).

## Layout
- `skills/` — active skills (auto-loaded each session)
- `agents/` — specialist subagents (recon, sqli/ssrf/xxe hunters, validator, report-writer, autopilot orchestrator...)
- `library/` — full reference sources (Anthropic cybersecurity, yaklang hack-skills, recon-skills, owasp-hunting payloads, public-skills-builder...)
- `CATALOG.md` — what every source does + combo workflows
- `hunt-router` (inside skills/) — the routing brain: signal → skills chain + specialist agent

## Install (new machine)
```bash
git clone https://github.com/YOU/REPO.git && cd REPO
./install.sh
# restart your agent session
```

## Update flow
Edit skills locally, then commit & push. To re-sync a machine: `git pull && ./install.sh`

## Notes
- Aggregated from public repositories (MIT and similar licenses) for personal hunting use; each source keeps its original license in `library/`.
- Run only against authorized targets. Validate scope before any request.
- `library/` is ~184 MB — delete the folder before your first push if you want a light repo (skills+agents only).
