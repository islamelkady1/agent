#!/usr/bin/env bash
# Restore the hunter arsenal into ZCode (or any agent harness using ~/.zcode layout)
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
mkdir -p ~/.zcode/skills ~/.zcode/agents ~/.zcode/skill-library
cp -r "$SRC/skills/."  ~/.zcode/skills/
cp -r "$SRC/agents/."  ~/.zcode/agents/
[ -d "$SRC/library" ] && cp -r "$SRC/library/." ~/.zcode/skill-library/
echo "Done: $(ls ~/.zcode/skills | wc -l) skills, $(ls ~/.zcode/agents/*.md | wc -l) agents installed. Restart your session to load them."
