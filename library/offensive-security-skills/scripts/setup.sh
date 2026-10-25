#!/usr/bin/env bash
#
# setup.sh — install the toolchain referenced by skills/osint-pentest.md
#
# Idempotent: only installs what's missing. Safe to re-run.
# Usage:
#   ./scripts/setup.sh           # install all missing tools
#   ./scripts/setup.sh --check   # only report installed/missing, install nothing
#   ./scripts/setup.sh --core    # install just the high-signal recon/exploit set
#
# Targets macOS (Homebrew) and Debian/Ubuntu. GUI tools (Burp, Caido, MobSF
# desktop) and credentialed CLIs (gcloud auth, ipatool login) are noted, not forced.
#
set -uo pipefail

# ---- config ----------------------------------------------------------------
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"          # git-cloned python tools live here
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"         # wrapper scripts go here (put on PATH)
GOBIN="$(go env GOPATH 2>/dev/null)/bin"
MODE="install"
SET="full"

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --core)  SET="core" ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

# ---- helpers ---------------------------------------------------------------
c_ok=$'\033[32m'; c_no=$'\033[31m'; c_hd=$'\033[1;36m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
have(){ command -v "$1" >/dev/null 2>&1; }
hdr(){ printf "\n%s== %s ==%s\n" "$c_hd" "$1" "$c_rst"; }
ok(){  printf "  %s✓%s %s\n" "$c_ok" "$c_rst" "$1"; }
miss(){ printf "  %s✗%s %s%s%s%s\n" "$c_no" "$c_rst" "$1" "$c_dim" "${2:+  → $2}" "$c_rst"; }
note(){ printf "  %s· %s%s\n" "$c_dim" "$1" "$c_rst"; }

OS="$(uname -s)"
PKG=""
if   have brew;    then PKG="brew"
elif have apt-get; then PKG="apt"
fi

brew_i(){ have brew && brew list "$1" >/dev/null 2>&1 || brew install "$@" >/dev/null 2>&1; }
apt_i(){  sudo apt-get install -y "$@" >/dev/null 2>&1; }

# install one system pkg by best available manager
sys_install(){ # sys_install <brew-formula> <apt-pkg>
  case "$PKG" in
    brew) brew install "$1" >/dev/null 2>&1 ;;
    apt)  sudo apt-get install -y "$2" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

# ---- prerequisites ---------------------------------------------------------
hdr "prerequisites"
for p in git curl python3 go; do have "$p" && ok "$p" || miss "$p" "install $p first — required"; done
have pipx || { [ "$MODE" = install ] && { note "installing pipx"; python3 -m pip install --user -q pipx 2>/dev/null; python3 -m pipx ensurepath >/dev/null 2>&1; }; }
have pipx && ok pipx || miss pipx "python3 -m pip install --user pipx"
[ -n "$PKG" ] && ok "pkg manager: $PKG" || miss "pkg manager" "install Homebrew (mac) or use apt (Debian)"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) note "add to shell rc:  export PATH=\"$BIN_DIR:$GOBIN:\$PATH\"" ;; esac

# ---- tool tables -----------------------------------------------------------
# binary | go import path
GO_TOOLS_FULL=(
  "subjs|github.com/lc/subjs@latest"
  "chaos|github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  "puredns|github.com/d3mondev/puredns/v2@latest"
  "shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "mapcidr|github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
  "anew|github.com/tomnomnom/anew@latest"
  "qsreplace|github.com/tomnomnom/qsreplace@latest"
  "sourcemapper|github.com/denandz/sourcemapper@latest"
  "s3scanner|github.com/sa7mon/s3scanner@latest"
  "interactsh-client|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "webanalyze|github.com/rverton/webanalyze/cmd/webanalyze@latest"
)
# kubeletctl: module path != repo path so `go install` fails — built via clone below.
# aquatone: archived, go.mod breaks modern `go install` — gowitness (in base stack) covers screenshots.
GO_TOOLS_CORE=( "anew|" "qsreplace|" "chaos|" "puredns|" "shuffledns|" "mapcidr|" "interactsh-client|" )

# binary | brew formula | apt pkg
SYS_TOOLS=(
  "massdns|massdns|massdns"          # required by puredns/shuffledns
  "masscan|masscan|masscan"
  "rustscan|rustscan|"
  "hashcat|hashcat|hashcat"
  "rabin2|radare2|radare2"           # radare2 provides rabin2 (iOS binary strings)
  "ipatool|ipatool|"
)
# pipx package | resulting command (if different).  ghauri is git-only (not on PyPI).
PIPX_TOOLS=(
  "git+https://github.com/r0oth3x49/ghauri.git|ghauri"
  "dnstwist|dnstwist"
  "scoutsuite|scout"
  "pacu|pacu"
  "clairvoyance|clairvoyance"
  "apkleaks|apkleaks"
  "kube-hunter|kube-hunter"
)
# wrapper-name | git repo | entry script | requirements?
# Each gets its OWN venv (do_git) — system pip is blocked by PEP 668 on Homebrew Python.
GIT_TOOLS=(
  "jwt_tool|https://github.com/ticarpi/jwt_tool|jwt_tool.py|y"
  "linkfinder|https://github.com/GerbenJavado/LinkFinder|linkfinder.py|y"
  "secretfinder|https://github.com/m4ll0k/SecretFinder|SecretFinder.py|y"
  "enumerate-iam|https://github.com/andresriancho/enumerate-iam|enumerate-iam.py|y"
  "gcpbucketbrute|https://github.com/RhinoSecurityLabs/GCPBucketBrute|gcpbucketbrute.py|y"
  "crackql|https://github.com/nicholasaleks/CrackQL|CrackQL.py|y"
  "graphw00f|https://github.com/dolevf/graphw00f|main.py|n"
  "graphql-cop|https://github.com/dolevf/graphql-cop|graphql-cop.py|y"
  "cloud_enum|https://github.com/initstring/cloud_enum|cloud_enum.py|y"
)

# ---- install routines ------------------------------------------------------
do_go(){ local b="${1%%|*}" path="${1#*|}"
  have "$b" && { ok "$b"; return; }
  [ "$MODE" = check ] && { miss "$b" "go install $path"; return; }
  [ -z "$path" ] && { miss "$b" "(core alias — see full list)"; return; }
  note "go install $b"; GOBIN="$GOBIN" go install "$path" >/dev/null 2>&1 && ok "$b" || miss "$b" "go install $path  (failed)"
}
do_sys(){ local b="${1%%|*}" rest="${1#*|}"; local brewf="${rest%%|*}" aptp="${rest#*|}"
  have "$b" && { ok "$b"; return; }
  [ "$MODE" = check ] && { miss "$b" "${PKG:+$PKG} $brewf"; return; }
  note "install $b"; sys_install "$brewf" "$aptp" && ok "$b" || miss "$b" "manual: $brewf"
}
do_pipx(){ local pkg="${1%%|*}" cmd="${1#*|}"
  have "$cmd" && { ok "$cmd"; return; }
  [ "$MODE" = check ] && { miss "$cmd" "pipx install $pkg"; return; }
  note "pipx install $pkg"; pipx install "$pkg" >/dev/null 2>&1 && ok "$cmd" || miss "$cmd" "pipx install $pkg  (failed)"
}
do_git(){ local name="${1%%|*}" rest="${1#*|}"; local repo="${rest%%|*}" rest2="${rest#*|}"; local entry="${rest2%%|*}" req="${rest2##*|}"
  have "$name" && { ok "$name"; return; }
  [ "$MODE" = check ] && { miss "$name" "git clone $repo → wrapper"; return; }
  local dir="$TOOLS_DIR/$name"
  [ -d "$dir/.git" ] || git clone -q --depth 1 "$repo" "$dir" 2>/dev/null
  # per-tool venv — avoids PEP 668 "externally-managed-environment" pip failures
  python3 -m venv "$dir/.venv" 2>/dev/null
  [ "$req" = y ] && [ -f "$dir/requirements.txt" ] && "$dir/.venv/bin/pip" install -q -r "$dir/requirements.txt" 2>/dev/null
  printf '#!/usr/bin/env bash\nexec "%s/.venv/bin/python" "%s/%s" "$@"\n' "$dir" "$dir" "$entry" > "$BIN_DIR/$name"
  chmod +x "$BIN_DIR/$name"
  have "$name" && ok "$name" || miss "$name" "wrapper at $BIN_DIR/$name (ensure on PATH)"
}

# ---- run -------------------------------------------------------------------
hdr "go tools"
if [ "$SET" = core ]; then for t in "${GO_TOOLS_CORE[@]}"; do
    b="${t%%|*}"; for f in "${GO_TOOLS_FULL[@]}"; do [ "${f%%|*}" = "$b" ] && t="$f"; done; do_go "$t"; done
else for t in "${GO_TOOLS_FULL[@]}"; do do_go "$t"; done; fi
# kubeletctl — repo's go.mod declares module "kubeletctl", so `go install <url>` can't
# resolve it. Clone + tidy + build the binary directly into BIN_DIR.
if have kubeletctl; then ok kubeletctl
elif [ "$MODE" = check ]; then miss kubeletctl "git clone cyberark/kubeletctl + go build"
elif [ "$SET" != core ]; then
  d="$TOOLS_DIR/kubeletctl"; [ -d "$d/.git" ] || git clone -q --depth 1 https://github.com/cyberark/kubeletctl "$d" 2>/dev/null
  ( cd "$d" && go mod tidy >/dev/null 2>&1 && go build -o "$BIN_DIR/kubeletctl" . >/dev/null 2>&1 )
  have kubeletctl && ok kubeletctl || miss kubeletctl "cd $TOOLS_DIR/kubeletctl && go mod tidy && go build -o $BIN_DIR/kubeletctl ."
fi

hdr "system packages ($PKG)"
for t in "${SYS_TOOLS[@]}"; do do_sys "$t"; done

hdr "pipx tools (python apps)"
for t in "${PIPX_TOOLS[@]}"; do do_pipx "$t"; done

hdr "git tools (cloned + wrapper in $BIN_DIR)"
for t in "${GIT_TOOLS[@]}"; do do_git "$t"; done

# ---- data: templates, gf patterns, resolvers -------------------------------
hdr "data & patterns"
if [ "$MODE" = install ]; then
  have nuclei && { note "updating nuclei templates"; nuclei -update-templates -silent >/dev/null 2>&1 && ok "nuclei-templates"; }
  if [ ! -d "$HOME/.gf" ] || [ -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]; then
    note "installing gf patterns"; mkdir -p "$HOME/.gf"
    git clone -q --depth 1 https://github.com/tomnomnom/gf "$TOOLS_DIR/gf" 2>/dev/null && cp "$TOOLS_DIR/gf/examples/"*.json "$HOME/.gf/" 2>/dev/null
    git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$TOOLS_DIR/gf-patterns" 2>/dev/null && cp "$TOOLS_DIR/gf-patterns/"*.json "$HOME/.gf/" 2>/dev/null
    ok "gf patterns → ~/.gf"
  else ok "gf patterns (present)"; fi
  if [ ! -f "$TOOLS_DIR/resolvers.txt" ]; then
    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o "$TOOLS_DIR/resolvers.txt" 2>/dev/null && \
      ok "resolvers → $TOOLS_DIR/resolvers.txt (use with puredns/shuffledns -r)"
  else ok "resolvers.txt (present)"; fi
else
  note "nuclei -update-templates ; gf patterns (tomnomnom + 1ndianl33t) ; trickest resolvers"
fi

# ---- manual / credentialed -------------------------------------------------
hdr "manual install (GUI / credentialed / niche)"
have gcloud && ok "gcloud (+gsutil)" || miss "gcloud" "${PKG/apt/apt}; mac: brew install --cask google-cloud-sdk  →  gcloud init"
have apksigner && ok "apksigner" || miss "apksigner" "Android SDK build-tools (brew install --cask android-commandlinetools → sdkmanager 'build-tools;35.0.0')"
have x8 && ok "x8" || miss "x8" "cargo install x8  (needs rust)"
have kr && ok "kiterunner (kr)" || miss "kr" "github.com/assetnote/kiterunner → make build  (or brew install kiterunner)"
have class-dump && ok "class-dump" || miss "class-dump" "brew install --cask class-dump  (iOS ObjC headers)"
have inql && ok "inql" || note "InQL — install via Burp BApp store (GraphQL)"
note "Burp Suite / Caido — GUI, install from portswigger.net / caido.io (see Appendix C)"
note "MobSF — docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
note "ipatool / gcloud / aws / az — run their 'login'/'init' before use"
note "masscan/rustscan — endpoint security (Trend Micro, CrowdStrike, etc.) often QUARANTINES"
note "  these offensive scanners (empty Cellar bin = EDR ate the binary). naabu + nmap"
note "  (already in the base stack) cover the same need without tripping EDR."

# ---- summary ---------------------------------------------------------------
hdr "summary"
total=0; present=0
for t in "${GO_TOOLS_FULL[@]}" "${SYS_TOOLS[@]}"; do b="${t%%|*}"; total=$((total+1)); have "$b" && present=$((present+1)); done
for t in "${PIPX_TOOLS[@]}"; do c="${t#*|}"; total=$((total+1)); have "$c" && present=$((present+1)); done
for t in "${GIT_TOOLS[@]}"; do b="${t%%|*}"; total=$((total+1)); have "$b" && present=$((present+1)); done
printf "  %s/%s gap-filling tools present (the set this script manages).\n" "$present" "$total"
note "your base recon stack (subfinder/httpx/dnsx/nuclei/ffuf/amass/gau/trufflehog…) is checked by the repo README, not here."
[ "$MODE" = check ] && note "run without --check to install the missing ones (or --core for the high-signal subset)."
note "restart your shell (or source rc) so PATH picks up $BIN_DIR and \$GOPATH/bin."
