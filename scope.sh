#!/usr/bin/env bash
# ============================================================================
#  RECON v2.0 — Full Reconnaissance & Vulnerability Assessment
#  Dev    : KaguraV01d
#  Github : https://github.com/Fairuz-Ardion
#  Note   : Only use on targets you have explicit WRITTEN permission to test.
# ============================================================================
# Architecture:
#   - Each module is isolated and testable (TDD-friendly)
#   - Vuln scanning uses dedicated tools per category.
#   - Parallel execution with controlled job queues
#   - Strict timeouts to prevent hanging
# ============================================================================

# set -e disabled: grep returning no match (exit 1) would kill script
set -uo pipefail

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
CYAN='\033[0;36m';   BLUE='\033[0;34m';    MAGENTA='\033[0;35m'
WHITE='\033[1;37m';  DIM='\033[2m';        BOLD='\033[1m';  NC='\033[0m'

# ─── GLOBALS ─────────────────────────────────────────────────────────────────
DOMAIN=""
THREADS=50
RATE_LIMIT=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=""
ERROR_LOG=""
ERROR_COUNT=0
START_TIME=0
MAX_PARALLEL_JOBS=8          # max background jobs at once
TOOL_TIMEOUT=120             # default per-tool timeout (seconds)
HTTP_TIMEOUT=8               # per-request HTTP timeout
TEST_MODE="${TEST_MODE:-0}"  # set to 1 to run unit tests instead

trap '_cleanup' EXIT
_cleanup() { tput cnorm 2>/dev/null || true; }
tput civis 2>/dev/null || true

# ─── LOGGING ─────────────────────────────────────────────────────────────────
log()   { echo -e "${GREEN}${BOLD} [+]${NC} ${1:-}"; }
info()  { echo -e "${CYAN}${BOLD} [*]${NC} ${1:-}"; }
warn()  { echo -e "${YELLOW}${BOLD} [!]${NC} ${1:-}"; }
err()   { echo -e "${RED}${BOLD} [x]${NC} ${1:-}"; echo "[ERR] $(date +%T) ${1:-}" >> "${ERROR_LOG:-/dev/null}" 2>/dev/null; (( ERROR_COUNT++ )) || true; }
blank() { echo ""; }
ok()    { echo -e "  ${GREEN}${BOLD}[✓]${NC} ${1:-}"; }
fail()  { echo -e "  ${RED}${BOLD}[✗]${NC} ${1:-}"; }
stat()  { printf "  ${DIM}%-38s${NC} ${BOLD}${WHITE}%s${NC}\n" "${1:-}" "${2:-}"; }
div()   { echo -e "${WHITE}  ──────────────────────────────────────────────────────────────${NC}"; }
hdiv()  { echo -e "${BLUE}  ══════════════════════════════════════════════════════════════${NC}"; }

_spinner() {
  local pid="$1" label="$2"
  local -a frames=("  [⠋] " "  [⠙] " "  [⠹] " "  [⠸] " "  [⠼] " "  [⠴] " "  [⠦] " "  [⠧] " "  [⠇] " "  [⠏] ")
  local i=0
  tput cnorm 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${CYAN}${BOLD}%s${NC}${DIM} %s${NC}   " "${frames[$i]}" "${label:-}"
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.08
  done
  printf "\r\033[K"
  tput civis 2>/dev/null || true
  ok "$label"
}

# Run command in background with spinner. Returns 0 always (errors go to log).
_run() {
  local label="$1"; shift
  "$@" 2>>"${ERROR_LOG:-/dev/null}" &
  local pid=$!
  _spinner "$pid" "$label"
  wait "$pid" 2>/dev/null || true
}

# Run with stdout suppressed
_run_silent() {
  local label="$1"; shift
  "$@" >/dev/null 2>>"${ERROR_LOG:-/dev/null}" &
  local pid=$!
  _spinner "$pid" "$label"
  wait "$pid" 2>/dev/null || true
}

# Job queue: limit concurrent background jobs
_job_queue() {
  while (( $(jobs -rp | wc -l) >= MAX_PARALLEL_JOBS )); do sleep 0.2; done
}

section() {
  local title="$1" icon="${2:->>}"
  local full_text="$icon  $title"
  local len=${#full_text}
  echo ""
  echo -ne "  ${WHITE}${BOLD}"
  for ((i=0; i<len; i++)); do echo -ne "${full_text:$i:1}"; sleep 0.02; done
  echo -e "${NC}"
  sleep 0.05
  echo -ne "${BOLD}${BLUE}"
  for ((i=0; i<62; i++)); do echo -ne "━"; sleep 0.003; done
  echo -e "${NC}\n"
}

banner() {
  clear
  tput civis 2>/dev/null || true
  echo -e "${WHITE}${BOLD}"
  cat << 'ART'
 .----. .---.  .----. .----. .----.
{ {__  /  ___}/  {}  \| {}  }| {_  
.-._} }\     }\      /| .--' | {__ 
`----'  `---'  `----' `-'    `----'
ART
  echo -e "${NC}"
  echo -e "  ${CYAN}${BOLD}Dev: KaguraV01d  |  Github: https://github.com/Fairuz-Ardion${NC}"
  echo -e "  ${YELLOW}${BOLD}Use this tool without any ethical considerations may be illegal${NC}"
  blank; blank
}

# ─── HELPERS ─────────────────────────────────────────────────────────────────
check_tool()  { command -v "$1" &>/dev/null; }
count_lines() { [[ -f "$1" ]] && wc -l < "$1" 2>/dev/null || echo 0; }
has_content() { [[ -s "${1:-}" ]]; }

# Safely append to a file with dedup
append_dedup() {
  local src="$1" dst="$2"
  [[ -s "$src" ]] || return 0
  cat "$src" "$dst" 2>/dev/null | sort -u > "${dst}.tmp" && mv "${dst}.tmp" "$dst" || true
}

# Pick first non-empty file from a list
first_nonempty() {
  for f in "$@"; do [[ -s "$f" ]] && echo "$f" && return; done
}

# Ensure URLs have http(s):// prefix
ensure_http() {
  local f="$1"
  if grep -qP '^https?://' "$f" 2>/dev/null; then
    cat "$f"
  else
    sed 's#^#https://#' "$f"
  fi
}

install_go_tool() {
  local name="$1" pkg="$2"
  if ! check_tool "$name"; then
    go install -v "$pkg" &>/dev/null &
    _spinner $! "Installing $name"
    check_tool "$name" && ok "$name installed" || fail "$name install failed"
  else
    ok "$name already present"
  fi
}

validate_domain() {
  local _exit="${TEST_MODE:-0}"; [[ "$_exit" == "1" ]] && _exit="return" || _exit="exit"
  [[ -z "$DOMAIN" ]] && { err "No domain specified. Usage: $0 <domain>"; $_exit 1; return 1; }
  echo "$DOMAIN" | grep -qP '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' \
    || { err "Invalid domain format: $DOMAIN"; $_exit 1; return 1; }
}

setup_workspace() {
  OUTPUT_DIR="Scope_${DOMAIN}_${TIMESTAMP}"
  mkdir -p "$OUTPUT_DIR"/{subdomains,network,http,urls,js,vuln,report}
  ERROR_LOG="${OUTPUT_DIR}/error.log"
  touch "$ERROR_LOG"

  # vuln subdirectories per tool/category
  mkdir -p "$OUTPUT_DIR/vuln"/{xss,sqli,lfi,ssrf,rce,redirect,ssti,xxe,cve,misconfig,secrets,takeover,injection,cloud,auth}

  local files=(
    subdomains/raw.txt     subdomains/permuted.txt  subdomains/alive_perm.txt
    subdomains/all.txt     subdomains/live.txt
    network/ips.txt        network/ports.txt
    http/probed.txt        http/alive.txt            http/200.txt
    http/403.txt           http/redirect.txt
    urls/all.txt           urls/params.txt
    js/urls.txt            js/secrets.txt
    vuln/all.txt           report/summary.txt        report/vulns.txt
  )
  for f in "${files[@]}"; do touch "$OUTPUT_DIR/$f"; done

  blank
  echo -e "${CYAN}${BOLD}  Target    ${NC}: ${WHITE}${BOLD}$DOMAIN${NC}"
  echo -e "${CYAN}${BOLD}  Output    ${NC}: ${WHITE}${BOLD}$OUTPUT_DIR${NC}"
  echo -e "${CYAN}${BOLD}  Threads   ${NC}: ${WHITE}${BOLD}$THREADS${NC}"
  echo -e "${CYAN}${BOLD}  Rate      ${NC}: ${WHITE}${BOLD}${RATE_LIMIT} req/s${NC}"
  echo -e "${CYAN}${BOLD}  Timestamp ${NC}: ${WHITE}${BOLD}$TIMESTAMP${NC}"
  blank
}

confirm() {
  div; blank
  echo -e "  ${YELLOW}${BOLD}WARNING:${NC} Only scan targets you have explicit written authorization for."
  blank
  printf "  ${BOLD}Start recon on ${CYAN}%s${NC}${BOLD}? [y/N]: " "$DOMAIN"
  tput cnorm 2>/dev/null || true
  read -r CONF
  tput civis 2>/dev/null || true
  [[ "$CONF" != "y" && "$CONF" != "Y" ]] && { blank; warn "Aborted."; exit 0; }
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 00 — DEPENDENCY CHECK & INSTALL
# ═════════════════════════════════════════════════════════════════════════════
mod_install() {
  section "DEPENDENCY CHECK" "00"
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

  # Core recon tools (Go)
  install_go_tool subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool alterx      "github.com/projectdiscovery/alterx/cmd/alterx@latest"
  install_go_tool dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  install_go_tool httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  install_go_tool naabu       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  install_go_tool katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
  install_go_tool nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  install_go_tool gau         "github.com/lc/gau/v2/cmd/gau@latest"
  install_go_tool waybackurls "github.com/tomnomnom/waybackurls@latest"
  install_go_tool assetfinder "github.com/tomnomnom/assetfinder@latest"
  install_go_tool dalfox      "github.com/hahwul/dalfox/v2@latest"
  install_go_tool qsreplace   "github.com/tomnomnom/qsreplace@latest"
  install_go_tool gf          "github.com/tomnomnom/gf@latest"
  install_go_tool anew        "github.com/tomnomnom/anew@latest"

  # Python tools check
  for pytool in sqlmap ffuf; do
    check_tool "$pytool" && ok "$pytool present" || warn "$pytool not found (optional)"
  done

  if check_tool nuclei; then
    nuclei -update-templates -silent &>/dev/null &
    _spinner $! "Updating Nuclei templates"
  fi

  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 01 — SUBDOMAIN ENUMERATION (passive, parallel)
# ═════════════════════════════════════════════════════════════════════════════
mod_subfinder() {
  section "SUBDOMAIN ENUMERATION" "01"
  local OUT="$OUTPUT_DIR/subdomains"
  local TMP="$OUT/.tmp_$$"
  mkdir -p "$TMP"

  # Run all passive sources in true parallel
  local pids=()

  # subfinder
  if check_tool subfinder; then
    subfinder -d "$DOMAIN" -all -silent -timeout 30 2>/dev/null \
      | sort -u > "$TMP/subfinder.txt" &
    pids+=($!)
  fi

  # assetfinder
  if check_tool assetfinder; then
    assetfinder --subs-only "$DOMAIN" 2>/dev/null \
      | grep -F ".${DOMAIN}" | sort -u > "$TMP/assetfinder.txt" &
    pids+=($!)
  fi

  # crt.sh
  {
    curl -sf --max-time 20 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
      | jq -r '.[].name_value' 2>/dev/null \
      | sed 's/\*\.//g' | grep -F ".${DOMAIN}" | sort -u > "$TMP/crtsh.txt" || true
  } &
  pids+=($!)

  # OTX
  {
    curl -sf --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" 2>/dev/null \
      | jq -r '.passive_dns[]?.hostname' 2>/dev/null \
      | grep -F ".${DOMAIN}" | sort -u > "$TMP/otx.txt" || true
  } &
  pids+=($!)

  # HackerTarget
  {
    curl -sf --max-time 15 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>/dev/null \
      | cut -d',' -f1 | grep -F ".${DOMAIN}" | sort -u > "$TMP/ht.txt" || true
  } &
  pids+=($!)

  # RapidDNS
  {
    curl -sf --max-time 15 "https://rapiddns.io/subdomain/${DOMAIN}?full=1&down=1" 2>/dev/null \
      | grep -oP "[a-zA-Z0-9._-]+\.${DOMAIN}" | sort -u > "$TMP/rapiddns.txt" || true
  } &
  pids+=($!)

  # Anubis
  {
    curl -sf --max-time 15 "https://jldc.me/anubis/subdomains/${DOMAIN}" 2>/dev/null \
      | jq -r '.[]' 2>/dev/null | grep -F ".${DOMAIN}" | sort -u > "$TMP/anubis.txt" || true
  } &
  pids+=($!)

  # Show spinner while all run
  echo -ne "  ${CYAN}${BOLD}[⟳]${NC}${DIM} Running 7 passive sources in parallel...${NC}"
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  printf "\r\033[K"
  ok "All passive sources complete"

  # Merge everything
  cat "$TMP"/*.txt 2>/dev/null | sort -u > "$OUT/raw.txt" || true
  rm -rf "$TMP"

  blank
  stat "Raw subdomains collected:" "$(count_lines "$OUT/raw.txt")"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 02 — PERMUTATION + DNS PRE-FILTER
# ═════════════════════════════════════════════════════════════════════════════
mod_alterx() {
  section "PERMUTATION + DNS PRE-FILTER" "02"
  local OUT="$OUTPUT_DIR/subdomains"

  if ! has_content "$OUT/raw.txt"; then warn "No subdomains to permute"; return; fi

  if check_tool alterx; then
    alterx -l "$OUT/raw.txt" -silent -timeout 30 2>/dev/null \
      | sort -u > "$OUT/permuted.txt" || true &
    _spinner $! "alterx — generating smart permutations"
    ok "Permutations: $(count_lines "$OUT/permuted.txt")"

    if check_tool dnsx && has_content "$OUT/permuted.txt"; then
      dnsx -l "$OUT/permuted.txt" -a -silent -t "$THREADS" -timeout 5 2>/dev/null \
        | awk '{print $1}' | sort -u > "$OUT/alive_perm.txt" || true &
      _spinner $! "dnsx — resolving permutations"
      ok "Alive: $(count_lines "$OUT/alive_perm.txt") / $(count_lines "$OUT/permuted.txt")"
    else
      cp "$OUT/permuted.txt" "$OUT/alive_perm.txt" 2>/dev/null || true
    fi
  else
    cp "$OUT/raw.txt" "$OUT/alive_perm.txt" 2>/dev/null || true
  fi

  cat "$OUT/raw.txt" "$OUT/alive_perm.txt" 2>/dev/null | sort -u > "$OUT/all.txt" || true

  blank
  stat "Master list total:" "$(count_lines "$OUT/all.txt")"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 03 — DNS RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════
mod_dnsx() {
  section "DNS RESOLUTION" "03"
  local ALL
  ALL=$(first_nonempty "$OUTPUT_DIR/subdomains/all.txt" "$OUTPUT_DIR/subdomains/raw.txt")

  [[ -z "$ALL" ]] && { warn "No subdomains to resolve"; return; }
  check_tool dnsx || { warn "dnsx not found — skipping"; return; }

  # Run IP extraction and live subdomain resolution in parallel
  {
    dnsx -l "$ALL" -a -resp-only -silent -t "$THREADS" -timeout 5 2>/dev/null \
      | sort -u > "$OUTPUT_DIR/network/ips.txt" || true
  } &
  local pid_ip=$!
  _spinner $pid_ip "dnsx — extracting unique IPs"
  wait $pid_ip 2>/dev/null || true

  {
    dnsx -l "$ALL" -silent -t "$THREADS" -timeout 5 2>/dev/null \
      | awk '{print $1}' | sort -u > "$OUTPUT_DIR/subdomains/live.txt" || true
  } &
  local pid_live=$!
  _spinner $pid_live "dnsx — resolving live subdomains"
  wait $pid_live 2>/dev/null || true

  blank
  stat "Unique IPs:"      "$(count_lines "$OUTPUT_DIR/network/ips.txt")"
  stat "Live subdomains:" "$(count_lines "$OUTPUT_DIR/subdomains/live.txt")"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 04 — HTTP PROBING
# ═════════════════════════════════════════════════════════════════════════════
mod_httpx() {
  section "HTTP PROBING" "04"
  local HTTP="$OUTPUT_DIR/http"
  local SRC
  SRC=$(first_nonempty "$OUTPUT_DIR/subdomains/live.txt" \
                        "$OUTPUT_DIR/subdomains/all.txt" \
                        "$OUTPUT_DIR/subdomains/raw.txt")

  [[ -z "$SRC" ]] && { err "No targets for HTTP probing"; return; }
  check_tool httpx || { warn "httpx not found"; return; }

  info "Probing $(count_lines "$SRC") subdomains..."
  blank

  httpx -l "$SRC" \
    -status-code -title -tech-detect -content-length \
    -no-color -follow-redirects \
    -threads "$THREADS" -timeout "$HTTP_TIMEOUT" -silent \
    > "$HTTP/probed.txt" 2>/dev/null &

  _spinner $! "httpx — probing (status + title + tech)"

  # Filter results (|| true: grep exits 1 when no match, safe to ignore)
  awk '{print $1}' "$HTTP/probed.txt" 2>/dev/null | sort -u > "$HTTP/alive.txt" || true
  grep ' \[200\]'       "$HTTP/probed.txt" 2>/dev/null | awk '{print $1}' | sort -u > "$HTTP/200.txt"    || true
  grep ' \[403\]'       "$HTTP/probed.txt" 2>/dev/null | awk '{print $1}' | sort -u > "$HTTP/403.txt"    || true
  grep -E ' \[30[12]\]' "$HTTP/probed.txt" 2>/dev/null | awk '{print $1}' | sort -u > "$HTTP/redirect.txt" || true

  blank
  stat "HTTP alive:"       "$(count_lines "$HTTP/alive.txt")"
  stat "Status 200:"       "$(count_lines "$HTTP/200.txt")"
  stat "Status 403:"       "$(count_lines "$HTTP/403.txt")"
  stat "Redirects 301/302:""$(count_lines "$HTTP/redirect.txt")"
  info "Tech stack: $HTTP/probed.txt"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 05 — PORT SCANNING
# ═════════════════════════════════════════════════════════════════════════════
mod_naabu() {
  section "PORT SCANNING" "05"
  local IPS="$OUTPUT_DIR/network/ips.txt"

  has_content "$IPS" || { warn "No IPs for port scanning"; return; }
  check_tool naabu || { warn "naabu not found"; return; }

  info "Scanning $(count_lines "$IPS") IPs..."
  blank

  timeout $((TOOL_TIMEOUT * 5)) naabu \
    -list "$IPS" \
    -top-ports 1000 \
    -silent -c 200 -rate 5000 \
    > "$OUTPUT_DIR/network/ports.txt" 2>/dev/null &

  _spinner $! "naabu — top-1000 port scan"

  blank
  stat "Open port entries:" "$(count_lines "$OUTPUT_DIR/network/ports.txt")"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 06 — URL COLLECTION (GAU + Wayback + Katana, parallel)
# ═════════════════════════════════════════════════════════════════════════════
mod_crawl() {
  section "URL COLLECTION" "06"
  local URL_OUT="$OUTPUT_DIR/urls"
  local TMP="$URL_OUT/.tmp_$$"
  mkdir -p "$TMP"

  local SRC
  SRC=$(first_nonempty "$OUTPUT_DIR/http/200.txt" "$OUTPUT_DIR/http/alive.txt" \
                        "$OUTPUT_DIR/subdomains/live.txt" "$OUTPUT_DIR/subdomains/all.txt")

  [[ -z "$SRC" ]] && { warn "No targets for URL collection"; return; }

  # Normalize to https:// URLs
  local TARGET_URLS="$TMP/targets.txt"
  ensure_http "$SRC" | sort -u > "$TARGET_URLS"

  local tc; tc=$(count_lines "$TARGET_URLS")
  info "Collecting URLs from $tc targets..."
  blank

  # GAU — historical archive URLs
  if check_tool gau; then
    {
      while IFS= read -r url; do
        local host; host=$(echo "$url" | grep -oP '(?<=://)([^/:]+)')
        [[ -z "$host" ]] && continue
        timeout 25 gau "$host" \
          --threads 3 \
          --blacklist png,jpg,gif,css,woff,woff2,ttf,svg,ico,eot,mp4,mp3,pdf \
          2>/dev/null | head -2000 >> "$TMP/gau.txt" || true
      done < "$TARGET_URLS"
    } &
    local pid_gau=$!
    _spinner $pid_gau "GAU — historical URLs"
  fi

  # Waybackurls
  if check_tool waybackurls; then
    {
      while IFS= read -r url; do
        local host; host=$(echo "$url" | grep -oP '(?<=://)([^/:]+)')
        [[ -z "$host" ]] && continue
        echo "$host" | timeout 20 waybackurls 2>/dev/null | head -2000 >> "$TMP/wayback.txt" || true
      done < "$TARGET_URLS"
    } &
    local pid_wb=$!
    _spinner $pid_wb "waybackurls — archived URLs"
  fi

  # Katana — active JS-aware crawl
  if check_tool katana; then
    timeout $((TOOL_TIMEOUT * 2)) katana \
      -list "$TARGET_URLS" \
      -silent -jc -d 3 \
      -c "$THREADS" \
      -aff -f qurl \
      -timeout "$HTTP_TIMEOUT" \
      2>/dev/null > "$TMP/katana.txt" || true &
    local pid_kat=$!
    _spinner $pid_kat "katana — active JS-aware crawl"
  fi

  # Wait for all crawlers
  wait "${pid_gau:-}" "${pid_wb:-}" "${pid_kat:-}" 2>/dev/null || true

  # Smart dedup merge
  {
    cat "$TMP"/*.txt 2>/dev/null \
      | grep -E "^https?://" \
      | grep -v '\.(png|jpg|gif|css|woff|ttf|svg|ico|eot|mp4|mp3|pdf)(\?|$)' \
      | sort -u > "$URL_OUT/all.txt" || true

    grep -E '\?[^=]+=.' "$URL_OUT/all.txt" 2>/dev/null \
      | sort -u > "$URL_OUT/params.txt" || true
  }

  rm -rf "$TMP"
  blank
  stat "Total URLs:"        "$(count_lines "$URL_OUT/all.txt")"
  stat "Parameterized URLs:""$(count_lines "$URL_OUT/params.txt")"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 07 — JAVASCRIPT ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════
mod_js() {
  section "JAVASCRIPT ANALYSIS" "07"
  local JS="$OUTPUT_DIR/js"

  local SRC
  SRC=$(first_nonempty "$OUTPUT_DIR/http/200.txt" "$OUTPUT_DIR/http/alive.txt" \
                        "$OUTPUT_DIR/subdomains/live.txt")
  [[ -z "$SRC" ]] && { warn "No targets for JS analysis"; return; }

  local TARGET_URLS; TARGET_URLS=$(mktemp)
  ensure_http "$SRC" | sort -u > "$TARGET_URLS"

  # ── Extract JS URLs ───────────────────────────────────────────────────────
  {
    while IFS= read -r url; do
      local content; content=$(curl -skL --max-time 6 "$url" 2>/dev/null) || continue
      echo "$content" \
        | grep -oP '(?:src|href)\s*=\s*["\x27]\K[^"\x27>]+\.js[^"\x27>]*' \
        2>/dev/null \
        | while read -r js; do
            if   [[ "$js" == http* ]]; then echo "$js"
            elif [[ "$js" == //*  ]]; then echo "https:$js"
            else echo "${url%/}/${js#/}"
            fi
          done
    done < "$TARGET_URLS" 2>/dev/null | sort -u > "$JS/urls.txt" || true
  } &
  _spinner $! "Extracting JS file URLs"
  ok "JS URLs: $(count_lines "$JS/urls.txt")"

  # ── Secret Scanning ───────────────────────────────────────────────────────
  > "$JS/secrets.txt"

  declare -A PATTERNS=(
    ["AWS_Access_Key"]="AKIA[0-9A-Z]{16}"
    ["AWS_Secret_Key"]="(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"
    ["GitHub_PAT"]="ghp_[A-Za-z0-9]{36}"
    ["GitHub_OAuth"]="gho_[A-Za-z0-9]{36}"
    ["Slack_Token"]="xox[baprs]-[0-9A-Za-z]{10,48}"
    ["Google_API"]="AIza[0-9A-Za-z_\\-]{35}"
    ["Firebase"]="AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
    ["JWT"]="eyJ[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{5,}"
    ["Stripe_Live"]="sk_live_[0-9a-zA-Z]{24,}"
    ["Stripe_Test"]="sk_test_[0-9a-zA-Z]{24,}"
    ["SendGrid"]="SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
    ["Mailgun"]="key-[0-9a-zA-Z]{32}"
    ["Twilio_SID"]="AC[a-f0-9]{32}"
    ["Twilio_Token"]="SK[a-f0-9]{32}"
    ["HerokuAPI"]="[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
    ["MongoDB_URI"]="mongodb(\+srv)?://[^\\s'\"<>]+"
    ["Private_Key"]="-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"
    ["Generic_Secret"]="(?i)(secret|password|passwd|api_key|apikey|token)\s*[=:]\s*['\"][A-Za-z0-9+/=_\-]{8,64}['\"]"
  )

  scan_js_file() {
    local jsurl="$1"
    local outfile="$2"
    local content; content=$(curl -skL --max-time 8 "$jsurl" 2>/dev/null) || return
    [[ ${#content} -lt 10 ]] && return

    # Pass pattern names and values via args to avoid subshell export issues
    local name pat
    while IFS='=' read -r name pat; do
      echo "$content" | grep -oiP "$pat" 2>/dev/null | head -2 | while read -r match; do
        [[ -n "$match" ]] && echo "[$name] ($jsurl) => ${match:0:120}" >> "$outfile"
      done
    done
  }

  # Export for xargs
  export -f scan_js_file

  if has_content "$JS/urls.txt"; then
    local pat_file; pat_file=$(mktemp)
    for name in "${!PATTERNS[@]}"; do
      echo "${name}=${PATTERNS[$name]}" >> "$pat_file"
    done

    {
      head -100 "$JS/urls.txt" | while IFS= read -r jsurl; do
        local content; content=$(curl -skL --max-time 8 "$jsurl" 2>/dev/null) || continue
        [[ ${#content} -lt 10 ]] && continue
        while IFS='=' read -r name pat; do
          echo "$content" | grep -oiP "${pat}" 2>/dev/null | head -2 | while read -r match; do
            [[ -n "$match" ]] && echo "[$name] ($jsurl) => ${match:0:120}" >> "$JS/secrets.txt"
          done
        done < "$pat_file"
      done
      rm -f "$pat_file"
    } &
    _spinner $! "Scanning JS files for secrets (top 100)"
  fi

  rm -f "$TARGET_URLS"
  blank
  stat "JS files found:"    "$(count_lines "$JS/urls.txt")"
  stat "Potential secrets:"  "$(count_lines "$JS/secrets.txt")"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 08 — WEB VULNERABILITY SCANNING
#
# Strategy: Use the BEST dedicated tool per vuln category
#   XSS         → dalfox (purpose-built XSS scanner)
#   SQLi        → sqlmap (industry standard)
#   LFI/Open-r  → gf patterns + httpx/nuclei
#   SSRF        → nuclei ssrf templates
#   RCE/CVE     → nuclei cve templates
#   Misconfig   → nuclei misconfig + httpx
#   Takeover    → subjack / nuclei takeover
#   Secrets     → JS analysis (mod_js)
#   Headers     → nuclei + httpx
# ═════════════════════════════════════════════════════════════════════════════

# Helper: run nuclei for a specific category
_nuclei_scan() {
  local label="$1" target="$2" out="$3"; shift 3
  has_content "$target" || { warn "No targets for $label"; return; }
  check_tool nuclei || return

  local _npid
  timeout $((TOOL_TIMEOUT * 2)) nuclei \
    -l "$target" -silent -no-color \
    -rl "$RATE_LIMIT" -c 20 \
    -timeout 10 -retries 1 \
    "$@" \
    -o "$out" 2>/dev/null &
  _npid=$!
  _spinner $_npid "nuclei — $label"
  wait $_npid 2>/dev/null || true
  ok "$label: $(count_lines "$out") findings"
}

# ── XSS: dalfox (primary) + nuclei (fallback) ────────────────────────────────
vuln_xss() {
  local V="$OUTPUT_DIR/vuln/xss"
  local PARAMS
  PARAMS=$(first_nonempty "$OUTPUT_DIR/urls/params.txt" "$OUTPUT_DIR/http/200.txt")
  [[ -z "$PARAMS" ]] && { warn "No param targets for XSS"; return; }

  if check_tool dalfox; then
    timeout $((TOOL_TIMEOUT * 3)) dalfox file "$PARAMS" \
      --silence --no-color \
      --worker "$THREADS" \
      --timeout "$HTTP_TIMEOUT" \
      --output "$V/dalfox.txt" \
      2>/dev/null &
    local _dpid=$!
    _spinner $_dpid "dalfox — XSS (active, context-aware)"
    wait $_dpid 2>/dev/null || true
    ok "dalfox XSS: $(count_lines "$V/dalfox.txt") findings"
  fi

  # Nuclei XSS as supplemental
  _nuclei_scan "XSS templates" "$PARAMS" "$V/nuclei_xss.txt" -tags xss

  cat "$V"/dalfox.txt "$V"/nuclei_xss.txt 2>/dev/null | sort -u > "$V/all.txt"
}

# ── SQLi: sqlmap on parameterized URLs ───────────────────────────────────────
vuln_sqli() {
  local V="$OUTPUT_DIR/vuln/sqli"

  if ! has_content "$OUTPUT_DIR/urls/params.txt"; then
    warn "No parameterized URLs for SQLi testing"; return
  fi

  if check_tool sqlmap; then
    {
      head -50 "$OUTPUT_DIR/urls/params.txt" | while IFS= read -r url; do
        timeout 30 sqlmap -u "$url" \
          --batch --random-agent --level=1 --risk=1 \
          --threads=5 --timeout=10 \
          --output-dir="$V/sqlmap_out" \
          --no-logging -q 2>/dev/null | grep -i "injectable\|vulnerable" >> "$V/sqlmap.txt" || true
      done
    } &
    local _spid=$!
    _spinner $_spid "sqlmap — SQLi detection (top 50 params)"
    wait $_spid 2>/dev/null || true
    ok "sqlmap: $(count_lines "$V/sqlmap.txt") findings"
  else
    warn "sqlmap not found — using nuclei SQLi templates"
  fi

  # Nuclei SQLi templates always run
  _nuclei_scan "SQLi templates" "$OUTPUT_DIR/urls/params.txt" "$V/nuclei_sqli.txt" \
    -tags sqli,sql-injection

  cat "$V"/sqlmap.txt "$V"/nuclei_sqli.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── LFI / Path Traversal ─────────────────────────────────────────────────────
vuln_lfi() {
  local V="$OUTPUT_DIR/vuln/lfi"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/urls/params.txt" "$OUTPUT_DIR/http/200.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for LFI"; return; }

  # GF patterns for LFI-suspicious params, then nuclei
  if check_tool gf && has_content "$OUTPUT_DIR/urls/all.txt"; then
    gf lfi "$OUTPUT_DIR/urls/all.txt" 2>/dev/null | sort -u > "$V/gf_lfi.txt" || true
    local lfi_in
    lfi_in=$(first_nonempty "$V/gf_lfi.txt" "$TARGET")
    _nuclei_scan "LFI/Path Traversal" "$lfi_in" "$V/nuclei_lfi.txt" \
      -tags lfi,path-traversal
  else
    _nuclei_scan "LFI/Path Traversal" "$TARGET" "$V/nuclei_lfi.txt" \
      -tags lfi,path-traversal
  fi

  cat "$V"/gf_lfi.txt "$V"/nuclei_lfi.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── SSRF ─────────────────────────────────────────────────────────────────────
vuln_ssrf() {
  local V="$OUTPUT_DIR/vuln/ssrf"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/urls/params.txt")
  [[ -z "$TARGET" ]] && { warn "No param targets for SSRF"; return; }

  if check_tool gf; then
    gf ssrf "$OUTPUT_DIR/urls/all.txt" 2>/dev/null | sort -u > "$V/gf_ssrf.txt" || true
  fi

  _nuclei_scan "SSRF" "${TARGET}" "$V/nuclei_ssrf.txt" -tags ssrf

  cat "$V"/gf_ssrf.txt "$V"/nuclei_ssrf.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── Open Redirect ─────────────────────────────────────────────────────────────
vuln_redirect() {
  local V="$OUTPUT_DIR/vuln/redirect"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/urls/params.txt" "$OUTPUT_DIR/http/200.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for redirect check"; return; }

  if check_tool gf && has_content "$OUTPUT_DIR/urls/all.txt"; then
    gf redirect "$OUTPUT_DIR/urls/all.txt" 2>/dev/null | sort -u > "$V/gf_redirect.txt" || true
  fi

  _nuclei_scan "Open Redirect" "$TARGET" "$V/nuclei_redirect.txt" \
    -tags redirect,open-redirect

  cat "$V"/gf_redirect.txt "$V"/nuclei_redirect.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── SSTI ─────────────────────────────────────────────────────────────────────
vuln_ssti() {
  local V="$OUTPUT_DIR/vuln/ssti"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/urls/params.txt" "$OUTPUT_DIR/http/200.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for SSTI"; return; }

  if check_tool gf; then
    gf ssti "$OUTPUT_DIR/urls/all.txt" 2>/dev/null | sort -u > "$V/gf_ssti.txt" || true
  fi

  _nuclei_scan "SSTI" "$TARGET" "$V/nuclei_ssti.txt" -tags ssti

  cat "$V"/gf_ssti.txt "$V"/nuclei_ssti.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── RCE / XXE ────────────────────────────────────────────────────────────────
vuln_rce_xxe() {
  local VR="$OUTPUT_DIR/vuln/rce" VX="$OUTPUT_DIR/vuln/xxe"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/http/200.txt" "$OUTPUT_DIR/http/alive.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for RCE/XXE"; return; }

  _nuclei_scan "RCE"            "$TARGET" "$VR/nuclei_rce.txt" -tags rce
  _nuclei_scan "XXE"            "$TARGET" "$VX/nuclei_xxe.txt" -tags xxe
  _nuclei_scan "Log4Shell/Spring" "$TARGET" "$VR/injection.txt" -tags log4j,spring,injection

  cat "$VR"/nuclei_rce.txt "$VR"/injection.txt 2>/dev/null | sort -u > "$VR/all.txt" 2>/dev/null || true
  cp "$VX/nuclei_xxe.txt" "$VX/all.txt" 2>/dev/null || true
}

# ── CVE Scanning ─────────────────────────────────────────────────────────────
vuln_cve() {
  local V="$OUTPUT_DIR/vuln/cve"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/http/200.txt" "$OUTPUT_DIR/http/alive.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for CVE scan"; return; }

  # Critical/High first (faster, higher signal)
  _nuclei_scan "CVE Critical/High" "$TARGET" "$V/critical_high.txt" \
    -tags cve -severity critical,high

  # Medium/Low separately
  _nuclei_scan "CVE Medium/Low" "$TARGET" "$V/med_low.txt" \
    -tags cve -severity medium,low

  cat "$V"/critical_high.txt "$V"/med_low.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── Misconfiguration & Exposure ───────────────────────────────────────────────
vuln_misconfig() {
  local VM="$OUTPUT_DIR/vuln/misconfig"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/http/200.txt" "$OUTPUT_DIR/http/alive.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for misconfig scan"; return; }

  _nuclei_scan "Misconfiguration"    "$TARGET" "$VM/misconfig.txt"   -tags misconfig
  _nuclei_scan "Exposure/Info Leak"  "$TARGET" "$VM/exposure.txt"    -tags exposure,token,backup
  _nuclei_scan "Default Credentials" "$TARGET" "$VM/default_creds.txt" -tags default-login,default-credentials
  _nuclei_scan "Auth Bypass"         "$TARGET" "$VM/auth_bypass.txt" -tags auth-bypass
  _nuclei_scan "SSL/TLS Issues"      "$TARGET" "$VM/ssl_tls.txt"     -tags ssl,tls

  cat "$VM"/*.txt 2>/dev/null | sort -u > "$VM/all.txt" 2>/dev/null || true
}

# ── Subdomain Takeover ────────────────────────────────────────────────────────
vuln_takeover() {
  local V="$OUTPUT_DIR/vuln/takeover"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/subdomains/live.txt" "$OUTPUT_DIR/subdomains/all.txt")
  [[ -z "$TARGET" ]] && { warn "No subdomains for takeover check"; return; }

  # subjack if available
  if check_tool subjack; then
    timeout $((TOOL_TIMEOUT * 2)) subjack \
      -w "$TARGET" -t "$THREADS" -timeout 10 \
      -o "$V/subjack.txt" -ssl 2>/dev/null &
    local _sjpid=$!
    _spinner $_sjpid "subjack — subdomain takeover check"
    wait $_sjpid 2>/dev/null || true
    ok "subjack: $(count_lines "$V/subjack.txt") findings"
  fi

  # nuclei takeover templates
  local http_subs; http_subs=$(mktemp)
  ensure_http "$TARGET" > "$http_subs"
  _nuclei_scan "Subdomain Takeover" "$http_subs" "$V/nuclei_takeover.txt" \
    -tags takeover,subdomain-takeover
  rm -f "$http_subs"

  cat "$V"/subjack.txt "$V"/nuclei_takeover.txt 2>/dev/null | sort -u > "$V/all.txt" 2>/dev/null || true
}

# ── Cloud / Bucket Misconfigurations ─────────────────────────────────────────
vuln_cloud() {
  local V="$OUTPUT_DIR/vuln/cloud"
  local TARGET
  TARGET=$(first_nonempty "$OUTPUT_DIR/http/200.txt" "$OUTPUT_DIR/http/alive.txt")
  [[ -z "$TARGET" ]] && { warn "No targets for cloud scan"; return; }

  _nuclei_scan "Cloud/Bucket/S3" "$TARGET" "$V/nuclei_cloud.txt" \
    -tags cloud,s3,aws,gcp,azure,firebase,bucket

  cp "$V/nuclei_cloud.txt" "$V/all.txt" 2>/dev/null || true
}

# ── MAIN VULN MODULE ORCHESTRATOR ─────────────────────────────────────────────
mod_vuln() {
  section "VULNERABILITY SCANNING" "08"
  local V="$OUTPUT_DIR/vuln"
  local N="$OUTPUT_DIR/nuclei"  # legacy compat dir
  mkdir -p "$N" 2>/dev/null || true

  info "Running dedicated tools per vulnerability class..."
  blank

  echo -e "  ${BOLD}${WHITE}[A] Injection & Input Handling${NC}"; div
  vuln_xss
  vuln_sqli
  vuln_lfi
  vuln_ssrf
  vuln_ssti
  vuln_rce_xxe
  vuln_redirect
  blank

  echo -e "  ${BOLD}${WHITE}[B] CVE Scanning${NC}"; div
  vuln_cve
  blank

  echo -e "  ${BOLD}${WHITE}[C] Configuration & Auth${NC}"; div
  vuln_misconfig
  blank

  echo -e "  ${BOLD}${WHITE}[D] Takeover & Cloud${NC}"; div
  vuln_takeover
  vuln_cloud
  blank

  # Aggregate all findings
  {
    find "$V" -name "*.txt" ! -name "all.txt" -exec cat {} \; 2>/dev/null \
      | grep -v '^$' | sort -u > "$V/all.txt" || true
  }

  # Summary
  blank
  echo -e "  ${BOLD}${WHITE}Vulnerability Summary:${NC}"; div
  stat "  XSS:"                "$(count_lines "$V/xss/all.txt")"
  stat "  SQL Injection:"      "$(count_lines "$V/sqli/all.txt")"
  stat "  LFI/Path Traversal:" "$(count_lines "$V/lfi/all.txt")"
  stat "  SSRF:"               "$(count_lines "$V/ssrf/all.txt")"
  stat "  SSTI:"               "$(count_lines "$V/ssti/all.txt")"
  stat "  RCE:"                "$(count_lines "$V/rce/all.txt")"
  stat "  XXE:"                "$(count_lines "$V/xxe/all.txt")"
  stat "  Open Redirect:"      "$(count_lines "$V/redirect/all.txt")"
  stat "  CVE (Crit/High):"    "$(count_lines "$V/cve/critical_high.txt")"
  stat "  CVE (All):"          "$(count_lines "$V/cve/all.txt")"
  stat "  Misconfiguration:"   "$(count_lines "$V/misconfig/all.txt")"
  stat "  Subdomain Takeover:" "$(count_lines "$V/takeover/all.txt")"
  stat "  Cloud/Bucket:"       "$(count_lines "$V/cloud/all.txt")"
  div
  local total; total=$(count_lines "$V/all.txt")
  echo -e "  ${BOLD}${RED}  TOTAL FINDINGS: ${total}${NC}"
  blank

  if (( total > 0 )); then
    echo -e "${RED}${BOLD}  ┌─────────────────────────────────────────────────────────┐"
    echo -e "  │  !! VULNERABILITIES FOUND — check $V/"
    echo -e "  └─────────────────────────────────────────────────────────┘${NC}"
    blank
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE 09 — REPORT
# ═════════════════════════════════════════════════════════════════════════════
mod_report() {
  section "GENERATING FINAL REPORT" "09"
  local RPT="$OUTPUT_DIR/report/summary.txt"
  local VRPT="$OUTPUT_DIR/report/vulns.txt"
  local V="$OUTPUT_DIR/vuln"
  local ELAPSED=$(( $(date +%s) - START_TIME ))
  local MINS=$(( ELAPSED / 60 ))
  local SECS=$(( ELAPSED % 60 ))

  {
    echo "=================================================================="
    echo "            SCOPE REPORT :: ${DOMAIN}"
    echo "=================================================================="
    echo "Date       : $(date)"
    echo "Duration   : ${MINS}m ${SECS}s"
    echo "Output Dir : $OUTPUT_DIR"
    echo "Errors     : $ERROR_COUNT"
    echo ""
    echo "── SUBDOMAIN STATS ──────────────────────────────────────────────"
    echo "  Raw collected         : $(count_lines "$OUTPUT_DIR/subdomains/raw.txt")"
    echo "  Permutations          : $(count_lines "$OUTPUT_DIR/subdomains/permuted.txt")"
    echo "  Alive permuted        : $(count_lines "$OUTPUT_DIR/subdomains/alive_perm.txt")"
    echo "  Master list           : $(count_lines "$OUTPUT_DIR/subdomains/all.txt")"
    echo "  DNS-confirmed live    : $(count_lines "$OUTPUT_DIR/subdomains/live.txt")"
    echo ""
    echo "── NETWORK ──────────────────────────────────────────────────────"
    echo "  Unique IPs            : $(count_lines "$OUTPUT_DIR/network/ips.txt")"
    echo "  Open ports            : $(count_lines "$OUTPUT_DIR/network/ports.txt")"
    echo ""
    echo "── HTTP ─────────────────────────────────────────────────────────"
    echo "  HTTP services         : $(count_lines "$OUTPUT_DIR/http/alive.txt")"
    echo "  Status 200            : $(count_lines "$OUTPUT_DIR/http/200.txt")"
    echo "  Status 403            : $(count_lines "$OUTPUT_DIR/http/403.txt")"
    echo "  Crawled URLs          : $(count_lines "$OUTPUT_DIR/urls/all.txt")"
    echo "  Parameterized URLs    : $(count_lines "$OUTPUT_DIR/urls/params.txt")"
    echo "  JS files              : $(count_lines "$OUTPUT_DIR/js/urls.txt")"
    echo "  JS secrets found      : $(count_lines "$OUTPUT_DIR/js/secrets.txt")"
    echo ""
    echo "── VULNERABILITY PATH & FINDINGS (MAKE SURE TO VERIFY THE FINDINGS)─"
    echo "  Tool used per category:"
    echo "  XSS            [dalfox + nuclei]  : $(count_lines "$V/xss/all.txt")"
    echo "  SQL Injection  [sqlmap + nuclei]  : $(count_lines "$V/sqli/all.txt")"
    echo "  LFI/Traversal  [gf + nuclei]      : $(count_lines "$V/lfi/all.txt")"
    echo "  SSRF           [gf + nuclei]      : $(count_lines "$V/ssrf/all.txt")"
    echo "  SSTI           [gf + nuclei]      : $(count_lines "$V/ssti/all.txt")"
    echo "  RCE/Log4j      [nuclei]           : $(count_lines "$V/rce/all.txt")"
    echo "  XXE            [nuclei]           : $(count_lines "$V/xxe/all.txt")"
    echo "  Open Redirect  [gf + nuclei]      : $(count_lines "$V/redirect/all.txt")"
    echo "  CVE Crit/High  [nuclei]           : $(count_lines "$V/cve/critical_high.txt")"
    echo "  CVE All        [nuclei]           : $(count_lines "$V/cve/all.txt")"
    echo "  Misconfig/Auth [nuclei]           : $(count_lines "$V/misconfig/all.txt")"
    echo "  Subdomain Tkover [subjack+nuclei] : $(count_lines "$V/takeover/all.txt")"
    echo "  Cloud/Bucket   [nuclei]           : $(count_lines "$V/cloud/all.txt")"
    echo ""
    echo "  TOTAL FINDINGS        : $(count_lines "$V/all.txt")"
    echo ""
    [[ -s "$V/rce/all.txt" ]] && {
      echo "── RCE FINDINGS (CRITICAL) ──────────────────────────────────"
      cat "$V/rce/all.txt"; echo ""
    }
    [[ -s "$V/cve/critical_high.txt" ]] && {
      echo "── CRITICAL/HIGH CVEs (top 30) ──────────────────────────────"
      head -30 "$V/cve/critical_high.txt"; echo ""
    }
    [[ -s "$V/takeover/all.txt" ]] && {
      echo "── SUBDOMAIN TAKEOVER ────────────────────────────────────────"
      cat "$V/takeover/all.txt"; echo ""
    }
    [[ -s "$OUTPUT_DIR/js/secrets.txt" ]] && {
      echo "── JS SECRETS (top 20) ───────────────────────────────────────"
      head -20 "$OUTPUT_DIR/js/secrets.txt"; echo ""
    }
    echo "── OUTPUT TREE ──────────────────────────────────────────────────"
    echo "  $OUTPUT_DIR/"
    echo "  ├── subdomains/   raw | permuted | alive_perm | all | live"
    echo "  ├── network/      ips | ports"
    echo "  ├── http/         probed | alive | 200 | 403 | redirect"
    echo "  ├── urls/         all | params"
    echo "  ├── js/           urls | secrets"
    echo "  ├── vuln/"
    echo "  │   ├── xss/      dalfox.txt | nuclei_xss.txt | all.txt"
    echo "  │   ├── sqli/     sqlmap.txt | nuclei_sqli.txt | all.txt"
    echo "  │   ├── lfi/      gf_lfi.txt | nuclei_lfi.txt | all.txt"
    echo "  │   ├── ssrf/     gf_ssrf.txt | nuclei_ssrf.txt | all.txt"
    echo "  │   ├── ssti/     gf_ssti.txt | nuclei_ssti.txt | all.txt"
    echo "  │   ├── rce/      nuclei_rce.txt | injection.txt | all.txt"
    echo "  │   ├── xxe/      nuclei_xxe.txt | all.txt"
    echo "  │   ├── redirect/ gf_redirect.txt | nuclei_redirect.txt | all.txt"
    echo "  │   ├── cve/      critical_high.txt | med_low.txt | all.txt"
    echo "  │   ├── misconfig/misconfig.txt | exposure.txt | default_creds.txt"
    echo "  │   ├── takeover/ subjack.txt | nuclei_takeover.txt | all.txt"
    echo "  │   ├── cloud/    nuclei_cloud.txt | all.txt"
    echo "  │   └── all.txt   (aggregated)"
    echo "  └── report/       summary.txt | vulns.txt"
    echo "=================================================================="
  } > "$RPT"
  ok "Summary: $RPT"

  # Detailed vuln report
  {
    echo "=================================================================="
    echo "      VULNERABILITY DETAIL REPORT :: ${DOMAIN}"
    echo "=================================================================="
    for pair in \
      "vuln/rce/all.txt:RCE — CRITICAL" \
      "vuln/cve/critical_high.txt:CVE Critical/High" \
      "vuln/takeover/all.txt:Subdomain Takeover" \
      "vuln/misconfig/default_creds.txt:Default Credentials" \
      "vuln/misconfig/auth_bypass.txt:Auth Bypass" \
      "vuln/xss/all.txt:XSS" \
      "vuln/sqli/all.txt:SQL Injection" \
      "vuln/lfi/all.txt:LFI/Path Traversal" \
      "vuln/ssrf/all.txt:SSRF" \
      "vuln/ssti/all.txt:SSTI" \
      "vuln/xxe/all.txt:XXE" \
      "vuln/redirect/all.txt:Open Redirect" \
      "vuln/cve/all.txt:CVE All" \
      "vuln/misconfig/all.txt:Misconfiguration/Exposure" \
      "vuln/cloud/all.txt:Cloud/Bucket" \
      "js/secrets.txt:JS Secrets"; do
      local file="${pair%%:*}" label="${pair##*:}"
      [[ -s "$OUTPUT_DIR/$file" ]] && {
        echo ""
        echo "[${label}]"
        echo "──────────────────────────────────────────"
        cat "$OUTPUT_DIR/$file"
      }
    done
  } > "$VRPT"
  ok "Vulns:   $VRPT"
  blank
}

# ═════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
final_summary() {
  local ELAPSED=$(( $(date +%s) - START_TIME ))
  local MINS=$(( ELAPSED / 60 ))
  local SECS=$(( ELAPSED % 60 ))
  local V="$OUTPUT_DIR/vuln"

  blank
  echo -e "${GREEN}${BOLD}"
  cat << 'DONEART'
  __   __    __      ____   __   __ _  ____ 
 / _\ (  )  (  )    (    \ /  \ (  ( \(  __)
/    \/ (_/\/ (_/\   ) D ((  O )/    / ) _) 
\_/\_/\____/\____/  (____/ \__/ \_)__)(____)
DONEART
  echo -e "${NC}"

  hdiv
  echo -e "  ${CYAN}${BOLD}Target   ${NC}: ${WHITE}$DOMAIN${NC}"
  echo -e "  ${CYAN}${BOLD}Duration ${NC}: ${WHITE}${MINS}m ${SECS}s${NC}"
  echo -e "  ${CYAN}${BOLD}Output   ${NC}: ${WHITE}$OUTPUT_DIR${NC}"
  echo -e "  ${CYAN}${BOLD}Errors   ${NC}: ${WHITE}$ERROR_COUNT${NC}"
  hdiv; blank

  echo -e "  ${BOLD}${WHITE}SUBDOMAIN STATS:${NC}"; div
  stat "  Raw collected:"      "$(count_lines "$OUTPUT_DIR/subdomains/raw.txt")"
  stat "  Permutations:"       "$(count_lines "$OUTPUT_DIR/subdomains/permuted.txt")"
  stat "  Alive permuted:"     "$(count_lines "$OUTPUT_DIR/subdomains/alive_perm.txt")"
  stat "  Master list:"        "$(count_lines "$OUTPUT_DIR/subdomains/all.txt")"
  stat "  DNS-confirmed live:" "$(count_lines "$OUTPUT_DIR/subdomains/live.txt")"
  blank

  echo -e "  ${BOLD}${WHITE}ASSET OVERVIEW:${NC}"; div
  stat "  Unique IPs:"         "$(count_lines "$OUTPUT_DIR/network/ips.txt")"
  stat "  Open ports:"         "$(count_lines "$OUTPUT_DIR/network/ports.txt")"
  stat "  HTTP alive:"         "$(count_lines "$OUTPUT_DIR/http/alive.txt")"
  stat "  Status-200:"         "$(count_lines "$OUTPUT_DIR/http/200.txt")"
  stat "  Crawled URLs:"       "$(count_lines "$OUTPUT_DIR/urls/all.txt")"
  stat "  Parameterized URLs:" "$(count_lines "$OUTPUT_DIR/urls/params.txt")"
  stat "  JS files:"           "$(count_lines "$OUTPUT_DIR/js/urls.txt")"
  stat "  JS secrets:"         "$(count_lines "$OUTPUT_DIR/js/secrets.txt")"
  blank

  echo -e "  ${BOLD}${WHITE}VULNERABILITY FINDINGS:${NC}"; div
  stat "  XSS (dalfox+nuclei):"        "$(count_lines "$V/xss/all.txt")"
  stat "  SQLi (sqlmap+nuclei):"       "$(count_lines "$V/sqli/all.txt")"
  stat "  LFI/Traversal (gf+nuclei):"  "$(count_lines "$V/lfi/all.txt")"
  stat "  SSRF (gf+nuclei):"           "$(count_lines "$V/ssrf/all.txt")"
  stat "  SSTI (gf+nuclei):"           "$(count_lines "$V/ssti/all.txt")"
  stat "  RCE:"                        "$(count_lines "$V/rce/all.txt")"
  stat "  XXE:"                        "$(count_lines "$V/xxe/all.txt")"
  stat "  Open Redirect (gf+nuclei):"  "$(count_lines "$V/redirect/all.txt")"
  stat "  CVE Critical/High:"          "$(count_lines "$V/cve/critical_high.txt")"
  stat "  CVE All:"                    "$(count_lines "$V/cve/all.txt")"
  stat "  Misconfig/Auth:"             "$(count_lines "$V/misconfig/all.txt")"
  stat "  Subdomain Takeover:"         "$(count_lines "$V/takeover/all.txt")"
  stat "  Cloud/Bucket:"               "$(count_lines "$V/cloud/all.txt")"
  div

  local total; total=$(count_lines "$V/all.txt")
  echo -e "  ${BOLD}${RED}  TOTAL FINDINGS: ${total}${NC}"
  div; blank

  # Critical alerts
  [[ -s "$V/rce/all.txt" ]] && {
    echo -e "${RED}${BOLD}  [!!] RCE DETECTED — immediate action required:${NC}"
    head -3 "$V/rce/all.txt" | while IFS= read -r l; do echo -e "  ${RED}  $l${NC}"; done; blank
  }
  [[ -s "$V/cve/critical_high.txt" ]] && {
    echo -e "${RED}${BOLD}  [!!] CRITICAL/HIGH CVEs:${NC}"
    head -5 "$V/cve/critical_high.txt" | while IFS= read -r l; do echo -e "  ${RED}  $l${NC}"; done; blank
  }
  [[ -s "$V/takeover/all.txt" ]] && {
    echo -e "${MAGENTA}${BOLD}  [!] SUBDOMAIN TAKEOVER possible:${NC}"
    head -3 "$V/takeover/all.txt" | while IFS= read -r l; do echo -e "  ${MAGENTA}  $l${NC}"; done; blank
  }
  [[ -s "$V/misconfig/default_creds.txt" ]] && {
    echo -e "${YELLOW}${BOLD}  [!] DEFAULT CREDENTIALS found:${NC}"
    head -3 "$V/misconfig/default_creds.txt" | while IFS= read -r l; do echo -e "  ${YELLOW}  $l${NC}"; done; blank
  }

  echo -e "  ${DIM}Summary : $OUTPUT_DIR/report/summary.txt${NC}"
  echo -e "  ${DIM}Vulns   : $OUTPUT_DIR/report/vulns.txt${NC}"
  blank
  tput cnorm 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════════════════════════
# MODULE REGISTRY
# ═════════════════════════════════════════════════════════════════════════════
declare -A MOD_FUNCS=(
  [1]="mod_install:00  Dependency Check & Tool Install"
  [2]="mod_subfinder:01  Subdomain Enumeration (7 passive sources, parallel)"
  [3]="mod_alterx:02  Permutation + DNS Pre-filter"
  [4]="mod_dnsx:03  DNS Resolution"
  [5]="mod_httpx:04  HTTP Probing (status + tech detect)"
  [6]="mod_naabu:05  Port Scanning (top-1000)"
  [7]="mod_crawl:06  URL Collection (GAU + Wayback + Katana)"
  [8]="mod_js:07  JavaScript Analysis & Secret Mining"
  [9]="mod_vuln:08  Vulnerability Scanning (per-tool per-category)"
  [10]="mod_report:09  Generate Reports"
)
MOD_ORDER=(1 2 3 4 5 6 7 8 9 10)
SELECTED_MODULES=()

mod_select() {
  section "MODULE SELECTOR" "--"

  local DLG=""
  check_tool whiptail && DLG="whiptail"
  [[ -z "$DLG" ]] && check_tool dialog && DLG="dialog"

  if [[ -n "$DLG" ]]; then
    local opts=()
    for i in "${MOD_ORDER[@]}"; do
      opts+=("$i" "${MOD_FUNCS[$i]#*:}" "ON")
    done
    tput cnorm 2>/dev/null || true
    local raw
    raw=$($DLG --title "Recon Module Selector" \
      --checklist "SPACE=toggle, ENTER=confirm" 22 80 12 "${opts[@]}" 3>&1 1>&2 2>&3)
    local rc=$?
    tput civis 2>/dev/null || true
    clear; banner

    if [[ $rc -ne 0 || -z "$raw" ]]; then
      warn "Using all modules."; SELECTED_MODULES=("${MOD_ORDER[@]}")
    else
      for i in "${MOD_ORDER[@]}"; do
        for sel in $raw; do
          [[ "$(echo "$sel" | tr -d '"')" == "$i" ]] && SELECTED_MODULES+=("$i")
        done
      done
    fi
  else
    local -A checked=()
    for i in "${MOD_ORDER[@]}"; do checked[$i]=1; done

    while true; do
      clear; banner
      echo -e "  ${BOLD}${WHITE}SELECT MODULES${NC}"; div; blank
      for i in "${MOD_ORDER[@]}"; do
        if [[ "${checked[$i]:-0}" == "1" ]]; then
          echo -e "   ${GREEN}${BOLD}[x]${NC} ${WHITE}$i)${NC} ${MOD_FUNCS[$i]#*:}"
        else
          echo -e "   ${DIM}[ ]${NC} ${DIM}$i) ${MOD_FUNCS[$i]#*:}${NC}"
        fi
      done
      blank; div
      echo -e "  ${CYAN}Numbers=toggle  ${BOLD}a${NC}${CYAN}=all  ${BOLD}n${NC}${CYAN}=none  ENTER=confirm${NC}"
      printf "  > "; tput cnorm 2>/dev/null || true
      read -r line; tput civis 2>/dev/null || true
      [[ -z "$line" ]] && break
      case "$line" in
        a|A) for i in "${MOD_ORDER[@]}"; do checked[$i]=1; done ;;
        n|N) for i in "${MOD_ORDER[@]}"; do checked[$i]=0; done ;;
        *)   for tok in $line; do
               [[ -n "${checked[$tok]:-}" ]] && checked[$tok]=$(( 1 - checked[$tok] ))
             done ;;
      esac
    done

    clear; banner
    for i in "${MOD_ORDER[@]}"; do
      [[ "${checked[$i]:-0}" == "1" ]] && SELECTED_MODULES+=("$i")
    done
    [[ ${#SELECTED_MODULES[@]} -eq 0 ]] && {
      warn "Nothing selected — using all."; SELECTED_MODULES=("${MOD_ORDER[@]}")
    }
  fi

  blank
  echo -e "  ${BOLD}${WHITE}Execution order:${NC}"; div
  local n=1
  for tag in "${SELECTED_MODULES[@]}"; do
    [[ -n "${MOD_FUNCS[$tag]:-}" ]] && { stat "  $n." "${MOD_FUNCS[$tag]#*:}"; (( n++ )) || true; }
  done
  blank
}

run_selected_modules() {
  for tag in "${SELECTED_MODULES[@]}"; do
    [[ -z "${MOD_FUNCS[$tag]:-}" ]] && continue
    "${MOD_FUNCS[$tag]%%:*}"
  done
}

# ═════════════════════════════════════════════════════════════════════════════
# UNIT TESTS (TDD)
# Run with: TEST_MODE=1 bash recon.sh
# ═════════════════════════════════════════════════════════════════════════════
run_tests() {
  # Disable set -e inside tests so assertions can fail gracefully
  set +e

  echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${NC}"
  echo -e "${BOLD}${WHITE}  RECON v2.0 — Unit Test Suite${NC}"
  echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"

  local PASS=0 FAIL=0
  local T_DIR; T_DIR=$(mktemp -d)
  ERROR_LOG="$T_DIR/errors.log"

  _t() {
    local name="$1" result="$2" expected="$3"
    if [[ "$result" == "$expected" ]]; then
      echo -e "  ${GREEN}${BOLD}PASS${NC} $name"
      (( PASS++ )) || true
    else
      echo -e "  ${RED}${BOLD}FAIL${NC} $name"
      echo -e "       expected: '${expected}'"
      echo -e "       got:      '${result}'"
      (( FAIL++ )) || true
    fi
  }

  # ── test: validate_domain ─────────────────────────────────────────────────
  echo -e "  ${BLUE}[validate_domain]${NC}"
  DOMAIN="example.com"
  validate_domain 2>/dev/null && _t "valid domain passes" "ok" "ok" || _t "valid domain passes" "fail" "ok"

  DOMAIN="sub.example.co.uk"
  validate_domain 2>/dev/null && _t "multi-label TLD passes" "ok" "ok" || _t "multi-label TLD passes" "fail" "ok"

  DOMAIN="not_a_domain"
  validate_domain 2>/dev/null && _t "invalid domain fails" "ok" "fail" || _t "invalid domain fails (expected)" "ok" "ok"

  DOMAIN="has space.com"
  validate_domain 2>/dev/null && _t "space in domain fails" "ok" "fail" || _t "space in domain fails (expected)" "ok" "ok"

  DOMAIN=""
  validate_domain 2>/dev/null && _t "empty domain fails" "ok" "fail" || _t "empty domain fails (expected)" "ok" "ok"

  # ── test: count_lines ────────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[count_lines]${NC}"
  local tf; tf=$(mktemp)
  printf "a\nb\nc\n" > "$tf"
  _t "count 3 lines"  "$(count_lines "$tf")"       "3"
  _t "count no file"  "$(count_lines "/nonexist")"  "0"
  echo -n "" > "$tf"
  _t "count empty file" "$(count_lines "$tf")"      "0"
  rm -f "$tf"

  # ── test: has_content ────────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[has_content]${NC}"
  local hf; hf=$(mktemp)
  echo "data" > "$hf"
  has_content "$hf" && _t "file with content" "ok" "ok" || _t "file with content" "fail" "ok"
  > "$hf"
  has_content "$hf" && _t "empty file no content" "ok" "fail" || _t "empty file no content (expected)" "ok" "ok"
  has_content "/nonexist" && _t "missing file no content" "ok" "fail" || _t "missing file no content (expected)" "ok" "ok"
  rm -f "$hf"

  # ── test: first_nonempty ─────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[first_nonempty]${NC}"
  local f1; f1=$(mktemp); local f2; f2=$(mktemp)
  echo "hit" > "$f2"
  result=$(first_nonempty "/nonexist" "$f1" "$f2")
  _t "picks first nonempty"  "$result"  "$f2"
  result=$(first_nonempty "/nonexist" "/nonexist2")
  _t "returns empty if none" "$result"  ""
  rm -f "$f1" "$f2"

  # ── test: ensure_http ────────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[ensure_http]${NC}"
  local ef; ef=$(mktemp)
  printf "example.com\nsub.example.com\n" > "$ef"
  local http_out; http_out=$(ensure_http "$ef")
  _t "adds https prefix"    "$(echo "$http_out" | head -1)" "https://example.com"
  printf "https://example.com\nhttp://other.com\n" > "$ef"
  http_out=$(ensure_http "$ef")
  _t "passes through https" "$(echo "$http_out" | head -1)" "https://example.com"
  rm -f "$ef"

  # ── test: append_dedup ───────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[append_dedup]${NC}"
  local src; src=$(mktemp); local dst; dst=$(mktemp)
  printf "a\nb\nc\n" > "$src"
  printf "b\nd\n" > "$dst"
  append_dedup "$src" "$dst"
  local lines; lines=$(count_lines "$dst")
  _t "dedup merge 4 unique lines" "$lines" "4"
  rm -f "$src" "$dst"

  # ── test: check_tool ─────────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[check_tool]${NC}"
  check_tool bash  && _t "bash found"         "ok" "ok" || _t "bash found" "fail" "ok"
  check_tool curl  && _t "curl found"         "ok" "ok" || _t "curl found" "fail" "ok"
  check_tool __nonexistent_xyz__ && \
    _t "nonexistent fails" "ok" "fail" || \
    _t "nonexistent fails (expected)" "ok" "ok"

  # ── test: setup_workspace ────────────────────────────────────────────────
  echo -e "\n  ${BLUE}[setup_workspace]${NC}"
  DOMAIN="test.example.com"
  THREADS=10; RATE_LIMIT=5
  TIMESTAMP="test"
  # setup_workspace computes OUTPUT_DIR from DOMAIN+TIMESTAMP itself
  setup_workspace >/dev/null 2>&1
  _t "output dir created"        "$(test -d "$OUTPUT_DIR" && echo ok)" "ok"
  _t "subdomains dir exists"     "$(test -d "$OUTPUT_DIR/subdomains" && echo ok)" "ok"
  _t "network dir exists"        "$(test -d "$OUTPUT_DIR/network" && echo ok)" "ok"
  _t "http dir exists"           "$(test -d "$OUTPUT_DIR/http" && echo ok)" "ok"
  _t "vuln dir exists"           "$(test -d "$OUTPUT_DIR/vuln" && echo ok)" "ok"
  _t "report dir exists"         "$(test -d "$OUTPUT_DIR/report" && echo ok)" "ok"
  _t "error log created"         "$(test -f "$OUTPUT_DIR/error.log" && echo ok)" "ok"
  _t "subdomains/raw.txt exists" "$(test -f "$OUTPUT_DIR/subdomains/raw.txt" && echo ok)" "ok"

  # ── test: nuclei helper guard ─────────────────────────────────────────────
  echo -e "\n  ${BLUE}[_nuclei_scan guard]${NC}"
  local empty_file; empty_file=$(mktemp)
  local out_file; out_file=$(mktemp)
  _nuclei_scan "empty guard test" "$empty_file" "$out_file" -tags xss 2>/dev/null
  _t "_nuclei_scan skips empty target" "$(count_lines "$out_file")" "0"
  rm -f "$empty_file" "$out_file"

  # ── test: mod_subfinder passive sources ───────────────────────────────────
  echo -e "\n  ${BLUE}[mod_subfinder — offline structure test]${NC}"
  _t "raw.txt writable" "$(test -w "$OUTPUT_DIR/subdomains/raw.txt" && echo ok)" "ok"

  # ── test: vuln directory structure ───────────────────────────────────────
  echo -e "\n  ${BLUE}[vuln directory structure]${NC}"
  for dir in xss sqli lfi ssrf ssti rce xxe redirect cve misconfig secrets takeover cloud auth; do
    _t "vuln/$dir exists" "$(test -d "$OUTPUT_DIR/vuln/$dir" && echo ok || echo missing)" "ok"
  done

  # Cleanup test workspace
  rm -rf "$OUTPUT_DIR" "$T_DIR"

  # ── Results ───────────────────────────────────────────────────────────────
  rm -rf "$T_DIR"
  echo ""
  echo -e "  ${BOLD}${CYAN}════════════════════════════════════════${NC}"
  local total=$(( PASS + FAIL ))
  if (( FAIL == 0 )); then
    echo -e "  ${GREEN}${BOLD}ALL $total TESTS PASSED ✓${NC}"
  else
    echo -e "  ${GREEN}${BOLD}PASSED: $PASS${NC} / ${RED}${BOLD}FAILED: $FAIL${NC} (total: $total)"
  fi
  echo -e "  ${BOLD}${CYAN}════════════════════════════════════════${NC}\n"
  (( FAIL > 0 )) && exit 1 || exit 0
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
main() {
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin

  # Test mode
  if [[ "${TEST_MODE:-0}" == "1" || "${1:-}" == "--test" ]]; then
    run_tests
    exit $?
  fi

  banner

  DOMAIN="${1:-}"
  if [[ -z "$DOMAIN" ]]; then
    tput cnorm 2>/dev/null || true
    printf "  ${CYAN}${BOLD}Enter target domain: ${NC}"
    read -r DOMAIN
    tput civis 2>/dev/null || true
  fi

  validate_domain
  setup_workspace
  mod_select
  confirm
  START_TIME=$(date +%s)

  run_selected_modules
  final_summary
}

main "$@"
