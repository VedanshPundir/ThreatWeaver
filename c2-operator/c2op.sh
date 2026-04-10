#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║            C2 OPERATOR  —  Interactive Terminal UI               ║
# ╚══════════════════════════════════════════════════════════════════╝

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$SKILL_DIR/run.sh"
DYN="$SKILL_DIR/dynamic.sh"

# ── Colours ──────────────────────────────────────────────────────────
R='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
MAGENTA='\033[95m'
CYAN='\033[96m'
WHITE='\033[97m'

W=72   # box width

# ── Drawing helpers ───────────────────────────────────────────────────
line() { printf "${CYAN}"; printf '═%.0s' $(seq 1 $W); printf "${R}\n"; }
thin() { printf "${CYAN}"; printf '─%.0s' $(seq 1 $W); printf "${R}\n"; }

center_row() {
    local text="$1" color="${2:-$WHITE}"
    local len=${#text}
    local pad=$(( (W - len) / 2 ))
    printf "${CYAN}║${R}%${pad}s${color}${BOLD}${text}${R}%${pad}s${CYAN}║${R}\n" "" ""
}

blank_row() { printf "${CYAN}║${R}%${W}s${CYAN}║${R}\n" ""; }

ok()   { echo -e "  ${GREEN}✔${R}  $1"; }
fail() { echo -e "  ${RED}✘${R}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${R}  $1"; }
info() { echo -e "  ${CYAN}ℹ${R}  $1"; }
ts()   { date '+%Y-%m-%d %H:%M:%S'; }

pause() {
    echo ""
    printf "  ${DIM}Press Enter to continue...${R}"
    read -r
}

# ── Load env ──────────────────────────────────────────────────────────
load_env() {
    local ef="$SKILL_DIR/.env"
    if [ -f "$ef" ]; then
        set -a; source "$ef"; set +a
    fi
    export C2_BASE_URL="${C2_BASE_URL:-http://localhost:8000}"
    export C2_USERNAME="${C2_USERNAME:-admin}"
    export C2_PASSWORD="${C2_PASSWORD:-admin123}"
    export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
}

# ── Service health dots ───────────────────────────────────────────────
svc_dot() {
    local url="$1" label="$2" mode="${3:-http}"
    local dot
    if [ "$mode" = "chroma" ]; then
        echo "$(curl -s "$url" 2>/dev/null)" | grep -q "heartbeat" \
            && dot="${GREEN}●${R}" || dot="${RED}●${R}"
    else
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
        [[ "$code" =~ ^2|^3 ]] && dot="${GREEN}●${R}" || dot="${RED}●${R}"
    fi
    printf "  ${dot} ${DIM}%-12s${R}" "$label"
}

# ── Banner ────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${CYAN}"
    echo '  ██████╗██████╗      ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ '
    echo ' ██╔════╝╚════██╗    ██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗'
    echo ' ██║      █████╔╝    ██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝'
    echo ' ██║     ██╔═══╝     ██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗'
    echo ' ╚██████╗███████╗    ╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║'
    echo '  ╚═════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝'
    echo -e "${R}"
    line
    center_row "RAG-Powered C2 Simulation Platform  •  MITRE ATT&CK  •  Neo4j  •  ChromaDB"
    blank_row
    printf "${CYAN}║${R}  ${DIM}%-40s${R}  ${DIM}%s${R}%8s${CYAN}║${R}\n" \
        "$(ts)" "v3.0  Interactive Mode" ""
    blank_row
    printf "${CYAN}║${R}"
    svc_dot "$C2_BASE_URL/health"                   "C2 API"
    svc_dot "http://localhost:7474"                  "Neo4j"
    svc_dot "http://localhost:8001/api/v2/heartbeat" "ChromaDB" "chroma"
    printf "%19s${CYAN}║${R}\n" ""
    line
    echo ""
}

# ── Output formatter ──────────────────────────────────────────────────
fmt() {
    thin
    while IFS= read -r ln; do
        ln="${ln//SUCCESS/${GREEN}SUCCESS${R}}"
        ln="${ln//FAILED/${RED}FAILED${R}}"
        ln="${ln//ERROR/${RED}ERROR${R}}"
        ln="${ln//✓/${GREEN}✓${R}}"
        ln="${ln//✗/${RED}✗${R}}"
        ln="${ln//⚠/${YELLOW}⚠${R}}"
        echo -e "  $ln"
    done
    thin
}

# ── Command runner with header ────────────────────────────────────────
run_cmd() {
    local label="$1" be="$2"; shift 2
    echo ""
    line
    if [ "$be" = "A" ]; then
        printf "${CYAN}║${R} ${BOLD}${WHITE}  %-38s${R} ${GREEN}[BACKEND A]  run.sh    ${R}  ${CYAN}║${R}\n" "$label"
    else
        printf "${CYAN}║${R} ${BOLD}${WHITE}  %-38s${R} ${MAGENTA}[BACKEND B]  dynamic.sh${R}  ${CYAN}║${R}\n" "$label"
    fi
    printf "${CYAN}║${R}  ${DIM}%-68s${R}${CYAN}║${R}\n" "$(ts)"
    line
    echo ""
    "$@" 2>/dev/null | fmt
}

# ── Tactic picker ─────────────────────────────────────────────────────
pick_tactic() {
    echo ""
    line
    center_row "SELECT TACTIC" "$YELLOW"
    line
    printf "  ${CYAN}[1]${R}  %-28s  ${CYAN}[2]${R}  %s\n" "discovery"            "credential-access"
    printf "  ${CYAN}[3]${R}  %-28s  ${CYAN}[4]${R}  %s\n" "privilege-escalation" "persistence"
    printf "  ${CYAN}[5]${R}  %-28s  ${CYAN}[6]${R}  %s\n" "defense-evasion"      "lateral-movement"
    printf "  ${CYAN}[7]${R}  %-28s  ${CYAN}[8]${R}  %s\n" "collection"           "exfiltration"
    printf "  ${CYAN}[9]${R}  custom\n"
    echo ""
    printf "  ${BOLD}Select tactic [1-9]: ${R}"
    read -r t
    case $t in
        1) TACTIC="discovery" ;;
        2) TACTIC="credential-access" ;;
        3) TACTIC="privilege-escalation" ;;
        4) TACTIC="persistence" ;;
        5) TACTIC="defense-evasion" ;;
        6) TACTIC="lateral-movement" ;;
        7) TACTIC="collection" ;;
        8) TACTIC="exfiltration" ;;
        9) printf "  Enter tactic name: "; read -r TACTIC ;;
        *) TACTIC="discovery" ;;
    esac
    info "Selected: ${YELLOW}$TACTIC${R}"
}

# ════════════════════════════════════════════════════════════════════
#  SUB-MENUS
# ════════════════════════════════════════════════════════════════════

# ── Core C2 ──────────────────────────────────────────────────────────
menu_core() {
    while true; do
        banner
        line
        center_row "CORE C2 COMMANDS" "$GREEN"
        printf "${CYAN}║${R}  ${DIM}Backend A  →  run.sh  →  c2.js%$((W-32))s${CYAN}║${R}\n" ""
        line
        printf "  ${GREEN}[1]${R}  %-30s  ${DIM}check all services${R}\n"          "Health Check"
        printf "  ${GREEN}[2]${R}  %-30s  ${DIM}connected victim agents${R}\n"      "Show Agents"
        printf "  ${GREEN}[3]${R}  %-30s  ${DIM}all supported T-codes${R}\n"        "List Techniques"
        printf "  ${GREEN}[4]${R}  %-30s  ${DIM}queue a technique on victim${R}\n"  "Run Technique"
        printf "  ${GREEN}[5]${R}  %-30s  ${DIM}AI technique explanation${R}\n"     "Explain Technique"
        printf "  ${GREEN}[6]${R}  %-30s  ${DIM}victim command output${R}\n"        "Show Output"
        printf "  ${GREEN}[7]${R}  %-30s  ${DIM}threat group correlation${R}\n"     "APT Correlation"
        printf "  ${GREEN}[8]${R}  %-30s  ${DIM}live IDS / security events${R}\n"   "Live Alerts"
        printf "  ${GREEN}[9]${R}  %-30s  ${DIM}clear session and queues${R}\n"     "Reset Session"
        echo ""
        printf "  ${CYAN}[0]${R}  Back to Main Menu\n"
        echo ""
        printf "  ${BOLD}Select [0-9]: ${R}"
        read -r c

        case $c in
            1) run_cmd "HEALTH CHECK"         A "$RUN" health;  pause ;;
            2) run_cmd "CONNECTED AGENTS"     A "$RUN" agents;  pause ;;
            3) run_cmd "SUPPORTED TECHNIQUES" A "$RUN" list;    pause ;;
            4)
               printf "\n  ${BOLD}Enter T-code (e.g. T1082): ${R}"; read -r tc
               [ -z "$tc" ] && warn "No T-code entered" && pause && continue
               run_cmd "EXECUTE  $tc" A "$RUN" run "$tc"
               info "Check results → ${CYAN}option 6 Show Output${R}"
               pause ;;
            5)
               printf "\n  ${BOLD}Enter T-code (e.g. T1003): ${R}"; read -r tc
               [ -z "$tc" ] && warn "No T-code entered" && pause && continue
               run_cmd "EXPLAIN  $tc" A "$RUN" explain "$tc"
               pause ;;
            6) run_cmd "VICTIM OUTPUT"        A "$RUN" output;  pause ;;
            7) run_cmd "APT CORRELATION"      A "$RUN" apt;     pause ;;
            8) run_cmd "LIVE ALERTS  (Ctrl+C to stop)" A "$RUN" alerts; pause ;;
            9)
               printf "\n  ${YELLOW}Reset clears all queues. Continue? [y/N]: ${R}"
               read -r yn
               [[ "$yn" =~ ^[Yy]$ ]] \
                   && run_cmd "RESET SESSION" A "$RUN" reset \
                   || info "Cancelled"
               pause ;;
            0) break ;;
            *) warn "Invalid option" ; sleep 1 ;;
        esac
    done
}

# ── AI Attack Engine ──────────────────────────────────────────────────
menu_ai() {
    while true; do
        banner
        line
        center_row "AI ATTACK ENGINE" "$MAGENTA"
        printf "${CYAN}║${R}  ${DIM}Backend B  →  dynamic.sh  →  learning-engine.js%$((W-50))s${CYAN}║${R}\n" ""
        line
        printf "  ${MAGENTA}[1]${R}  %-30s  ${DIM}fingerprint victim OS + tools${R}\n"        "Profile Victim"
        printf "  ${MAGENTA}[2]${R}  %-30s  ${DIM}3 techniques · 2 retries${R}\n"             "Auto Attack"
        printf "  ${MAGENTA}[3]${R}  %-30s  ${DIM}5 techniques · 3 retries · RAG loop${R}\n"  "Smart Attack"
        printf "  ${MAGENTA}[4]${R}  %-30s  ${DIM}discovery→creds→persist→evasion${R}\n"     "Full Kill Chain"
        printf "  ${MAGENTA}[5]${R}  %-30s  ${DIM}pick your own tactic sequence${R}\n"        "Custom Chain"
        printf "  ${MAGENTA}[6]${R}  %-30s  ${DIM}re-analyse and adapt via RAG${R}\n"         "Evolve Strategy"
        printf "  ${MAGENTA}[7]${R}  %-30s  ${DIM}success rates + detection stats${R}\n"      "Attack Statistics"
        printf "  ${MAGENTA}[8]${R}  %-30s  ${DIM}ChromaDB experience store${R}\n"            "RAG Knowledge Base"
        printf "  ${MAGENTA}[9]${R}  %-30s  ${DIM}AI-generated pentest report${R}\n"          "Generate Report"
        echo ""
        printf "  ${CYAN}[0]${R}  Back to Main Menu\n"
        echo ""
        printf "  ${BOLD}Select [0-9]: ${R}"
        read -r c

        case $c in
            1) run_cmd "VICTIM PROFILE" B "$DYN" profile; pause ;;
            2) pick_tactic
               run_cmd "AUTO ATTACK  —  $TACTIC" B "$DYN" auto "$TACTIC"
               info "Next → ${MAGENTA}[7] Attack Statistics${R}  or  ${GREEN}[6] Show Output${R}"
               pause ;;
            3) pick_tactic
               run_cmd "SMART ATTACK  —  $TACTIC" B "$DYN" smart "$TACTIC"
               info "Next → ${MAGENTA}[6] Evolve Strategy${R}  or  ${MAGENTA}[7] Statistics${R}"
               pause ;;
            4) run_cmd "FULL KILL CHAIN" B "$DYN" learnall
               info "Next → ${MAGENTA}[9] Generate Report${R}"
               pause ;;
            5)
               printf "\n  ${BOLD}Enter comma-separated tactics: ${R}"
               read -r chain
               [ -z "$chain" ] && warn "No tactics entered" && pause && continue
               run_cmd "CUSTOM CHAIN  —  $chain" B "$DYN" chain "$chain"
               pause ;;
            6) run_cmd "EVOLVE STRATEGY"   B "$DYN" evolve;  pause ;;
            7) run_cmd "ATTACK STATISTICS" B "$DYN" stats;   pause ;;
            8) run_cmd "RAG KNOWLEDGE BASE" B "$DYN" learned; pause ;;
            9)
               printf "\n  ${BOLD}Format — [1] HTML  [2] JSON (default HTML): ${R}"
               read -r rf
               [ "$rf" = "2" ] && FMT="json" || FMT="html"
               run_cmd "PENTEST REPORT  —  $FMT" B "$DYN" report "$FMT"
               pause ;;
            0) break ;;
            *) warn "Invalid option" ; sleep 1 ;;
        esac
    done
}

# ── Quick Flows ───────────────────────────────────────────────────────
menu_quickflow() {
    while true; do
        banner
        line
        center_row "QUICK ATTACK FLOWS" "$YELLOW"
        printf "${CYAN}║${R}  ${DIM}Automated multi-step sequences%$((W-32))s${CYAN}║${R}\n" ""
        line
        printf "  ${YELLOW}[1]${R}  %-30s  ${DIM}profile → smart discovery → output → apt${R}\n"  "Quick Recon"
        printf "  ${YELLOW}[2]${R}  %-30s  ${DIM}smart creds → smart privesc → evolve${R}\n"       "Quick Exploit"
        printf "  ${YELLOW}[3]${R}  %-30s  ${DIM}full kill chain → stats → report${R}\n"           "Full Engagement"
        echo ""
        printf "  ${CYAN}[0]${R}  Back to Main Menu\n"
        echo ""
        printf "  ${BOLD}Select [0-3]: ${R}"
        read -r c

        case $c in
            1)
               run_cmd "PROFILE VICTIM"   B "$DYN" profile
               run_cmd "SMART DISCOVERY"  B "$DYN" smart discovery
               run_cmd "VICTIM OUTPUT"    A "$RUN" output
               run_cmd "APT CORRELATION"  A "$RUN" apt
               info "Quick Recon complete"
               pause ;;
            2)
               run_cmd "SMART CRED ACCESS" B "$DYN" smart credential-access
               run_cmd "SMART PRIVESC"     B "$DYN" smart privilege-escalation
               run_cmd "EVOLVE STRATEGY"   B "$DYN" evolve
               info "Exploit chain complete"
               pause ;;
            3)
               run_cmd "FULL KILL CHAIN"  B "$DYN" learnall
               run_cmd "ATTACK STATS"     B "$DYN" stats
               run_cmd "PENTEST REPORT"   B "$DYN" report html
               info "Full engagement complete"
               pause ;;
            0) break ;;
            *) warn "Invalid option" ; sleep 1 ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════════
main_menu() {
    load_env

    while true; do
        banner
        line
        center_row "MAIN MENU"
        line
        blank_row
        printf "${CYAN}║${R}  ${GREEN}[1]${R}  %-30s  ${DIM}run.sh  →  c2.js%$((W-50))s${CYAN}║${R}\n"              "Core C2 Commands"   ""
        printf "${CYAN}║${R}  ${MAGENTA}[2]${R}  %-30s  ${DIM}dynamic.sh  →  learning-engine.js%$((W-62))s${CYAN}║${R}\n" "AI Attack Engine"   ""
        printf "${CYAN}║${R}  ${YELLOW}[3]${R}  %-30s  ${DIM}automated multi-step flows%$((W-54))s${CYAN}║${R}\n"    "Quick Attack Flows"  ""
        blank_row
        printf "${CYAN}║${R}  ${CYAN}[4]${R}  %-62s${CYAN}║${R}\n" "Health Check"
        printf "${CYAN}║${R}  ${RED}[0]${R}  %-62s${CYAN}║${R}\n"  "Exit"
        blank_row
        line
        echo ""
        printf "  ${BOLD}Select [0-4]: ${R}"
        read -r m

        case $m in
            1) menu_core ;;
            2) menu_ai ;;
            3) menu_quickflow ;;
            4) run_cmd "SYSTEM HEALTH CHECK" A "$RUN" health; pause ;;
            0)
               echo ""
               info "Exiting C2 Operator. Stay safe."
               echo ""
               exit 0 ;;
            *) warn "Invalid — use 0-4" ; sleep 1 ;;
        esac
    done
}

main_menu
