#!/bin/bash
# dynamic.sh v4.2 — Self-Improving Autonomous Attack Engine Wrapper
set -a
if [ -f "/home/ocuser2/.openclaw/skills/c2-operator/.env" ]; then
    source /home/ocuser2/.openclaw/skills/c2-operator/.env
fi
set +a

export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export C2_PASSWORD="${C2_PASSWORD:-admin123}"
export C2_BASE_URL="${C2_BASE_URL:-http://localhost:8000}"
export C2_USERNAME="${C2_USERNAME:-admin}"

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$SKILL_DIR/learning-engine.js"

# Known victims — update if you add more
DOCKER_VICTIM="websecsim-victim-c2"
CUSTOM_VICTIM="${C2_VICTIM:-}"   # set via .env or export C2_VICTIM=192.168.209.4
ALL_VICTIMS="${DOCKER_VICTIM}${CUSTOM_VICTIM:+,$CUSTOM_VICTIM}"

# ── AUTH ──────────────────────────────────────────────────────
get_token() {
  curl -s -X POST "$C2_BASE_URL/token" \
    -d "username=$C2_USERNAME&password=$C2_PASSWORD" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

# ── PREREQ CHECK ──────────────────────────────────────────────
check_engine() {
  if [ ! -f "$ENGINE" ]; then
    echo "ERROR: learning-engine.js not found at $ENGINE"
    exit 1
  fi
  if ! command -v node &>/dev/null; then
    echo "ERROR: node.js not installed or not in PATH"
    exit 1
  fi
}

check_c2() {
  if ! curl -s --max-time 5 "$C2_BASE_URL/health" &>/dev/null; then
    echo "ERROR: C2 API not reachable at $C2_BASE_URL"
    echo "       Is the FastAPI container running?"
    exit 1
  fi
}

CMD="${1:-help}"
shift 2>/dev/null

case "$CMD" in

  # ── AUTO ────────────────────────────────────────────────────
  # Triggers: auto, auto attack, auto discovery, ai attack, run auto
  # Optional ARG2: victim target
  auto)
    TACTIC="${1:-discovery}"
    VICTIM="${2:-}"
    check_engine
    check_c2
    echo "Auto attack: $TACTIC${VICTIM:+ → victim: $VICTIM}"
    if [ -n "$VICTIM" ]; then
      timeout 180 node "$ENGINE" run \
        --tactic "$TACTIC" \
        --techniques 3 \
        --retries 2 \
        --victim "$VICTIM"
    else
      timeout 180 node "$ENGINE" run \
        --tactic "$TACTIC" \
        --techniques 3 \
        --retries 2
    fi
    ;;

  # ── SMART ───────────────────────────────────────────────────
  # Triggers: smart, smart attack, smart discovery, self improving, run smart
  # Optional ARG2: victim target
  smart)
    TACTIC="${1:-discovery}"
    VICTIM="${2:-}"
    check_engine
    check_c2
    echo "Smart attack: $TACTIC${VICTIM:+ → victim: $VICTIM}"
    if [ -n "$VICTIM" ]; then
      timeout 240 node "$ENGINE" run \
        --tactic "$TACTIC" \
        --techniques 5 \
        --retries 3 \
        --victim "$VICTIM"
    else
      timeout 240 node "$ENGINE" run \
        --tactic "$TACTIC" \
        --techniques 5 \
        --retries 3
    fi
    ;;

  # ── LEARNALL ────────────────────────────────────────────────
  # Triggers: learnall, learn all, full attack, full chain, full kill chain, run all
  # Optional ARG1: single victim target
  learnall)
    VICTIM="${1:-}"
    check_engine
    check_c2
    echo "Full kill chain starting..."
    echo "Tactics: discovery -> credential-access -> persistence -> defense-evasion"
    if [ -n "$VICTIM" ]; then
      echo "Target victim: $VICTIM"
    else
      echo "Target victim: $DOCKER_VICTIM (default)"
    fi
    echo "This may take 5-10 minutes. Output will stream below."
    echo ""
    if [ -n "$VICTIM" ]; then
      timeout 600 node "$ENGINE" fullchain \
        --tactics "discovery,credential-access,persistence,defense-evasion" \
        --techniques 3 \
        --retries 3 \
        --victim "$VICTIM"
    else
      timeout 600 node "$ENGINE" fullchain \
        --tactics "discovery,credential-access,persistence,defense-evasion" \
        --techniques 3 \
        --retries 3
    fi
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
      echo "WARNING: Kill chain timed out after 10 minutes"
    fi
    ;;

  # ── LEARNALL-ALL ────────────────────────────────────────────
  # Triggers: attack all victims, full chain all victims, learnall all
  # Attacks ALL known victims (docker + custom) in one chain
  learnall-all)
    check_engine
    check_c2
    echo "Full kill chain on ALL victims: $ALL_VICTIMS"
    echo "Tactics: discovery -> credential-access -> persistence -> defense-evasion"
    echo "This may take 10-20 minutes depending on number of victims."
    echo ""
    timeout 1200 node "$ENGINE" fullchain \
      --tactics "discovery,credential-access,persistence,defense-evasion" \
      --techniques 3 \
      --retries 3 \
      --victims "$ALL_VICTIMS"
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
      echo "WARNING: Kill chain timed out"
    fi
    ;;

  # ── PROFILE ─────────────────────────────────────────────────
  # Triggers: profile, profile victim, victim info, analyze target, fingerprint
  # Optional ARG1: victim target
  profile)
    VICTIM="${1:-}"
    check_engine
    check_c2
    if [ -n "$VICTIM" ]; then
      echo "Profiling victim: $VICTIM"
      timeout 60 node "$ENGINE" profile --victim "$VICTIM"
    else
      echo "Profiling default victim environment..."
      timeout 60 node "$ENGINE" profile
    fi
    ;;

  # ── LIST-VICTIMS ────────────────────────────────────────────
  # Triggers: list victims, show victims, victims, who are targets
  list-victims)
    check_engine
    check_c2
    node "$ENGINE" list-victims
    ;;

  # ── ADD-VICTIM ──────────────────────────────────────────────
  # Triggers: add victim, new victim, register victim, add target
  # ARG1: target IP/hostname/URL  ARG2 (optional): label
  add-victim)
    TARGET="${1:-}"
    LABEL="${2:-}"
    if [ -z "$TARGET" ]; then
      echo "ERROR: Specify a target, e.g.: add-victim 192.168.209.4"
      exit 1
    fi
    check_engine
    check_c2
    echo "Registering victim: $TARGET${LABEL:+ ($LABEL)}"
    if [ -n "$LABEL" ]; then
      node "$ENGINE" add-victim --target "$TARGET" --label "$LABEL"
    else
      node "$ENGINE" add-victim --target "$TARGET"
    fi
    ;;

  # ── VICTIM-STATUS ───────────────────────────────────────────
  # Triggers: victim status, check victim, target status
  victim-status)
    VICTIM="${1:-}"
    if [ -z "$VICTIM" ]; then
      echo "ERROR: Specify a victim ID, e.g.: victim-status 192.168.209.4"
      exit 1
    fi
    TOKEN=$(get_token)
    echo "Status for victim: $VICTIM"
    curl -s -H "Authorization: Bearer $TOKEN" \
      "$C2_BASE_URL/api/victims/$(python3 -c "import urllib.parse; print(urllib.parse.quote('$VICTIM'))")/status" \
      | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Victim ID   : {d.get('victim_id')}\")
print(f\"  Label       : {d.get('label')}\")
print(f\"  Active      : {d.get('active')}\")
print(f\"  Source      : {d.get('source')}\")
print(f\"  Connected   : {d.get('is_beacon_connected')}\")
print(f\"  Last seen   : {d.get('agent_last_seen','never')}\")
print(f\"  Pending     : {d.get('pending_tasks',0)} tasks\")
techs = d.get('executed_techniques', [])
if techs:
    print(f\"  Techniques  : {', '.join(techs)}\")
else:
    print(f\"  Techniques  : none yet\")
" 2>/dev/null
    ;;

  # ── EVOLVE ──────────────────────────────────────────────────
  # Triggers: evolve, evolve strategy, improve strategy, ai suggestions
  evolve)
    check_engine
    echo "Evolving attack strategy using AI..."
    timeout 120 node "$ENGINE" evolve
    ;;

  # ── LEARNED ─────────────────────────────────────────────────
  # Triggers: learned, show learned, knowledge base, what learned
  learned)
    check_engine
    node "$ENGINE" knowledge
    ;;

  # ── STATS ───────────────────────────────────────────────────
  # Triggers: stats, show stats, attack stats, statistics, success rate
  stats)
    check_engine
    node "$ENGINE" stats
    ;;

  # ── EXPORT ──────────────────────────────────────────────────
  # Triggers: export, export data, export research
  export)
    check_engine
    node "$ENGINE" export-research
    ;;

  # ── RESET ───────────────────────────────────────────────────
  # Triggers: reset, reset c2, reset session, clear c2
  reset)
    check_engine
    node "$ENGINE" reset-session
    ;;

  # ── CHAIN ───────────────────────────────────────────────────
  # Custom tactic chain with optional victim
  chain)
    TACTICS="${1:-discovery,credential-access,persistence}"
    VICTIM="${2:-}"
    check_engine
    check_c2
    echo "Custom chain: $TACTICS${VICTIM:+ → victim: $VICTIM}"
    if [ -n "$VICTIM" ]; then
      timeout 600 node "$ENGINE" fullchain \
        --tactics "$TACTICS" \
        --techniques 3 \
        --retries 3 \
        --victim "$VICTIM"
    else
      timeout 600 node "$ENGINE" fullchain \
        --tactics "$TACTICS" \
        --techniques 3 \
        --retries 3
    fi
    ;;

  # ── REPORT ──────────────────────────────────────────────────
  # Triggers: report, generate report, create report, pentest report
  report)
    check_c2
    echo "Generating penetration test report..."
    TOKEN=$(get_token)
    if [ -z "$TOKEN" ]; then
      echo "ERROR: Could not authenticate with C2 API"
      echo "       Check C2_USERNAME and C2_PASSWORD in .env"
      exit 1
    fi

    RESULT=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/report" 2>/dev/null)
    HAS_REPORT=$(echo "$RESULT" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('yes' if 'report' in d else 'no')
except:
    print('no')
" 2>/dev/null)

    if [ "$HAS_REPORT" = "yes" ]; then
      echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
s = d.get('session_stats', {})
print('=' * 62)
print('  PENETRATION TEST REPORT')
print('=' * 62)
print(f\"  Generated : {d.get('generated_at','unknown')}\")
print(f\"  Techniques: {s.get('techniques_executed', 0)} executed\")
print(f\"  Top APT   : {s.get('top_apt_match','none')} ({s.get('apt_confidence',0)}% match)\")
techs = d.get('executed_techniques', [])
if techs:
    print(f\"  TIDs      : {', '.join(techs)}\")
print('=' * 62)
print()
print(d.get('report', 'No report text returned'))
print()
print('=' * 62)
"
    else
      echo "Note: /api/report not found — assembling from available data"
      echo ""

      NAV=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/navigator/status" 2>/dev/null)
      APT=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/apt/correlate?top_n=5" 2>/dev/null)
      LOGS=$(curl -s "$C2_BASE_URL/api/logs?level=alert&limit=15" 2>/dev/null)
      STATS=$(curl -s "$C2_BASE_URL/api/logs/stats" 2>/dev/null)

      # Pull per-victim summary from new endpoint
      VICTIMS_DATA=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/victims" 2>/dev/null)

      python3 - "$NAV" "$APT" "$LOGS" "$STATS" "$VICTIMS_DATA" << 'PYEOF'
import sys, json

def safe_load(s):
    try: return json.loads(s)
    except: return {}

nav     = safe_load(sys.argv[1])
apt     = safe_load(sys.argv[2])
logs    = safe_load(sys.argv[3])
stats   = safe_load(sys.argv[4])
victims = safe_load(sys.argv[5])

print('=' * 62)
print('  PENETRATION TEST REPORT  (assembled from C2 data)')
print('=' * 62)

count = nav.get('executed_technique_count', 0)
techs = nav.get('executed_techniques', [])
print(f'\n  ATTACK SUMMARY')
print(f'  Techniques executed : {count}')
if techs:
    print(f'  Techniques          : {", ".join(techs)}')
else:
    print('  No techniques executed yet — run an attack first')

# Per-victim summary (v4.2)
victim_list = victims.get('victims', [])
if victim_list:
    print(f'\n  VICTIMS TARGETED  ({len(victim_list)} total)')
    for v in victim_list:
        connected = '✅ connected' if v.get('is_beacon_connected') else '❌ no beacon'
        print(f'  {v["victim_id"]:<25} {v.get("label",""):<20} {connected}')

matches = apt.get('top_matches', [])
if matches:
    print(f'\n  APT CORRELATION  (top {len(matches)} matches)')
    for m in matches:
        bar = '#' * int(m["score_pct"] / 10)
        print(f'  #{m["rank"]} {m["name"]:<20} {m["group_id"]:<8} {bar:<10} {m["score_pct"]}% ({m["overlap_count"]} techniques)')
else:
    print('\n  APT CORRELATION  : no data yet')

log_entries = logs.get('logs', [])
if log_entries:
    print(f'\n  ALERTS  ({len(log_entries)} recent)')
    for e in log_entries[-10:]:
        print(f'  [{e["level"].upper():8}] {e["ts"][:19]}  [{e["source"]}]  {e["msg"]}')
else:
    print('\n  ALERTS  : none recorded')

s = stats.get('stats', {})
if s:
    print('\n  LOG STATISTICS')
    for cat, levels in s.items():
        total = sum(levels.values())
        print(f'  {cat:<12} : {total} events  ({", ".join(f"{l}:{n}" for l,n in levels.items())})')

print('\n' + '=' * 62)
PYEOF
    fi
    ;;

  # ── HELP ────────────────────────────────────────────────────
  *)
    echo "
Self-Improving Attack Engine v4.2
===================================
Commands:
  profile [victim]                Profile victim environment
  auto <tactic> [victim]          AI attack — 3 techniques, 2 retries
  smart <tactic> [victim]         Smart attack — 5 techniques, 3 retries
  learnall [victim]               Full kill chain on one victim (~10 min)
  learnall-all                    Full kill chain on ALL victims
  chain <t1,t2,t3> [victim]       Custom tactic chain
  list-victims                    List all victims in registry
  add-victim <ip> [label]         Register a new victim
  victim-status <id>              Status of a specific victim
  evolve                          AI strategy evolution
  learned                         Knowledge base with stealth rates
  stats                           Statistics + cross-session trend
  export                          Export full research data to JSON
  reset                           Reset session (keeps KB)
  report                          Generate pentest report

Available tactics:
  discovery | credential-access | persistence
  defense-evasion | lateral-movement | collection | exfiltration

Victim examples:
  dynamic.sh learnall 192.168.209.4
  dynamic.sh auto discovery 192.168.209.4
  dynamic.sh add-victim 192.168.209.4 Metasploitable2
  dynamic.sh learnall-all

Set default custom victim:
  export C2_VICTIM=192.168.209.4   (or add to .env)
"
    ;;
esac
