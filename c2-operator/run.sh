#!/bin/bash
# run.sh v4.2 — OpenClaw SKILL.md command dispatcher
# Maps every trigger in SKILL.md to the correct dynamic.sh or API call

SKILL_DIR="/home/ocuser2/.openclaw/skills/c2-operator"
DYNAMIC="$SKILL_DIR/dynamic.sh"
C2_BASE_URL="${C2_BASE_URL:-http://localhost:8000}"
C2_USERNAME="${C2_USERNAME:-admin}"
C2_PASSWORD="${C2_PASSWORD:-admin123}"

# Load .env if present
if [ -f "$SKILL_DIR/.env" ]; then
  set -a
  source "$SKILL_DIR/.env"
  set +a
fi

# ── AUTH ──────────────────────────────────────────────────────
get_token() {
  curl -s -X POST "$C2_BASE_URL/token" \
    -d "username=$C2_USERNAME&password=$C2_PASSWORD" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

# ── COMMAND DISPATCHER ────────────────────────────────────────
CMD="${1:-help}"
ARG="${2:-}"    # technique ID or victim target
ARG3="${3:-}"   # second argument (e.g. victim when ARG is tactic)

case "$CMD" in

  # ── HEALTH ──────────────────────────────────────────────────
  # Triggers: health, health check, c2 health, is c2 running, status
  health)
    echo "Checking C2 health..."
    RESULT=$(curl -s --max-time 10 "$C2_BASE_URL/health")
    if [ -z "$RESULT" ]; then
      echo "ERROR: C2 API not reachable at $C2_BASE_URL"
      exit 1
    fi
    echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"Status         : {d.get('status','unknown').upper()}\")
print(f\"Timestamp      : {d.get('timestamp','')[:19]}\")
print(f\"MITRE loaded   : {d.get('mitre_loaded')} ({d.get('mitre_source')}, {d.get('technique_count')} techniques)\")
print(f\"AI configured  : {d.get('ai_configured')} — model: {d.get('ai_model','none')}\")
print(f\"Agents online  : {d.get('agents_connected')}\")
print(f\"Tasks pending  : {d.get('tasks_pending')}\")
print(f\"APT groups     : {d.get('apt_groups_loaded')}\")
print(f\"Techniques run : {d.get('executed_techniques')}\")
print(f\"Victims total  : {d.get('victim_count','?')}\")
print(f\"Victims active : {d.get('active_victims','?')}\")
"
    ;;

  # ── AGENTS ──────────────────────────────────────────────────
  # Triggers: agents, show agents, connected agents, who is connected
  agents)
    TOKEN=$(get_token)
    RESULT=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/agents")
    COUNT=$(echo "$RESULT" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null)
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
      echo "No agents currently connected."
      echo "Make sure the victim container is running and beaconing to $C2_BASE_URL"
    else
      echo "Connected agents ($COUNT):"
      echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for host, info in d.items():
    print(f\"  Host: {host}\")
    print(f\"  Last seen: {info.get('last_seen','unknown')}\")
    print()
"
    fi
    ;;

  # ── LIST ────────────────────────────────────────────────────
  # Triggers: techniques, list techniques, show techniques
  list)
    TOKEN=$(get_token)
    curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/attack/supported" \
      | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"Available techniques ({d.get('count',0)}):\")
print(f\"{'ID':<14} {'Name':<40} Command\")
print('-' * 80)
for t in d.get('techniques', []):
    name = (t.get('name') or 'Unknown')[:38]
    cmd  = t.get('command','')[:30]
    print(f\"  {t['technique']:<12} {name:<40} {cmd}\")
"
    ;;

  # ── OUTPUT ──────────────────────────────────────────────────
  # Triggers: output, show output, victim output, what happened
  output)
    TOKEN=$(get_token)
    AGENTS=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/agents" \
      | python3 -c "import sys,json; [print(k) for k in json.load(sys.stdin).keys()]" 2>/dev/null)
    if [ -z "$AGENTS" ]; then
      echo "No agents connected — no output to show."
    else
      for HOST in $AGENTS; do
        echo "=== Output from Agent: $HOST ==="
        curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/output/$HOST" \
          | python3 -c "
import sys, json
entries = json.load(sys.stdin)
if not entries:
    print('  No output yet for this agent')
else:
    for e in entries[-5:]:
        print(f\"  [{e.get('time','')[:19]}] Technique: {e.get('technique','?')}\")
        out = e.get('output','').strip()
        lines = out.split('\n')[:8]
        for l in lines:
            print(f\"    {l}\")
        if len(out.split('\n')) > 8:
            print(f\"    ... ({len(out.split(chr(10)))-8} more lines)\")
        print()
"
      done
    fi
    ;;

  # ── RUN ─────────────────────────────────────────────────────
  # Triggers: run T[any], execute T[any], queue T[any]
  # Optional ARG3: victim target  e.g. run T1082 192.168.209.4
  run)
    if [ -z "$ARG" ]; then
      echo "ERROR: Specify a technique ID, e.g.: run T1082"
      exit 1
    fi
    TID=$(echo "$ARG" | tr '[:lower:]' '[:upper:]')
    VICTIM="${ARG3:-}"
    TOKEN=$(get_token)
    echo "Queuing technique $TID${VICTIM:+ on victim $VICTIM}..."

    if [ -n "$VICTIM" ]; then
      QUEUE_RESULT=$(curl -s -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"victim\":\"$VICTIM\"}" \
        "$C2_BASE_URL/api/attack/$TID")
    else
      QUEUE_RESULT=$(curl -s -X POST \
        -H "Authorization: Bearer $TOKEN" \
        "$C2_BASE_URL/api/attack/$TID")
    fi

    echo "$QUEUE_RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'detail' in d:
    print(f\"ERROR: {d['detail']}\")
else:
    print(f\"Queued: {d.get('technique')} → victim: {d.get('victim','default')} — {d.get('status')}\")
" 2>/dev/null || echo "$QUEUE_RESULT"

    echo "Waiting 18s for agent to execute and report back..."
    sleep 18

    # Collect output — use victim-specific endpoint if victim was specified
    if [ -n "$VICTIM" ]; then
      ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$VICTIM'))")
      OUTPUT=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "$C2_BASE_URL/api/victims/$ENCODED/outputs?limit=20" \
        | python3 -c "
import sys,json
d=json.load(sys.stdin)
entries=[e for e in d.get('outputs',[]) if e.get('technique')=='$TID']
if entries:
    out=entries[-1].get('output','').strip()
    print(out[:1500] if out else 'Command ran but produced no output')
" 2>/dev/null)
    else
      AGENTS=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/agents" \
        | python3 -c "import sys,json;[print(k) for k in json.load(sys.stdin).keys()]" 2>/dev/null)
      OUTPUT=""
      for HOST in $AGENTS; do
        OUTPUT=$(curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/output/$HOST" \
          | python3 -c "
import sys,json
entries=[e for e in json.load(sys.stdin) if e.get('technique')=='$TID']
if entries:
    out=entries[-1].get('output','').strip()
    print(out[:1500] if out else 'Command ran but produced no output')
" 2>/dev/null)
        [ -n "$OUTPUT" ] && break
      done
    fi

    if [ -n "$OUTPUT" ]; then
      echo ""
      echo "=== Output ==="
      echo "$OUTPUT"
    else
      echo "No output received yet — agent may not be connected or technique may have failed"
    fi
    ;;

  # ── EXPLAIN ─────────────────────────────────────────────────
  # Triggers: explain T[any], what is T[any], tell me about T[any]
  explain)
    if [ -z "$ARG" ]; then
      echo "ERROR: Specify a technique ID, e.g.: explain T1082"
      exit 1
    fi
    TID=$(echo "$ARG" | tr '[:lower:]' '[:upper:]')
    echo "Explaining $TID using AI..."
    curl -s -X POST "$C2_BASE_URL/api/ai/explain" \
      -H "Content-Type: application/json" \
      -d "{\"technique\":\"$TID\"}" \
      | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"Technique : {d.get('technique')} — {d.get('technique_name','')}\")
print()
print(d.get('explanation','No explanation returned'))
" 2>/dev/null
    ;;

  # ── APT ─────────────────────────────────────────────────────
  # Triggers: apt, apt report, threat groups, which apt
  apt)
    TOKEN=$(get_token)
    echo "Correlating executed techniques against APT groups..."
    curl -s -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/apt/correlate?top_n=10" \
      | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"Techniques executed : {d.get('executed_count', 0)}\")
print(f\"TIDs                : {', '.join(d.get('executed_techniques',[]))}\")
print(f\"APT groups in DB    : {d.get('group_count', 0)}\")
print()
matches = d.get('top_matches', [])
if not matches:
    print('No APT matches yet. Run some attack techniques first.')
else:
    print(f\"Top {len(matches)} APT matches:\")
    print(f\"  {'#':<3} {'Group':<22} {'ID':<8} {'Match':>6}  {'Techniques'}\")
    print('  ' + '-' * 60)
    for m in matches:
        bar = '#' * int(m['score_pct'] / 10)
        print(f\"  #{m['rank']:<2} {m['name']:<22} {m['group_id']:<8} {m['score_pct']:>5}%  {bar}\")
        print(f\"       Matched: {', '.join(m['matched_techniques'])}\")
"
    ;;

  # ── ALERTS ──────────────────────────────────────────────────
  # Triggers: alerts, monitor alerts, watch alerts
  alerts)
    echo "Recent security alerts:"
    curl -s "$C2_BASE_URL/api/logs?limit=25" \
      | python3 -c "
import sys, json
d = json.load(sys.stdin)
entries = d.get('logs', [])
if not entries:
    print('No alerts yet')
else:
    LEVEL_ORDER = {'critical':0,'alert':1,'warn':2,'info':3}
    important = [e for e in entries if e.get('level') in ('critical','alert','warn')]
    display   = important[-20:] if important else entries[-15:]
    for e in display:
        lvl = e.get('level','info').upper()
        pad = {'CRITICAL':'!!','ALERT':'! ','WARN':'  ','INFO':'  '}.get(lvl,'  ')
        print(f\"  {pad}[{lvl:8}] {e.get('ts','')[:19]}  [{e.get('source','?'):8}]  {e.get('msg','')}\")
"
    ;;

  # ── RESET ───────────────────────────────────────────────────
  # Triggers: reset, reset c2, reset session, clear c2
  reset)
    TOKEN=$(get_token)
    echo "Resetting C2 session..."
    API_RESULT=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" "$C2_BASE_URL/api/system/reset")
    echo "$API_RESULT" | python3 -c "
import sys,json; d=json.load(sys.stdin); print(f\"API reset: {d.get('status','done')}\")
" 2>/dev/null
    echo "Resetting learning engine session..."
    "$DYNAMIC" reset
    echo "Session cleared. Knowledge base (KB) preserved."
    ;;

  # ── AUTO ────────────────────────────────────────────────────
  # Triggers: auto, auto attack, auto discovery, ai attack, run auto
  # Optional ARG3: victim  e.g. auto discovery 192.168.209.4
  auto)
    TACTIC="${ARG:-discovery}"
    VICTIM="${ARG3:-}"
    "$DYNAMIC" auto "$TACTIC" "$VICTIM"
    ;;

  # ── SMART ───────────────────────────────────────────────────
  # Triggers: smart, smart attack, smart discovery, self improving, run smart
  # Optional ARG3: victim  e.g. smart discovery 192.168.209.4
  smart)
    TACTIC="${ARG:-discovery}"
    VICTIM="${ARG3:-}"
    "$DYNAMIC" smart "$TACTIC" "$VICTIM"
    ;;

  # ── LEARNALL ────────────────────────────────────────────────
  # Triggers: learnall, learn all, full attack, full chain, full kill chain, run all
  # Optional ARG: victim  e.g. learnall 192.168.209.4
  learnall)
    "$DYNAMIC" learnall "$ARG"
    ;;

  # ── LEARNALL-ALL ────────────────────────────────────────────
  # Triggers: attack all victims, full chain all victims, learnall all
  learnall-all)
    "$DYNAMIC" learnall-all
    ;;

  # ── PROFILE ─────────────────────────────────────────────────
  # Triggers: profile, profile victim, victim info, analyze target, fingerprint
  # Optional ARG: victim  e.g. profile 192.168.209.4
  profile)
    "$DYNAMIC" profile "$ARG"
    ;;

  # ── LIST-VICTIMS ────────────────────────────────────────────
  # Triggers: list victims, show victims, victims, who are targets
  list-victims)
    "$DYNAMIC" list-victims
    ;;

  # ── ADD-VICTIM ──────────────────────────────────────────────
  # Triggers: add victim, new victim, register victim, add target
  # ARG: IP/hostname/URL  ARG3 (optional): label
  add-victim)
    if [ -z "$ARG" ]; then
      echo "ERROR: Specify a target, e.g.: add-victim 192.168.209.4"
      exit 1
    fi
    "$DYNAMIC" add-victim "$ARG" "$ARG3"
    ;;

  # ── VICTIM-STATUS ───────────────────────────────────────────
  # Triggers: victim status, check victim, target status
  victim-status)
    if [ -z "$ARG" ]; then
      echo "ERROR: Specify a victim ID, e.g.: victim-status 192.168.209.4"
      exit 1
    fi
    "$DYNAMIC" victim-status "$ARG"
    ;;

  # ── EVOLVE ──────────────────────────────────────────────────
  # Triggers: evolve, evolve strategy, improve strategy, ai suggestions
  evolve)
    "$DYNAMIC" evolve
    ;;

  # ── STATS ───────────────────────────────────────────────────
  # Triggers: stats, show stats, attack stats, statistics, success rate
  stats)
    "$DYNAMIC" stats
    ;;

  # ── LEARNED ─────────────────────────────────────────────────
  # Triggers: learned, show learned, knowledge base, what learned
  learned)
    "$DYNAMIC" learned
    ;;

  # ── REPORT ──────────────────────────────────────────────────
  # Triggers: report, generate report, create report, pentest report
  report)
    "$DYNAMIC" report
    ;;

  # ── EXPORT ──────────────────────────────────────────────────
  # Triggers: export, export data, export research
  export)
    "$DYNAMIC" export
    ;;

  # ── UNKNOWN ─────────────────────────────────────────────────
  *)
    echo "Unknown command: $CMD"
    echo ""
    echo "Valid commands:"
    echo "  health | agents | list | output"
    echo "  run <TID> [victim] | explain <TID>"
    echo "  apt | alerts | reset"
    echo "  auto [tactic] [victim] | smart [tactic] [victim]"
    echo "  learnall [victim] | learnall-all"
    echo "  list-victims | add-victim <ip> [label] | victim-status <id>"
    echo "  profile [victim] | evolve | stats | learned"
    echo "  report | export"
    exit 1
    ;;
esac
