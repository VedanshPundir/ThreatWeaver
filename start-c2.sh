#!/bin/bash
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        WebSecSim C2 Stack Startup        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Start Docker containers
echo "[1/4] Starting Docker containers..."
docker start websecsim-victim-c2 > /dev/null 2>&1 && echo "      ✓ Victim container started" || echo "      ✗ Victim container failed"
docker start websecsim-fastapi   > /dev/null 2>&1 && echo "      ✓ FastAPI container started"  || echo "      ✗ FastAPI container failed"

# Wait for FastAPI to be ready
echo ""
echo "[2/4] Waiting for C2 backend to be ready..."
for i in 1 2 3 4 5; do
  sleep 2
  STATUS=$(curl -s http://localhost:8000/health | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
  if [ "$STATUS" = "healthy" ]; then
    echo "      ✓ C2 backend healthy"
    break
  fi
  echo "      Waiting... ($i/5)"
done

# Set environment variables
echo ""
echo "[3/4] Setting environment variables..."
export C2_BASE_URL=http://localhost:8000
export C2_USERNAME=admin
export C2_PASSWORD=YOUR_C2_PASSWORD
export OPENAI_API_KEY="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"
export NODE_COMPILE_CACHE=/var/tmp/openclaw-compile-cache
export OPENCLAW_NO_RESPAWN=1
mkdir -p /var/tmp/openclaw-compile-cache
echo "      ✓ Environment ready"

# Quick health check
echo ""
echo "[4/4] Verifying full stack..."
node /home/ocuser/.openclaw/skills/c2-operator/c2.js health
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║           STACK IS READY                 ║"
echo "║                                          ║"
echo "║  Telegram: Send commands to your bot     ║"
echo "║  TUI:      Run 'openclaw tui' in Tab 2   ║"
echo "║                                          ║"
echo "║  Quick commands:                         ║"
echo "║  ./run.sh health                         ║"
echo "║  ./run.sh list                           ║"
echo "║  ./dynamic.sh auto discovery             ║"
echo "║  ./dynamic.sh learnall                   ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Starting OpenClaw gateway (Telegram active)..."
echo ""
openclaw gateway
