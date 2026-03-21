# WebSecSim C2 — OpenClaw Integration

AI-powered C2 simulation platform integrating OpenClaw with MITRE ATT&CK,
GPT-4o mini, and autonomous attack execution via Telegram.

## Architecture
```
Telegram → OpenClaw Gateway → GPT-4o mini → c2.js → FastAPI C2 → Victim
```

## Features

- 35 hardcoded MITRE ATT&CK techniques via standard API
- 835 techniques accessible via dynamic AI engine
- GPT-4o mini explains any technique on demand
- APT correlation against 168 real threat groups
- Live alert push to Telegram (critical/alert events)
- Autonomous attack chaining across 6 tactics
- Self-improving retry loop with failure memory
- Daily APT brief via OpenClaw cron scheduler

## Stack

| Component     | Technology                        |
|---------------|-----------------------------------|
| AI Gateway    | OpenClaw 2026.3.13                |
| LLM           | GPT-4o mini (OpenAI)              |
| C2 Backend    | FastAPI + Python                  |
| MITRE Data    | STIX bundle (835 techniques)      |
| APT Data      | 168 intrusion sets                |
| Victim        | Docker (Ubuntu 22.04)             |
| Host          | Kali Linux                        |
| Channel       | Telegram Bot API                  |

## Installation

### Prerequisites
- Kali Linux
- Node.js 22+
- Docker
- OpenAI API key
- Telegram bot token

### Setup
```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/websecssim-c2-openclaw
cd websecssim-c2-openclaw

# 2. Install OpenClaw
npm install -g openclaw@latest

# 3. Copy skill files
mkdir -p ~/.openclaw/skills/c2-operator
cp skills/c2-operator/* ~/.openclaw/skills/c2-operator/

# 4. Set credentials in run.sh and dynamic.sh
nano skills/c2-operator/run.sh
# Replace YOUR_OPENAI_API_KEY and YOUR_C2_PASSWORD

# 5. Start everything
bash start-c2.sh
```

## Usage

### From Telegram
```
# Health check
use the exec tool to run: /home/ocuser/.openclaw/skills/c2-operator/run.sh health

# Run attack technique
use the exec tool to run: /home/ocuser/.openclaw/skills/c2-operator/run.sh run T1082

# Explain technique
use the exec tool to run: /home/ocuser/.openclaw/skills/c2-operator/run.sh explain T1003

# APT correlation
use the exec tool to run: /home/ocuser/.openclaw/skills/c2-operator/run.sh apt

# Autonomous AI attack
use the exec tool to run: /home/ocuser/.openclaw/skills/c2-operator/dynamic.sh smart discovery

# Full autonomous attack across all tactics
use the exec tool to run: /home/ocuser/.openclaw/skills/c2-operator/dynamic.sh learnall
```

## File Structure
```
websecssim-c2-openclaw/
├── README.md
├── start-c2.sh                        # One-command startup
├── .gitignore
└── skills/
    └── c2-operator/
        ├── SKILL.md                   # OpenClaw skill definition
        ├── c2.js                      # Core C2 helper (35 techniques)
        ├── run.sh                     # Wrapper with env vars
        ├── dynamic-attack.js          # AI autonomous engine (835 techniques)
        └── dynamic.sh                 # Dynamic engine wrapper
```

## Security

- Keep this repo PRIVATE
- Never commit real API keys
- Use environment variables for credentials
- Run only in isolated lab environments
