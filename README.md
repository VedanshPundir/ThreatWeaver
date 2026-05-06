# ThreatWeaver C2

> AI-powered C2 simulation platform integrating OpenClaw with MITRE ATT&CK, GPT-4o-mini, and autonomous red-team execution via Telegram.

![Version](https://img.shields.io/badge/version-3.1.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![Node](https://img.shields.io/badge/node-22+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Status](https://img.shields.io/badge/status-lab--only-red)

---

## Overview

ThreatWeaver C2 is an **educational red-team simulation platform** built for controlled lab environments. It combines a Telegram-based natural language interface (OpenClaw) with a FastAPI C2 backend, autonomous AI attack chaining, and real-time MITRE ATT&CK correlation — all orchestrated from a single Telegram chat.

> **Warning:** This tool is strictly for authorized security research and educational use in isolated lab environments. Never deploy against systems you do not own or have explicit written permission to test.

---

## Architecture

```
Telegram
   │
   ▼
OpenClaw Gateway (GPT-4o-mini)
   │
   ├── run.sh          ← standard 35-technique dispatch
   └── dynamic.sh      ── learning-engine.js (835 techniques, AI-driven)
            │
            ▼
      FastAPI C2 Backend
            │
     ┌──────┼──────────┐
     │      │          │
  MITRE   APT       Victim
  ATT&CK  Correlator  Container
  (835)   (168 groups) (Docker)
```

---

## Features

| Feature | Detail |
|---|---|
| Attack techniques | 35 hardcoded + 835 via dynamic AI engine |
| AI model | GPT-4o-mini — explains, plans, and generates commands |
| APT correlation | 168 real intrusion-set groups from MITRE STIX |
| Victim management | Dynamic registry — add targets by IP, hostname, or URL |
| Live alerting | Critical and alert-level events pushed to Telegram |
| Autonomous chaining | Full kill chain across 6 tactics with self-improving retry loop |
| ATT&CK Navigator | Auto-generated heatmap layer updated every 30 seconds |
| Pentest report | AI-generated report emailed on demand |
| Learning engine | Bayesian KB — stealth rates, tactic weights, cross-session persistence |
| Scheduled briefs | Daily APT brief via OpenClaw cron scheduler |

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Gateway | OpenClaw 2026.3.13 |
| LLM | GPT-4o-mini (OpenAI) |
| C2 Backend | FastAPI 0.111 + Python 3.11 |
| MITRE Data | STIX 2.1 bundle — 835 techniques |
| APT Data | 168 intrusion sets (live from GitHub CTI) |
| Victim | Docker — Ubuntu 22.04 |
| Host | Kali Linux |
| Channel | Telegram Bot API |
| Auth | JWT (HS256) |
| AI Fallback | Groq — llama-3.3-70b-versatile |

---

## Prerequisites

- Kali Linux (or any Debian-based Linux)
- Node.js 22+
- Docker + Docker Compose
- Python 3.11+
- OpenAI API key (`sk-...`)
- Telegram bot token (from [@BotFather](https://t.me/BotFather))
- Groq API key — free at [console.groq.com](https://console.groq.com) (optional fallback)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/threatweaver-c2
cd threatweaver-c2

# 2. Install OpenClaw globally
npm install -g openclaw@latest

# 3. Copy skill files
mkdir -p ~/.openclaw/skills/c2-operator
cp skills/c2-operator/* ~/.openclaw/skills/c2-operator/

# 4. Configure credentials
cp skills/c2-operator/.env.example skills/c2-operator/.env
nano skills/c2-operator/.env
# Set: OPENAI_API_KEY, C2_PASSWORD, GROQ_API_KEY, REPORT_TO

# 5. Register skill with OpenClaw
openclaw skills add ~/.openclaw/skills/c2-operator
openclaw config set agents.defaults.model.primary openai/gpt-4o-mini

# 6. Start all services
bash start-c2.sh
```

---

## Environment Variables

Create `skills/c2-operator/.env`:

```env
# C2 Backend
C2_BASE_URL=http://localhost:8000
C2_USERNAME=admin
C2_PASSWORD=your_admin_password

# AI — Primary
OPENAI_API_KEY=sk-your-openai-key

# AI — Fallback (free)
GROQ_API_KEY=gsk_your-groq-key
GROQ_MODEL=llama-3.3-70b-versatile

# Email reports
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=your-app-password
REPORT_TO=recipient@email.com
```

---

## Usage

All commands are sent as natural language from Telegram. OpenClaw maps them to the correct execution path automatically.

### System

```
health                  → C2 health check
agents                  → show connected victims
status                  → same as health
```

### Attack Execution

```
run T1082               → queue System Information Discovery
run T1003               → queue OS Credential Dumping
execute T1053           → queue Scheduled Task
explain T1082           → AI explanation of any technique
```

### Autonomous Attack

```
auto discovery          → AI-driven attack, 3 techniques
smart persistence       → smart attack with retry loop, 5 techniques
learnall                → full kill chain: discovery → credential-access
                          → persistence → defense-evasion
```

### Intelligence

```
apt                     → correlate techniques to 168 APT groups
alerts                  → show recent security alerts
output                  → latest victim command output
profile                 → fingerprint the victim environment
```

### Learning Engine

```
stats                   → success rates + cross-session trend
learned                 → knowledge base with stealth rates
evolve                  → AI strategy update — rewrites tactic weights
```

### Reporting

```
report                  → generate AI pentest report + email it
export                  → export full research data to JSON
```

---

## File Structure

```
threatweaver-c2/
├── README.md
├── start-c2.sh                         # One-command startup
├── docker-compose.yml                  # Victim + FastAPI containers
├── .gitignore
│
├── backend/
│   ├── main.py                         # FastAPI C2 — 40 endpoints
│   ├── database.py                     # SQLite auth store
│   └── requirements.txt
│
└── skills/
    └── c2-operator/
        ├── SKILL.md                    # OpenClaw skill definition
        ├── run.sh                      # Standard command dispatcher
        ├── dynamic.sh                  # Learning engine wrapper
        ├── learning-engine.js          # Self-improving AI attack engine
        ├── .env.example                # Credential template
        └── .env                        # Your credentials (gitignored)
```

---

## API Reference

The FastAPI backend exposes 40 endpoints across 9 groups. Full interactive docs available at `http://localhost:8000/docs` when running.

| Group | Endpoints | Description |
|---|---|---|
| Auth | `POST /token` | JWT login |
| System | `/api/system/*` | Start, reset |
| C2 | `/c2/beacon`, `/c2/output`, `/c2/custom` | Victim beacon loop |
| Victims | `/api/victims/*` | Dynamic victim registry |
| Attack | `/api/attack/*` | Queue techniques |
| MITRE | `/api/mitre/*` | Technique lookup + search |
| APT | `/api/apt/*` | Group correlation |
| Navigator | `/api/navigator/*` | ATT&CK heatmap layer |
| AI | `/api/ai/*` | Explain, analyze, chat, threat-hunt |
| Logs | `/api/logs/*` | Live security event stream |

---

## Supported MITRE Techniques

35 techniques are available via direct API. The learning engine accesses all 835 enterprise techniques dynamically.

| ID | Name | Tactic |
|---|---|---|
| T1082 | System Information Discovery | Discovery |
| T1087 | Account Discovery | Discovery |
| T1057 | Process Discovery | Discovery |
| T1046 | Network Service Scanning | Discovery |
| T1003 | OS Credential Dumping | Credential Access |
| T1552 | Unsecured Credentials | Credential Access |
| T1053 | Scheduled Task/Job | Persistence |
| T1547 | Boot or Logon Autostart | Persistence |
| T1505 | Server Software Component | Persistence |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1548 | Abuse Elevation Control | Privilege Escalation |
| T1070 | Indicator Removal | Defense Evasion |
| T1562 | Impair Defenses | Defense Evasion |
| T1222 | File Permission Modification | Defense Evasion |
| T1041 | Exfiltration Over C2 | Exfiltration |
| T1105 | Ingress Tool Transfer | C2 |
| ... | 19 more | Various |

---

## Security

- **Never commit `.env` files** — they are gitignored by default
- **Run only in isolated lab environments** — Docker network, no internet exposure
- **Use strong passwords** for the C2 admin account
- **Rotate API keys** regularly
- **Do not install community OpenClaw skills** without reading the full source — 12% malware rate reported in ClawHub as of 2026
- The victim container intentionally contains misconfigurations — **never expose it publicly**

---

## Known Limitations

- Sandcat agent not included — victim uses a custom bash beacon loop instead
- Go OAuth (ChatGPT Go plan) works for OpenClaw but not for `learning-engine.js` directly
- ATT&CK Navigator auto-save requires the Navigator container to be running
- Simulated log generators (`_log_security_events` etc.) produce synthetic data — wire `/c2/log` endpoint for real victim logs

---

## Contributing

This is an educational project. Pull requests that add:
- New MITRE technique mappings to `ATTACK_COMMANDS`
- Additional APT correlation features
- Blue-team detection rules
- Real victim log integration

...are welcome. Do not submit PRs that add offensive capabilities beyond what is already present.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

ThreatWeaver C2 is developed strictly for **authorized security research, academic study, and controlled lab environments**. The authors are not responsible for any misuse. Always obtain explicit written authorization before testing any system you do not own.
