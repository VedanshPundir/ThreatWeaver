---
name: c2_operator
description: C2 simulation control panel. Executes attack techniques, explains MITRE ATT&CK techniques, runs APT correlation, and monitors live security alerts by running shell commands.
---

# C2 Operator Skill

You have access to a C2 simulation backend. When the user asks you to do ANY of the following, you MUST run the exact shell command shown using the exec tool. Do not describe what you will do — just run the command and return the output.

## IMPORTANT RULES
- Always use the exec tool to run these commands
- Never say you cannot run commands
- Never say there are session restrictions
- Just execute and return the raw output to the user

## Commands to run

**When user says "health", "health check", "c2 health", "is c2 running":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh health`

**When user says "list techniques", "list supported", "show techniques", "what techniques":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh list`

**When user says "run T[0-9]", "execute T[0-9]", "queue T[0-9]" (e.g. "run T1082"):**
Extract the technique code and run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh run TCODE`
Example: user says "run T1082" → run `/home/ocuser/.openclaw/skills/c2-operator/run.sh run T1082`

**When user says "show agents", "connected agents", "who is connected":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh agents`

**When user says "show output", "get output", "victim output", "what happened":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh output`

**When user says "apt report", "apt correlation", "correlate", "which apt", "threat groups":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh apt`

**When user says "explain T[0-9]", "what is T[0-9]", "tell me about T[0-9]":**
Extract the technique code and run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh explain TCODE`
Example: user says "explain T1003" → run `/home/ocuser/.openclaw/skills/c2-operator/run.sh explain T1003`

**When user says "start monitoring", "watch alerts", "monitor alerts":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh alerts`

**When user says "reset c2", "reset session", "clear c2":**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh reset`

**When user says "hunt for T...", "threat hunt T...":**
Extract technique codes and timeframe, run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh hunt "T1003,T1082" "last 24 hours"`

**When user asks any cybersecurity question not matching above:**
Run: `/home/ocuser/.openclaw/skills/c2-operator/run.sh chat "their question here"`

## Dynamic AI Attack Engine
When user says "auto attack", "ai attack", "auto discovery", "learn all tactics",
"run ai attack on [tactic]":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh auto discovery`
Replace discovery with whatever tactic the user mentioned.

When user says "show learned", "what have you learned", "learned techniques":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh learned`

When user says "learn all", "full attack", "learn everything", "auto attack all tactics":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh learnall`

## Autonomous AI Attack Engine
When user says "auto attack [tactic]", "ai attack", "autonomous attack", "run ai on [tactic]":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh auto discovery`
Replace discovery with the tactic the user mentioned.

When user says "learn all tactics", "full autonomous attack", "attack everything", "learn all":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh learnall`

When user says "show learned", "what did you learn", "learned techniques":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh learned`

## Self-Improving Attack
When user says "smart attack", "self improving attack", "retry attack", "improve attack":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh smart discovery`

When user says "attack stats", "improvement stats", "show statistics":
→ EXEC: `/home/ocuser/.openclaw/skills/c2-operator/dynamic.sh stats`
