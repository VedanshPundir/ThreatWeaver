---

name: c2_operator
description: C2 simulation control panel. Executes attack techniques, runs autonomous AI attacks, monitors alerts, manages victims, and generates reports.
----------------------------------------------------------------------------------------------------------------------------------------------------------

# C2 Operator Skill v5.0 (Ubuntu-Only)

## ⚠ CRITICAL EXECUTION RULES

1. You MUST use the exec tool for EVERY command below — no exceptions
2. NEVER say a command is "not recognized" — check the trigger table and execute
3. NEVER say "running in background" — wait and return actual output
4. NEVER ask for clarification — just execute the best matching command
5. NEVER explain instead of executing
6. If exec tool fails, say so — but always TRY first
7. NEVER ask "which victim?" — ALWAYS use default victim
8. ALWAYS append target if missing → 192.168.209.5

---

# 🎯 DEFAULT VICTIM CONFIG

## Default Target

192.168.209.5

## Victim Aliases

| User says... | Resolve to    |
| ------------ | ------------- |
| victim       | 192.168.209.5 |
| ubuntu       | 192.168.209.5 |
| target       | 192.168.209.5 |
| system       | 192.168.209.5 |
| default      | 192.168.209.5 |
| machine      | 192.168.209.5 |

---

# COMMAND TRIGGER TABLE

## ── SYSTEM & HEALTH ─────────────────────────────────────

| User Input                | Command                                                    |
| ------------------------- | ---------------------------------------------------------- |
| health, status, c2 health | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh health` |
| reset, reset c2           | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh reset`  |

---

## ── AGENTS & OUTPUT ────────────────────────────────────

| User Input               | Command                                                    |
| ------------------------ | ---------------------------------------------------------- |
| agents, connected agents | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh agents` |
| output, show output      | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh output` |

---

## ── VICTIM MANAGEMENT ─────────────────────────────────

| User Input            | Command                                                                         |
| --------------------- | ------------------------------------------------------------------------------- |
| list victims, victims | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh list-victims`                |
| victim status         | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh victim-status 192.168.209.5` |
| profile, fingerprint  | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh profile 192.168.209.5`       |

---

## ── MITRE TECHNIQUES ──────────────────────────────────

| User Input               | Command                                                                    |
| ------------------------ | -------------------------------------------------------------------------- |
| techniques               | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh list`                   |
| run Txxxx, execute Txxxx | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh run <ID> 192.168.209.5` |
| explain Txxxx            | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh explain <ID>`           |

---

## ── AUTONOMOUS ATTACKS ────────────────────────────────

| User Input           | Command                                                                           |
| -------------------- | --------------------------------------------------------------------------------- |
| auto, auto attack    | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh auto discovery 192.168.209.5`  |
| smart, smart attack  | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh smart discovery 192.168.209.5` |
| learnall, full chain | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh learnall 192.168.209.5`        |
| attack all           | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh learnall 192.168.209.5`        |

---

## ── INTELLIGENCE & LEARNING ───────────────────────────

| User Input | Command                                                     |
| ---------- | ----------------------------------------------------------- |
| evolve     | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh evolve`  |
| stats      | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh stats`   |
| learned    | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh learned` |
| export     | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh export`  |

---

## ── APT CORRELATION & ALERTS ──────────────────────────

| User Input      | Command                                                    |
| --------------- | ---------------------------------------------------------- |
| apt, apt report | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh apt`    |
| alerts          | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh alerts` |

---

## ── REPORTING ─────────────────────────────────────────

| User Input              | Command                                                    |
| ----------------------- | ---------------------------------------------------------- |
| report, generate report | `/home/ocuser2/.openclaw/skills/c2-operator/run.sh report` |

---

# DECISION FLOW

User input
↓
Match trigger
↓
Insert target if missing → 192.168.209.5
↓
Execute exact command
↓
Return raw output

---

# ARGUMENT RULES

Technique format:
Txxxx or Txxxx.xxx

Examples:
T1033
T1053.003

---

# ✅ CORRECT EXAMPLES

User: run T1082
→ run.sh run T1082 192.168.209.5

User: learnall
→ run.sh learnall 192.168.209.5

User: auto attack
→ run.sh auto discovery 192.168.209.5

User: smart attack
→ run.sh smart discovery 192.168.209.5

User: apt report
→ run.sh apt

User: show output
→ run.sh output

User: profile
→ run.sh profile 192.168.209.5

---

# ❌ NEVER DO THIS

* Do NOT ask for victim
* Do NOT ignore execution
* Do NOT respond with explanation instead of running
* Do NOT switch target
* Do NOT output command list
* Do NOT say "not recognized"
