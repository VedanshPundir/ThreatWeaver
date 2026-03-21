import fs from "fs";
import os from "os";
import path from "path";
import https from "https";
import http from "http";

const C2_BASE_URL  = process.env.C2_BASE_URL  || "http://localhost:8000";
const C2_USERNAME  = process.env.C2_USERNAME  || "admin";
const C2_PASSWORD  = process.env.C2_PASSWORD  || "";
const OPENAI_KEY   = process.env.OPENAI_API_KEY || "";
const OPENAI_URL   = "https://api.openai.com/v1/chat/completions";
const GPT_MODEL    = "gpt-4o-mini";
const TOKEN_CACHE  = path.join(os.homedir(), ".openclaw", "memory", "c2_token.txt");
const LOG_ID_CACHE = path.join(os.homedir(), ".openclaw", "memory", "c2_last_log_id.txt");

function ensureDir(f) {
  const d = path.dirname(f);
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}
function readCache(f, fb) {
  try { return fs.readFileSync(f, "utf8").trim(); } catch { return fb || ""; }
}
function writeCache(f, v) {
  ensureDir(f);
  fs.writeFileSync(f, String(v), "utf8");
}
function hr() { return "─".repeat(50); }

function request(urlStr, options, body) {
  options = options || {};
  return new Promise(function(resolve, reject) {
    const url = new URL(urlStr);
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const bodyStr = body ? JSON.stringify(body) : null;
    const headers = Object.assign({}, options.headers || {});
    if (bodyStr) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(bodyStr);
    }
    const reqOptions = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + (url.search || ""),
      method: options.method || "GET",
      headers: headers,
    };
    const req = lib.request(reqOptions, function(res) {
      let data = "";
      res.on("data", function(c) { data += c; });
      res.on("end", function() {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch(e) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function getToken(force) {
  if (!force) {
    const c = readCache(TOKEN_CACHE, "");
    if (c) return c;
  }
  const body = "username=" + encodeURIComponent(C2_USERNAME) + "&password=" + encodeURIComponent(C2_PASSWORD);
  return new Promise(function(resolve, reject) {
    const url = new URL(C2_BASE_URL + "/token");
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: "/token",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body)
      },
    }, function(res) {
      let d = "";
      res.on("data", function(c) { d += c; });
      res.on("end", function() {
        try {
          const p = JSON.parse(d);
          if (p.access_token) {
            writeCache(TOKEN_CACHE, p.access_token);
            resolve(p.access_token);
          } else {
            reject(new Error("Auth failed: " + d));
          }
        } catch(e) {
          reject(new Error("Auth parse error: " + d));
        }
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function c2req(method, endpoint, body) {
  const token = await getToken(false);
  let res = await request(C2_BASE_URL + endpoint, {
    method: method,
    headers: { Authorization: "Bearer " + token }
  }, body || null);
  if (res.status === 401) {
    const fresh = await getToken(true);
    res = await request(C2_BASE_URL + endpoint, {
      method: method,
      headers: { Authorization: "Bearer " + fresh }
    }, body || null);
  }
  return res;
}

async function gpt(systemPrompt, userMessage, stream) {
  if (!OPENAI_KEY) { console.log("OPENAI_API_KEY not set."); return null; }
  const payload = {
    model: GPT_MODEL,
    max_tokens: 400,
    temperature: 0.4,
    stream: stream || false,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user",   content: userMessage  }
    ]
  };
  if (!stream) {
    const res = await request(OPENAI_URL, {
      method: "POST",
      headers: { Authorization: "Bearer " + OPENAI_KEY }
    }, payload);
    if (res.status !== 200) throw new Error("OpenAI error " + res.status + ": " + JSON.stringify(res.body));
    return res.body.choices[0].message.content.trim();
  }
  return new Promise(function(resolve, reject) {
    const url = new URL(OPENAI_URL);
    const bodyStr = JSON.stringify(payload);
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname,
      method: "POST",
      headers: {
        Authorization: "Bearer " + OPENAI_KEY,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(bodyStr)
      },
    }, function(res) {
      let buf = "";
      res.on("data", function(chunk) {
        buf += chunk.toString();
        const lines = buf.split("\n");
        buf = lines.pop();
        for (let i = 0; i < lines.length; i++) {
          const t = lines[i].trim();
          if (!t || t === "data: [DONE]") continue;
          if (t.indexOf("data: ") === 0) {
            try {
              const d = JSON.parse(t.slice(6));
              const tok = d.choices && d.choices[0] && d.choices[0].delta && d.choices[0].delta.content;
              if (tok) process.stdout.write(tok);
            } catch(e) {}
          }
        }
      });
      res.on("end", function() { process.stdout.write("\n"); resolve(); });
    });
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

async function cmdRun(tCode) {
  if (!tCode) { console.log("Usage: c2.js run <T-CODE>"); process.exit(1); }
  tCode = tCode.toUpperCase();
  const info = await request(C2_BASE_URL + "/api/mitre/" + tCode);
  const name = (info.body && (info.body.technique_name || info.body.name)) || tCode;
  const res = await c2req("POST", "/api/attack/" + tCode);
  if (res.status === 200) {
    console.log("Task queued: " + tCode + " - " + name);
    console.log("Status: " + res.body.status);
  } else if (res.status === 403) {
    console.log("Access denied - admin role required.");
  } else if (res.status === 404) {
    console.log("Technique " + tCode + " not supported. Try: node c2.js list");
  } else {
    console.log("Error " + res.status + ": " + JSON.stringify(res.body));
  }
}

async function cmdList() {
  const res = await request(C2_BASE_URL + "/api/attack/supported");
  if (res.status !== 200) { console.log("Error: " + res.status); return; }
  const techniques = res.body.techniques;
  const count = res.body.count;
  console.log(hr());
  console.log("Supported techniques (" + count + ")");
  console.log(hr());
  for (let i = 0; i < techniques.length; i++) {
    const t = techniques[i];
    const code = (t.technique || "").padEnd(14);
    const name = ((t.name || "Unknown").slice(0, 34)).padEnd(36);
    const cmd  = (t.command || "").slice(0, 40);
    console.log(code + " " + name + " " + cmd);
  }
}

async function cmdAgents() {
  const res = await request(C2_BASE_URL + "/api/agents");
  const agents = res.body || {};
  const keys = Object.keys(agents);
  if (!keys.length) { console.log("No agents connected."); return; }
  console.log("Connected agents (" + keys.length + "):");
  for (let i = 0; i < keys.length; i++) {
    console.log("  " + keys[i] + " - last seen: " + agents[keys[i]].last_seen);
  }
}

async function cmdOutput() {
  const ar = await request(C2_BASE_URL + "/api/agents");
  const hosts = Object.keys(ar.body || {});
  if (!hosts.length) { console.log("No agents connected."); return; }
  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i];
    const res = await request(C2_BASE_URL + "/api/output/" + host);
    const entries = (res.body || []).slice(-5);
    if (!entries.length) { console.log("No output from " + host + " yet."); continue; }
    console.log("\nOutput from: " + host + "\n" + hr());
    for (let j = 0; j < entries.length; j++) {
      const e = entries[j];
      console.log("[" + e.time + "] " + (e.technique || "?"));
      console.log("  " + (e.output || "").slice(0, 200).replace(/\n/g, " "));
    }
  }
}

async function cmdReset() {
  const res = await c2req("POST", "/api/system/reset");
  if (res.status === 200) {
    console.log("C2 session reset.");
  } else {
    console.log("Reset failed: " + JSON.stringify(res.body));
  }
  writeCache(LOG_ID_CACHE, "0");
  writeCache(TOKEN_CACHE, "");
}

async function cmdAlerts() {
  const lastId = parseInt(readCache(LOG_ID_CACHE, "0"), 10);
  const res = await request(C2_BASE_URL + "/api/logs?since_id=" + lastId + "&limit=50");
  if (res.status !== 200) return;
  const logs = res.body.logs;
  const latest_id = res.body.latest_id;
  if (!logs || logs.length === 0) {
    if (latest_id !== undefined) writeCache(LOG_ID_CACHE, latest_id);
    return;
  }
  const important = logs.filter(function(l) { return l.level === "critical" || l.level === "alert"; });
  if (important.length > 0) {
    console.log("C2 Live Alerts (" + important.length + " new)\n" + hr());
    for (let i = 0; i < important.length; i++) {
      const log = important[i];
      const icon = log.level === "critical" ? "[CRITICAL]" : "[ALERT]";
      console.log(icon + " " + log.category + " - " + log.msg);
      console.log("  Source: " + log.source + " | Time: " + log.ts);
      if (log.details && log.details.technique) {
        console.log("  Technique: " + log.details.technique);
      }
    }
  }
  if (latest_id !== undefined) writeCache(LOG_ID_CACHE, latest_id);
}

async function cmdExplain(tCode) {
  if (!tCode) { console.log("Usage: c2.js explain <T-CODE>"); process.exit(1); }
  tCode = tCode.toUpperCase();
  const res = await request(C2_BASE_URL + "/api/mitre/" + tCode);
  if (res.status !== 200) { console.log("Technique " + tCode + " not found."); return; }
  const t = res.body;
  console.log(hr());
  console.log((t.technique_id || tCode) + " - " + (t.technique_name || t.name || ""));
  console.log("Tactics: " + (t.tactics || []).join(", "));
  console.log("Platforms: " + (t.platforms || []).join(", "));
  console.log(hr());
  console.log("GPT-4o mini analysis:\n");
  await gpt(
    "You are a senior threat intelligence analyst. Given a MITRE ATT&CK technique provide:\n**Summary**: 2-sentence plain-English explanation.\n**Why attackers use it**: 1-2 sentences.\n**Top 2 detection indicators**: bullet list.\n**One hardening tip**: single actionable sentence.\nUnder 180 words total.",
    "Technique: " + (t.technique_id || tCode) + "\nName: " + (t.technique_name || t.name) + "\nTactics: " + (t.tactics || []).join(", ") + "\nDescription: " + (t.description || "").slice(0, 500),
    true
  );
}

async function cmdAnalyze(tCode, command, output) {
  if (!output) { console.log("Usage: c2.js analyze <T-CODE> <COMMAND> <OUTPUT>"); process.exit(1); }
  console.log("Analyzing output for " + (tCode || "unknown") + "...\n");
  await gpt(
    "You are a red team analyst. Respond in exactly 4 bullet points:\n- Key findings\n- Risk level (Critical/High/Medium/Low) with justification\n- Attack path: how an adversary uses this\n- Defender action: one immediate blue team step\nUnder 150 words.",
    "Technique: " + (tCode || "Unknown") + "\nCommand: " + (command || "N/A") + "\nOutput:\n" + (output || "").slice(0, 2000),
    true
  );
}

async function cmdHunt(techniquesStr, timeframe) {
  if (!techniquesStr) { console.log("Usage: c2.js hunt 'T1003,T1082' 'last 24h'"); process.exit(1); }
  const codes = techniquesStr.split(",").map(function(s) { return s.trim().toUpperCase(); });
  const details = [];
  for (let i = 0; i < codes.length; i++) {
    const res = await request(C2_BASE_URL + "/api/mitre/" + codes[i]);
    const name = res.status === 200 ? (res.body.technique_name || res.body.name || "Unknown") : "not found";
    details.push("- " + codes[i] + ": " + name);
  }
  console.log("Threat hunt - " + codes.length + " techniques, " + (timeframe || "unspecified") + "\n");
  await gpt(
    "You are a threat hunter. Respond:\n**Adversary profile**: most likely threat actor type.\n**Kill chain stage**: where this cluster sits in ATT&CK.\n**3 hunting queries**: specific log searches or SIEM queries.\n**Priority action**: single most important next step.\nUnder 200 words.",
    "Techniques (" + (timeframe || "unknown") + "):\n" + details.join("\n"),
    true
  );
}

async function cmdChat(message) {
  if (!message) { console.log("Usage: c2.js chat 'question'"); process.exit(1); }
  await gpt(
    "You are a concise cybersecurity assistant in a C2 simulation environment. Answer in 3-5 sentences. Be technically accurate and actionable.",
    message,
    true
  );
}

async function cmdApt() {
  const res = await request(C2_BASE_URL + "/api/apt/correlate?top_n=5");
  if (res.status !== 200) { console.log("APT correlator not ready: " + res.status); return; }
  const data = res.body;
  if (data.message) { console.log(data.message); return; }
  console.log(hr());
  console.log("APT Correlation Report");
  console.log("Executed: " + data.executed_count + " techniques | Groups: " + data.group_count);
  console.log("Techniques: " + (data.executed_techniques || []).join(", "));
  console.log(hr());
  const matches = data.top_matches || [];
  if (!matches.length) { console.log("No APT overlap yet. Run more attack techniques."); return; }
  for (let i = 0; i < matches.length; i++) {
    const g = matches[i];
    const aliases = (g.aliases || []).filter(function(a) { return a !== g.name; }).slice(0, 3).join(" / ");
    console.log("\nRank " + g.rank + " - " + g.name + " (" + g.group_id + ")" + (aliases ? " - " + aliases : ""));
    console.log("  Match  : " + g.overlap_count + "/" + g.group_total + " (" + g.score_pct + "%)");
    console.log("  Matched: " + (g.matched_techniques || []).join(", "));
  }
  console.log("\n" + hr());
}

async function cmdHealth() {
  const res = await request(C2_BASE_URL + "/health");
  if (res.status !== 200) { console.log("C2 unreachable at " + C2_BASE_URL); return; }
  const h = res.body;
  console.log("C2 Health Check\n" + hr());
  console.log("  Status     : " + h.status);
  console.log("  MITRE      : " + (h.mitre_loaded ? "loaded" : "NOT loaded") + " (" + h.technique_count + " techniques, source: " + h.mitre_source + ")");
  console.log("  Agents     : " + h.agents_connected);
  console.log("  AI model   : " + h.ai_model + " (" + (h.ai_configured ? "configured" : "NOT configured") + ")");
  console.log("  APT groups : " + h.apt_groups_loaded + " loaded");
  console.log("  Executed   : " + h.executed_techniques + " techniques");
}

const args = process.argv.slice(2);
const cmd  = args[0];
const rest = args.slice(1);

const commands = {
  run:     function() { return cmdRun(rest[0]); },
  list:    function() { return cmdList(); },
  agents:  function() { return cmdAgents(); },
  output:  function() { return cmdOutput(); },
  reset:   function() { return cmdReset(); },
  alerts:  function() { return cmdAlerts(); },
  explain: function() { return cmdExplain(rest[0]); },
  analyze: function() { return cmdAnalyze(rest[0], rest[1], rest[2]); },
  hunt:    function() { return cmdHunt(rest[0], rest[1]); },
  chat:    function() { return cmdChat(rest[0]); },
  apt:     function() { return cmdApt(); },
  health:  function() { return cmdHealth(); },
  help:    function() { console.log("Commands: run list agents output reset alerts explain analyze hunt chat apt health"); return Promise.resolve(); },
};

if (!cmd || !commands[cmd]) {
  console.log("Unknown command: " + (cmd || "(none)") + ". Run: node c2.js help");
  process.exit(1);
}

commands[cmd]().catch(function(err) {
  console.error("Error: " + err.message);
  process.exit(1);
});
