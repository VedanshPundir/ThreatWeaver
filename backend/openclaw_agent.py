#!/usr/bin/env python3
"""
Intelligent OpenClaw Autonomous Red Team Agent
Analyzes command outputs to make strategic decisions like a real attacker
"""

import requests
import json
import os
import httpx
import asyncio
import time
import sys
import re
from typing import List, Dict, Any, Optional, Set

# ================= CONFIG =================

API_URL = "http://localhost:8000/api/attack/openclaw"
TOKEN_URL = "http://localhost:8000/token"
OUTPUT_URL = "http://localhost:8000/api/output/websecsim-victim-c2"
MITRE_URL = "http://localhost:8000/api/mitre"
CHECK_URL = "http://localhost:8000/api/openclaw/check"

USERNAME = "admin"
PASSWORD = "admin123"

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
MODEL = "llama-3.3-70b-versatile"
MAX_STEPS = 7
DELAY_BETWEEN_STEPS = 3

# ==========================================

class IntelligentOpenClawAgent:
    def __init__(self):
        self.token = None
        self.headers = None
        self.executed_techniques: List[str] = []  # List of technique IDs executed
        self.results: List[Dict] = []  # Detailed results with outputs
        # Better structured knowledge base
        self.knowledge_base = {
            "system": {
                "os": None,
                "kernel": None,
                "hostname": None,
                "architecture": None
            },
            "users": {
                "found": [],
                "total_count": 0,
                "privileged": []
            },
            "processes": {
                "running": [],
                "suspicious": [],
                "security_tools": []
            },
            "network": {
                "interfaces": [],
                "listening_ports": [],
                "connections": [],
                "dns_servers": []
            },
            "credentials": {
                "found": False,
                "locations": [],
                "types": []
            },
            "filesystem": {
                "sensitive_files": [],
                "writable_dirs": []
            },
            "vulnerabilities": {
                "found": [],
                "privilege_escalation": []
            }
        }
        
        # Technique to tactic mapping for strategic decisions
        self.technique_tactics = {
            "T1057": "discovery",      # Process Discovery
            "T1082": "discovery",      # System Information Discovery
            "T1087": "discovery",      # Account Discovery
            "T1046": "discovery",      # Network Service Scanning
            "T1016": "discovery",      # System Network Configuration Discovery
            "T1033": "discovery",      # System Owner/User Discovery
            "T1003": "credential-access",  # OS Credential Dumping
            "T1552": "credential-access",  # Unsecured Credentials
            "T1548": "privilege-escalation",  # Abuse Elevation Control Mechanism
            "T1068": "privilege-escalation",  # Exploitation for Privilege Escalation
            "T1053": "persistence",    # Scheduled Task/Job
            "T1070": "defense-evasion", # Indicator Removal
        }
        
    def get_token(self):
        """Get JWT authentication token"""
        print("[*] Authenticating with C2 server...")
        try:
            res = requests.post(
                TOKEN_URL,
                data={"username": USERNAME, "password": PASSWORD},
                timeout=10
            )
            if res.status_code != 200:
                print(f"[!] Login failed: {res.text}")
                sys.exit(1)
            self.token = res.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
            print("[✓] Authentication successful")
            return True
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            sys.exit(1)
    
    def get_technique_info(self, technique: str) -> Dict:
        """Get MITRE technique details"""
        try:
            res = requests.get(
                f"{MITRE_URL}/{technique}",
                headers=self.headers,
                timeout=10
            )
            if res.status_code == 200:
                return res.json()
            return {}
        except:
            return {}
    
    def get_command_outputs(self) -> List[Dict]:
        """Fetch all command outputs from the victim"""
        try:
            res = requests.get(
                OUTPUT_URL,
                headers=self.headers,
                timeout=10
            )
            if res.status_code == 200:
                return res.json()
            return []
        except:
            return []
    
    def extract_intelligence(self, technique: str, output: str):
        """Extract intelligence from command output"""
        
        if not output:
            return
            
        output_lower = output.lower()
        
        if technique == "T1082":  # System Info Discovery
            # Extract OS info
            if "linux" in output_lower:
                self.knowledge_base["system"]["os"] = "Linux"
            elif "windows" in output_lower:
                self.knowledge_base["system"]["os"] = "Windows"
            elif "darwin" in output_lower or "mac" in output_lower:
                self.knowledge_base["system"]["os"] = "macOS"
            
            # Extract kernel/hostname
            lines = output.split('\n')
            for line in lines[:10]:
                if "linux" in line.lower() and "version" in line.lower():
                    self.knowledge_base["system"]["kernel"] = line.strip()
                if "@" in line and not ":" in line:  # Possible hostname
                    parts = line.split()
                    for part in parts:
                        if "." in part and not part.startswith("192."):
                            self.knowledge_base["system"]["hostname"] = part
            
            print(f"    [ℹ️] OS: {self.knowledge_base['system']['os'] or 'Unknown'}")
        
        elif technique == "T1087":  # Account Discovery
            users = []
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("_"):
                    # Handle /etc/passwd format
                    if ':' in line:
                        username = line.split(':')[0]
                        if username and len(username) < 32:  # Valid username length
                            users.append(username)
                    # Handle simple list format
                    elif len(line.split()) == 1 and len(line) < 32:
                        users.append(line)
            
            if users:
                self.knowledge_base["users"]["found"] = list(set(users))
                self.knowledge_base["users"]["total_count"] = len(users)
                # Check for privileged users
                privileged = [u for u in users if u in ['root', 'admin', 'administrator', 'sudo']]
                self.knowledge_base["users"]["privileged"] = privileged
                print(f"    [👥] Found {len(users)} users: {', '.join(users[:5])}")
        
        elif technique == "T1057":  # Process Discovery
            processes = []
            security_tools = ['avast', 'avg', 'clamav', 'snort', 'ossec', 'falcon', 'crowdstrike', 
                             'carbon', 'defender', 'symantec', 'mcafee', 'kaspersky']
            
            lines = output.split('\n')
            for line in lines[:30]:  # Check first 30 lines
                parts = line.split()
                if len(parts) > 10:  # ps aux format
                    process_name = parts[10] if len(parts) > 10 else ""
                    if process_name and process_name not in ['ps', 'grep', 'bash', 'sh', 'python']:
                        processes.append(process_name)
                        
                        # Check for security tools
                        for tool in security_tools:
                            if tool in process_name.lower():
                                self.knowledge_base["processes"]["security_tools"].append(process_name)
            
            if processes:
                self.knowledge_base["processes"]["running"] = list(set(processes))[:15]
                if self.knowledge_base["processes"]["security_tools"]:
                    print(f"    [🛡️] Security tools detected: {', '.join(self.knowledge_base['processes']['security_tools'])}")
        
        elif technique == "T1046":  # Network Service Scanning
            listening = []
            lines = output.split('\n')
            for line in lines:
                if 'listen' in line.lower() or 'listening' in line.lower():
                    listening.append(line.strip())
                # Extract port info
                match = re.search(r':(\d+)', line)
                if match and ('tcp' in line.lower() or 'udp' in line.lower()):
                    port = match.group(1)
                    if port not in ['22', '80', '443']:  # Common ports
                        listening.append(f"Port {port} - {line.strip()}")
            
            if listening:
                self.knowledge_base["network"]["listening_ports"] = listening[:10]
                print(f"    [🌐] Found {len(listening)} listening services")
        
        elif technique == "T1003":  # Credential Dumping
            if "shadow" in output_lower or "password" in output_lower:
                self.knowledge_base["credentials"]["found"] = True
                self.knowledge_base["credentials"]["locations"].append("/etc/shadow")
                print(f"    [🔑] CREDENTIAL MATERIAL FOUND!")
                
                # Check if we got actual hashes
                if ':' in output and '$' in output:  # Possible hash format
                    lines = output.split('\n')
                    hash_count = 0
                    for line in lines:
                        if ':' in line and '$' in line:
                            hash_count += 1
                    if hash_count > 0:
                        print(f"    [💀] Extracted {hash_count} password hashes")
    
    async def analyze_with_ai(self, technique: str, output: str) -> Dict:
        """Use AI to analyze command output"""
        
        if not output or len(output) < 10:
            return {"findings": ["No significant output to analyze"], "risk_level": "LOW"}
        
        prompt = f"""Analyze this command output from a red team operation:

Technique: {technique}
Output:
{output[:1500]}

Provide a brief analysis in this JSON format:
{{
    "findings": ["key finding 1", "key finding 2"],
    "risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
    "next_moves": ["suggestion1", "suggestion2"]
}}
"""
        
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "You are a red team operator analyzing command outputs. Be concise."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 200
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload
                )
            
            if res.status_code == 200:
                data = res.json()
                content = data["choices"][0]["message"]["content"]
                
                # Extract JSON
                try:
                    start = content.find("{")
                    end = content.rfind("}") + 1
                    if start >= 0 and end > start:
                        return json.loads(content[start:end])
                except:
                    pass
            
            return {"findings": ["Analysis unavailable"], "risk_level": "MEDIUM"}
            
        except Exception as e:
            return {"findings": [f"Analysis error: {str(e)[:50]}"], "risk_level": "MEDIUM"}
    
    async def execute_and_analyze(self, technique: str) -> bool:
        """Execute a technique and analyze its output"""
        
        print(f"\n[▶] EXECUTING: {technique}")
        
        # Get technique info
        tech_info = self.get_technique_info(technique)
        tech_name = tech_info.get('technique_name', 'Unknown')
        print(f"    📋 {tech_name}")
        
        try:
            # Execute the attack
            res = requests.post(
                API_URL,
                json={"technique": technique},
                headers=self.headers,
                timeout=15
            )
            
            if res.status_code != 200:
                print(f"    [!] Execution failed: {res.status_code}")
                return False
            
            print(f"    ✓ Queued for execution")
            print(f"    ⏳ Waiting for output...")
            await asyncio.sleep(3)
            
            # Get outputs
            outputs = self.get_command_outputs()
            
            # Find our technique's output
            technique_output = None
            for output in reversed(outputs):
                if output.get('technique') == technique:
                    technique_output = output.get('output', '')
                    break
            
            if technique_output:
                preview = technique_output[:150].replace('\n', ' ')
                print(f"    📄 Output: {preview}...")
                
                # Extract intelligence
                self.extract_intelligence(technique, technique_output)
                
                # AI Analysis
                print(f"    🤖 Analyzing...")
                analysis = await self.analyze_with_ai(technique, technique_output)
                
                # Store result
                self.results.append({
                    "technique": technique,
                    "name": tech_name,
                    "output": technique_output,
                    "analysis": analysis,
                    "timestamp": time.time()
                })
                
                self.executed_techniques.append(technique)
                
                # Show AI findings
                if analysis.get('findings'):
                    for finding in analysis['findings'][:2]:
                        print(f"    🔍 {finding}")
                if analysis.get('risk_level'):
                    print(f"    ⚠️  Risk: {analysis['risk_level']}")
                
                return True
            else:
                print(f"    ⚠️  No output captured")
                self.executed_techniques.append(technique)
                return True
                
        except Exception as e:
            print(f"    [!] Error: {e}")
            return False
    
    def get_completed_tactics(self) -> Set[str]:
        """Get set of tactics we've completed"""
        completed = set()
        for tech in self.executed_techniques:
            if tech in self.technique_tactics:
                completed.add(self.technique_tactics[tech])
        return completed
    
    async def decide_next_technique(self) -> Optional[str]:
        """Intelligently decide next technique based on intelligence"""
        
        completed_tactics = self.get_completed_tactics()
        
        # Strategy decision tree
        if "T1082" not in self.executed_techniques:
            print("[🤔] No system information - running reconnaissance")
            return "T1082"
        
        if not self.knowledge_base["users"]["found"]:
            print("[🤔] Need user accounts - discovering users")
            return "T1087"
        
        if not self.knowledge_base["processes"]["running"]:
            print("[🤔] Checking running processes")
            return "T1057"
        
        if not self.knowledge_base["network"]["listening_ports"]:
            print("[🤔] Scanning for network services")
            return "T1046"
        
        # If we have recon but no credentials, go for credentials
        if ("discovery" in completed_tactics and 
            "credential-access" not in completed_tactics):
            print("[🤔] Recon complete - attempting credential access")
            return "T1003"
        
        # If we found credentials, try privilege escalation
        if (self.knowledge_base["credentials"]["found"] and
            "privilege-escalation" not in completed_tactics):
            print("[🤔] Credentials obtained - escalating privileges")
            return "T1548"
        
        # Try unsecured credentials if we haven't yet
        if "T1552" not in self.executed_techniques:
            print("[🤔] Searching for unsecured credentials")
            return "T1552"
        
        # Try persistence
        if "persistence" not in completed_tactics:
            print("[🤔] Establishing persistence")
            return "T1053"
        
        # If we've done everything, use AI to decide
        available = [t for t in self.technique_tactics.keys() 
                    if t not in self.executed_techniques]
        
        if available:
            print(f"[🤔] Choosing from {len(available)} remaining techniques")
            return available[0]
        
        return None
    
    def print_intelligence_summary(self):
        """Print what we've learned about the target"""
        
        print("\n" + "="*70)
        print("📊 INTELLIGENCE SUMMARY")
        print("="*70)
        
        print(f"\n🎯 Target Profile:")
        if self.knowledge_base["system"]["os"]:
            print(f"  • OS: {self.knowledge_base['system']['os']}")
        if self.knowledge_base["system"]["hostname"]:
            print(f"  • Hostname: {self.knowledge_base['system']['hostname']}")
        
        print(f"\n👥 Users:")
        user_count = len(self.knowledge_base["users"]["found"])
        if user_count > 0:
            print(f"  • Total accounts: {user_count}")
            if self.knowledge_base["users"]["privileged"]:
                print(f"  • Privileged: {', '.join(self.knowledge_base['users']['privileged'])}")
        
        print(f"\n⚙️  Processes:")
        proc_count = len(self.knowledge_base["processes"]["running"])
        if proc_count > 0:
            print(f"  • Running: {proc_count} processes")
            if self.knowledge_base["processes"]["security_tools"]:
                tools = list(set(self.knowledge_base["processes"]["security_tools"]))
                print(f"  • 🛡️  Security: {', '.join(tools[:3])}")
        
        print(f"\n🌐 Network:")
        port_count = len(self.knowledge_base["network"]["listening_ports"])
        if port_count > 0:
            print(f"  • Listening services: {port_count}")
        
        print(f"\n🔑 Credentials:")
        if self.knowledge_base["credentials"]["found"]:
            print(f"  • ✅ CREDENTIALS OBTAINED")
        
        print(f"\n📋 Techniques Used:")
        for tech in self.executed_techniques:
            tactic = self.technique_tactics.get(tech, "unknown")
            print(f"  • {tech} ({tactic})")
        
        print("\n" + "="*70)
        print("🔗 APT Correlation: http://localhost:8000/api/apt/correlate")
        print("🗺️  Navigator Layer: http://localhost:8000/api/navigator/layer")
        print("="*70 + "\n")
    
    async def run(self):
        """Main agent execution loop"""
        
        print("\n" + "="*70)
        print("🧠 INTELLIGENT OPENCLAW AUTONOMOUS AGENT")
        print("="*70)
        print("\n🔬 Analyzing outputs and making strategic decisions")
        print("   like a real attacker based on gathered intelligence\n")
        
        # Authenticate
        self.get_token()
        
        # Main execution loop
        step = 1
        while step <= MAX_STEPS:
            print(f"\n{'─'*70}")
            print(f"📌 STRATEGIC STEP {step}/{MAX_STEPS}")
            print(f"{'─'*70}")
            
            # Decide next technique
            next_tech = await self.decide_next_technique()
            
            if not next_tech:
                print("\n[✓] Campaign objectives complete!")
                break
            
            print(f"\n[🎯] DECISION: {next_tech}")
            
            # Execute and analyze
            success = await self.execute_and_analyze(next_tech)
            
            if success:
                step += 1
            else:
                print(f"\n[!] Execution failed, trying different approach...")
            
            # Brief pause
            if step <= MAX_STEPS:
                print(f"\n[⏳] Processing intelligence...")
                await asyncio.sleep(DELAY_BETWEEN_STEPS)
        
        # Final intelligence summary
        self.print_intelligence_summary()

# ================= MAIN =================

async def main():
    agent = IntelligentOpenClawAgent()
    await agent.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[!] Campaign interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
