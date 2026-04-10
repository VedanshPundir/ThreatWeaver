#!/usr/bin/env python3
import os
import datetime

# Simple backup script that creates credentials
backup_file = "/tmp/system_backup_$(date +%s).txt"
with open(backup_file, "w") as f:
f.write(f"Backup created at {datetime.datetime.now()}\\n")
f.write("Sensitive data:\\n")
try:
with open("/etc/passwd", "r") as p:
f.write(p.read())
except:
pass
f.write("\\nCredentials:\\n")
f.write("DB_PASSWORD=SuperSecret123!\\n")
f.write("API_KEY=sk-1234567890abcdef\\n")

print(f"[*] Backup created: {backup_file}")
