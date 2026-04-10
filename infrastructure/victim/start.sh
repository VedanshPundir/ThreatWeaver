#!/bin/bash

# Start core services
service ssh start
service apache2 start

# Start additional vulnerable services
echo "[*] Starting vulnerable services..."

# Start Redis (with weak config)
service redis-server start 2>/dev/null || redis-server --bind 0.0.0.0 --requirepass weakpassword &

# Start FTP service
service vsftpd start 2>/dev/null || vsftpd &

# Start TFTP (via xinetd)
service xinetd start 2>/dev/null || /usr/sbin/xinetd &

# Start cron daemon for persistence
service cron start

# Create some running processes for discovery
echo "[*] Creating additional processes for discovery..."

# Start a simple HTTP server on port 8000
python3 -m http.server 8000 --directory /var/www/html 2>/dev/null &

# Start a netcat listener (potential backdoor)
nc -lvp 4444 -e /bin/bash 2>/dev/null &

# Create some fake processes
/bin/bash -c "while true; do sleep 60; done" &
/usr/bin/python3 -c "import time; time.sleep(3600)" &

# Add some cron jobs dynamically
echo "*/10 * * * * root /bin/echo 'Cron heartbeat' >> /var/log/cron-heartbeat.log" >> /etc/crontab
echo "@reboot root /usr/bin/python3 /opt/vulnerable/backup_script.py" >> /etc/crontab

# Create a fake systemd service that's running
if [ -f /etc/systemd/system/vuln.service ]; then
systemctl daemon-reload 2>/dev/null
systemctl start vuln.service 2>/dev/null
fi

echo "[*] Services started: SSH, Apache, Redis, FTP, TFTP, Cron"
echo "[*] Additional processes: HTTP:8000, Netcat:4444, background jobs"

# Start C2 Agent (unbuffered output for logs)
echo "[*] Starting C2 victim agent..."

while true; do
python3 -u /victim_agent.py
echo "[!] Agent crashed or exited. Restarting in 3 seconds..."
sleep 3
done
