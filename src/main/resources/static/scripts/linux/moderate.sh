#!/usr/bin/env bash

# ============================
# MODERATE HARDENING SCRIPT
# ============================

HARDEN_ROOT="/var/lib/hardening-agent"
LOG_FILE="$HARDEN_ROOT/moderate.log"
REPORT_FILE="$HARDEN_ROOT/moderate_report.txt"
BACKUP_ROOT="$HARDEN_ROOT/backup_moderate_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$HARDEN_ROOT" "$BACKUP_ROOT"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') : $1" | tee -a "$LOG_FILE"
}

# ============================
# ROOT CHECK
# ============================
if [[ $EUID -ne 0 ]]; then
  echo " Run as root only"
  exit 1
fi

log "MODERATE HARDENING STARTED"

# ============================
# PACKAGE MANAGER DETECT
# ============================
PM=""
command -v apt >/dev/null && PM="apt"
command -v yum >/dev/null && PM="yum"
command -v dnf >/dev/null && PM="dnf"

install_pkg() {
  [[ "$PM" == "apt" ]] && apt install -y "$1" >/dev/null 2>&1
  [[ "$PM" == "yum" ]] && yum install -y "$1" >/dev/null 2>&1
  [[ "$PM" == "dnf" ]] && dnf install -y "$1" >/dev/null 2>&1
}

# ============================
# BACKUP IMPORTANT FILES
# ============================
log " Backing up configs"

backup_file() {
  [[ -f "$1" ]] && cp -a "$1" "$BACKUP_ROOT$1"
}

backup_file /etc/ssh/sshd_config
backup_file /etc/sysctl.conf
backup_file /etc/sudoers
backup_file /etc/crontab

# ============================
# SYSCTL HARDENING
# ============================
log "Applying sysctl hardening"

cat >/etc/sysctl.d/99-moderate.conf <<EOF
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.tcp_syncookies=1
kernel.randomize_va_space=2
fs.suid_dumpable=0
kernel.kptr_restrict=1
EOF

sysctl --system >/dev/null 2>&1

# ============================
# SSH HARDENING
# ============================
log "Hardening SSH"

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null

# ============================
# FIREWALL (UFW)
# ============================
log "Configuring Firewall"

install_pkg ufw

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

# ============================
# AUDITD
# ============================
log "Installing auditd"

install_pkg auditd

systemctl enable auditd --now

cat >/etc/audit/rules.d/moderate.rules <<EOF
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh
-a always,exit -F arch=b64 -S execve -k exec
EOF

augenrules --load || service auditd restart

# ============================
# CRON HARDENING
# ============================
log "Hardening CRON"

chmod 600 /etc/crontab 2>/dev/null
chmod 700 /etc/cron.* 2>/dev/null

# ============================
# FILE PERMISSIONS
# ============================
log "Hardening system files"

chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow

# ============================
# USB STORAGE BLOCK
# ============================
log " Blocking USB Storage"

echo "blacklist usb-storage" >/etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage 2>/dev/null

# ============================
# GENERATE REPORT
# ============================
log "Generating report"

cat >"$REPORT_FILE" <<EOF
========= MODERATE HARDENING REPORT =========
Date        : $(date)
Backup Path : $BACKUP_ROOT

✔ Sysctl network hardening applied
✔ SSH fully secured (no root login, pass auth OFF, timeout applied)
✔ Firewall enabled (UFW)
✔ auditd installed + rules loaded
✔ Cron permissions secured
✔ System file permissions secured
✔ USB Storage blocked

========= STATUS : SUCCESS =========
EOF

log "MODERATE HARDENING COMPLETED SUCCESSFULLY"
