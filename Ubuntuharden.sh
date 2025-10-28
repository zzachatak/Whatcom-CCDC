#!/usr/bin/env bash
# ubuntu_harden_with_passwords.sh


set -euo pipefail
IFS=$'\n\t'

timestamp="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/etc/hardening-backups/${timestamp}"
mkdir -p "$BACKUP_DIR"
log(){ echo "[$(date +'%F %T')] $*"; }
backup(){ [[ -e "$1" ]] && { mkdir -p "$(dirname "$BACKUP_DIR/$1")"; cp -a "$1" "$BACKUP_DIR/$1.bak"; log "Backup $1 -> $BACKUP_DIR/$1.bak"; } || true; }

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

log "Updating and installing packages…"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw fail2ban auditd unattended-upgrades \
  libpam-pwquality libpam-modules

# --- Unattended upgrades ---
backup /etc/apt/apt.conf.d/20auto-upgrades
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades || true

# --- UFW: default deny + SSH rate-limit ---
log "Configuring UFW baseline + rate-limit for SSH…"
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp    # throttles repeated SSH attempts
ufw logging low
if ufw status | grep -q inactive; then yes | ufw enable; fi

# --- SSHD: keep password auth, block root, reduce attack surface ---
SSHD=/etc/ssh/sshd_config
backup "$SSHD"
# Keep PasswordAuthentication YES (explicitly set)
if grep -qE '^#?PasswordAuthentication' "$SSHD"; then
  sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD"
else
  echo "PasswordAuthentication yes" >> "$SSHD"
fi
# No root SSH
if grep -qE '^#?PermitRootLogin' "$SSHD"; then
  sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD"
else
  echo "PermitRootLogin no" >> "$SSHD"
fi
# Reduce brute-force window
if grep -qE '^\s*MaxAuthTries' "$SSHD"; then
  sed -ri 's/^\s*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD"
else
  echo "MaxAuthTries 3" >> "$SSHD"
fi
if grep -qE '^\s*LoginGraceTime' "$SSHD"; then
  sed -ri 's/^\s*LoginGraceTime.*/LoginGraceTime 20/' "$SSHD"
else
  echo "LoginGraceTime 20" >> "$SSHD"
fi
# Minor hygiene
grep -qE '^\s*UseDNS' "$SSHD" && sed -ri 's/^\s*UseDNS.*/UseDNS no/' "$SSHD" || echo "UseDNS no" >> "$SSHD"
systemctl restart sshd || systemctl restart ssh

# --- Fail2ban: aggressive sshd jail ---
log "Configuring Fail2ban for sshd…"
mkdir -p /etc/fail2ban/jail.d
backup /etc/fail2ban/jail.d/sshd.local
cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled   = true
port      = ssh
backend   = systemd
bantime   = 2h
findtime  = 15m
maxretry  = 4
ignorecommand =
EOF
systemctl enable --now fail2ban

# --- PAM quality & lockouts (Ubuntu 22.04+ supports pam_faillock) ---
log "Enforcing password quality and lockouts…"
# pwquality (complexity & length)
backup /etc/pam.d/common-password
if ! grep -q 'pam_pwquality.so' /etc/pam.d/common-password; then
  sed -i '/pam_unix.so/s/$/ use_authtok/' /etc/pam.d/common-password || true
  sed -i '1i password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1' /etc/pam.d/common-password
else
  sed -ri 's/^(password\s+requisite\s+pam_pwquality\.so).*/\1 retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/' /etc/pam.d/common-password
fi

# faillock (graceful if module exists)
if grep -q pam_faillock.so /etc/pam.d/common-auth 2>/dev/null || ldconfig -p | grep -q faillock; then
  backup /etc/pam.d/common-auth
  backup /etc/pam.d/common-account
  # prevent duplicate lines
  sed -i '/pam_faillock.so/d' /etc/pam.d/common-auth || true
  sed -i '/pam_faillock.so/d' /etc/pam.d/common-account || true
  # add lockout: 5 failed attempts → 15 min lock
  sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=900' /etc/pam.d/common-auth
  sed -i '/pam_unix.so/s/^/auth \[success=1 default=bad\] pam_unix.so nullok_secure\n/' /etc/pam.d/common-auth
  echo 'auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900' >> /etc/pam.d/common-auth
  echo 'account required pam_faillock.so' >> /etc/pam.d/common-account
fi

# --- Password aging policy ---
log "Setting password aging policy (/etc/login.defs)…"
backup /etc/login.defs
sed -ri 's/^#?\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -ri 's/^#?\s*PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -ri 's/^#?\s*PASS_WARN_AGE\s+.*/PASS_WARN_AGE   14/' /etc/login.defs

# --- Auditd quick watches ---
log "Configuring auditd watches…"
backup /etc/audit/rules.d/50-ssh-passwd.rules
cat >/etc/audit/rules.d/50-ssh-passwd.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshconfig
EOF
augenrules --load 2>/dev/null || service auditd restart || true

# --- Clean up ---
apt-get autoremove -y
apt-get autoclean -y

log "Done. Backups at: $BACKUP_DIR"

echo "
Quick checks:
  ufw status verbose
  fail2ban-client status sshd
  sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|logingracetime'
  grep -E 'PASS_(MAX|MIN|WARN)_DAYS' /etc/login.defs
"
