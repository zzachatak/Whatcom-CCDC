# Hardening Resources & Commands (CCDC)

> Purpose: a compact, copy-pasteable hardening **template** you can add to your repo (`hardening/RESOURCES.md`).
> It collects curated learning resources, authoritative hardening benchmarks, practical one-line commands and checklists you can use in a CCDC / lab environment to harden and validate Linux and Windows hosts.

---

## Table of contents
1. Quick bookmarks (authoritative references)  
2. Learning resources (books, courses, labs)  
3. Tools to know and run in a lab  
4. Linux — command cheat sheet (hardening & verification)  
5. Windows — command cheat sheet (hardening & verification)  
6. Practical hardening checklist (copyable)  
7. Detection & monitoring quick wins  
8. Hands-on practice & labs  
9. Notes on safety & operational guidance

---

## 1 — Quick bookmarks (authoritative references)
- CIS Benchmarks — https://www.cisecurity.org/cis-benchmarks/
- NIST SP 800-123 — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf
- Microsoft Security Baselines — https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
- Ubuntu Server Hardening — https://ubuntu.com/server/docs/security-hardening
- OWASP — https://owasp.org/
- Mitre ATT&CK — https://attack.mitre.org/

---

## 2 — Learning resources
- **Books:** *Linux Hardening Cookbook*, *Practical UNIX and Internet Security*.
- **Courses:** TryHackMe Blue Team, HTB Defensive, Microsoft Learn Security modules.
- **Benchmarks:** CIS Level 1 (baseline) & Level 2 (strict) PDFs per OS.

---

## 3 — Tools to know
| Purpose | Tools |
|----------|-------|
| Firewall | ufw, iptables, nftables |
| IDS | Suricata, Snort, Zeek |
| Audit | auditd, ausearch, osquery |
| File integrity | AIDE, Tripwire |
| Logging | syslog, rsyslog, journalctl |
| Auth | pam_pwquality, pam_faillock |
| Detection | fail2ban, Sysmon |
| Baseline | Lynis, OpenSCAP |

---

## 4 — Linux command cheat sheet

**Update and patch**
```bash
sudo apt update && sudo apt -y upgrade
sudo apt install -y unattended-upgrades auditd ufw fail2ban aide
```

**Sysctl hardening**
```bash
sudo bash -c 'cat >> /etc/sysctl.conf <<EOF
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
EOF'
sudo sysctl -p
```

**SSH**
```bash
sudo sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -ri 's/^#?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

**Firewall**
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit ssh
sudo ufw enable
```

**Fail2ban**
```bash
sudo tee /etc/fail2ban/jail.d/ssh.local <<'EOF'
[sshd]
enabled = true
bantime = 3600
findtime = 600
maxretry = 4
EOF
sudo systemctl restart fail2ban
```

**Auditd**
```bash
sudo tee /etc/audit/rules.d/50-hardening.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
EOF
sudo augenrules --load
```

---

## 5 — Windows command cheat sheet
```powershell
# Firewall
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# Disable Guest
Disable-LocalUser -Name Guest

# Audit Policy
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable

# View failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20

# RDP hardening
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
```

---

## 6 — Hardening checklist
- [ ] Update system packages and enable auto-updates  
- [ ] Disable root SSH login  
- [ ] Limit SSH attempts (MaxAuthTries=3)  
- [ ] Enable UFW default deny + allow required ports  
- [ ] Install & configure fail2ban  
- [ ] Configure auditd rules for passwd, sudoers, sshd_config  
- [ ] Verify password complexity via PAM  
- [ ] Enable periodic AIDE integrity checks  
- [ ] Forward logs to central server or SIEM  
- [ ] Test with Lynis (`sudo lynis audit system`)

---

## 7 — Detection & monitoring quick wins
| Threat | Quick Detection |
|--------|----------------|
| SSH brute force | fail2ban + review /var/log/auth.log |
| Unauthorized user add | auditd rule on /etc/passwd |
| Privilege escalation | auditd rule on /etc/sudoers |
| Persistence via cron | `crontab -l`, audit /etc/cron* |
| Data exfil | unusual outbound connections via `ss -tulnp` |
| RDP brute force | Event ID 4625 bursts from same IP |

---

## 8 — Hands-on practice
- TryHackMe: *Linux Hardening*, *Blue Team Fundamentals*  
- HTB: Defensive Labs (APT Detection, SIEM)  
- Build a mini lab: 1x Linux, 1x Windows, 1x IDS node (Suricata).  
- Run `lynis audit system` and compare against CIS checklist.

---

## 9 — Notes & safety
- Always test in a lab before applying to production.  
- Back up `/etc/ssh/sshd_config`, `/etc/sudoers`, `/etc/login.defs` before editing.  
- Never disable SSH password auth unless console access is guaranteed.  
- Restrict who can SSH via `AllowGroups`.  
- Treat CSVs with passwords as secrets (`chmod 0400`).  
- During competitions: prioritize *visibility* (logging, monitoring) before extreme lockdowns.
