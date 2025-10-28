# 🛡️ System Hardening Guide

> Purpose: Provide repeatable, platform-agnostic steps for securing hosts during CCDC — Linux, Windows, or unknown systems.

## 1) Principles
- Minimize attack surface • Least privilege • Patch frequently • Audit/monitor • Encrypt • Defense-in-depth

## 2) Linux Checklist
- **Auth**: strong passwords (PAM), disable root SSH, idle timeouts.
- **Updates**: `apt update && apt -y upgrade`; enable unattended-upgrades.
- **Audit**: install & enable `auditd`; watch `/etc/passwd`, `/etc/sudoers`.
- **Firewall**: `ufw default deny incoming`, allow needed ports; consider disabling IPv6 if unused.
- **Logging**: forward syslog to central collector; monitor `auth.log`, `audit.log`.

## 3) Windows Checklist
- **Accounts**: disable Guest; restrict RDP; password policy via Local/Domain policy.
- **Firewall**: `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True`.
- **Audit**: `auditpol` enable success/failure; watch 4625/4720/7045.
- **Services**: disable unneeded (Telnet, Spooler if unused); enable updates.
- **Registry**: LmCompatibilityLevel=5; RDP NLA required.

## 4) Automation
- Ansible (Linux): `ansible-playbook -i inventory.yml site.yml`
- PowerShell (Windows): `powershell -ExecutionPolicy Bypass -File .\win_hardening.ps1`
- Bash (quick): `./ubuntu_baseline.sh`

## 5) Verification
- Open ports: `ss -tuln` / `netstat -ano`
- Services: `systemctl --type=service` / `Get-Service`
- Firewall: `ufw status` / `Get-NetFirewallProfile`

## 6) Competition Quick Moves
- SSH brute force → Fail2ban + review `auth.log`
- RDP brute force → NLA + lockout policy
- SMB lateral → block ADMIN$, disable SMBv1, monitor 445
- Persistence → audit crontab / `schtasks`
- Rogue users → review `/etc/passwd` / `net user`

See `hardening/scripts/` for automation, including **bulk password rotation** for Linux.
