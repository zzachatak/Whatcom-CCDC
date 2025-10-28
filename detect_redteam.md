# Detecting Red Team (Quick Checks)
- Look for password spraying: many failed auths (same src → many users).
- RDP brute force patterns.
- SMB ADMIN$ writes (PsExec-style lateral).
- DNS tunneling: many unique random subdomains per host.
- Periodic beacons: consistent intervals to same external IP:port.
