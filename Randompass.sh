#!/usr/bin/env bash
# rotate_nonadmin_pwds.sh
# Rotate passwords for all non-admin human users (UID >= 1000),
# generate an 8-character random password for each, print and save to CSV.
# Also produce a plain list of the non-admin usernames for later "fake user" use.

set -euo pipefail

# ---------- Configuration ----------
# Output files
timestamp="$(date +%Y%m%d-%H%M%S)"
OUT_CSV="/root/rotated-passwords-${timestamp}.csv"
OUT_USERLIST="/root/non_admin_users-${timestamp}.txt"

# Admin groups to exclude (if they exist on the system)
ADMIN_GROUPS=(root sudo wheel admin adm)

# Password length (8 characters as requested)
PW_LENGTH=8

# ---------- Helpers ----------
die() { echo "ERROR: $*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
  die "This script must be run as root."
fi

# Generate an 8-character random alphanumeric password
generate_pw() {
  # Uses /dev/urandom, selects alphanumeric characters only
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${PW_LENGTH}"
}

# Check if a user is member of any admin group
is_admin_user() {
  local user="$1"
  # get groups for user
  local groups
  groups="$(id -nG "$user" 2>/dev/null || echo "")"
  for ag in "${ADMIN_GROUPS[@]}"; do
    # if the group exists on system and the user is in it, consider admin
    if getent group "$ag" >/dev/null 2>&1; then
      if echo " $groups " | grep -q " $ag "; then
        return 0
      fi
    fi
  done
  return 1
}

# ---------- Discover candidate users ----------
# Standard Linux: use /etc/passwd entries with UID >= 1000, exclude nologin/false shells,
# exclude root explicitly.
mapfile -t CANDIDATES < <(awk -F: '($3>=1000)&&($1!="nobody"){print $1 ":" $3 ":" $7}' /etc/passwd)

# Prepare output files
: > "$OUT_CSV"
chmod 0600 "$OUT_CSV"
echo "username,new_password" >> "$OUT_CSV"

: > "$OUT_USERLIST"
chmod 0600 "$OUT_USERLIST"

processed=0
skipped=0

echo "Starting rotation: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Output CSV: $OUT_CSV"
echo "User list:   $OUT_USERLIST"
echo

for entry in "${CANDIDATES[@]}"; do
  # entry format: username:uid:shell
  IFS=":" read -r username uid shell <<< "$entry"

  # Skip accounts with nologin or false shells
  case "$shell" in
    */nologin|*/false|/sbin/nologin|/usr/sbin/nologin)
      # skip system/no-login accounts
      ((skipped++))
      continue
      ;;
  esac

  # Skip explicit root just in case (though root uid is <1000 typically)
  if [[ "$username" == "root" ]]; then
    ((skipped++))
    continue
  fi

  # If user is in admin group(s) — skip
  if is_admin_user "$username"; then
    echo "Skipping admin user: $username"
    ((skipped++))
    continue
  fi

  # Generate password and set it
  pw="$(generate_pw)"
  # Use chpasswd to set: username:password
  if echo "${username}:${pw}" | chpasswd; then
    echo "Rotated: $username"
    # Record to CSV and user list
    echo "${username},${pw}" >> "$OUT_CSV"
    echo "$username" >> "$OUT_USERLIST"
    ((processed++))
  else
    echo "Failed to change password for: $username" >&2
  fi
done

# Lock down the CSV file (read-only for root)
chmod 0400 "$OUT_CSV"
chmod 0400 "$OUT_USERLIST"

echo
echo "Done. Processed: $processed users. Skipped: $skipped users."
echo "Passwords saved to: $OUT_CSV (mode 0400) — treat as a secret."
echo "Non-admin username list saved to: $OUT_USERLIST"
echo

# Extra note: if you prefer not to keep plaintext passwords on disk,
# you can print to console and remove the CSV after secure delivery:
#   shred -u "$OUT_CSV"
#
# Also consider rotating these passwords again after the event.
