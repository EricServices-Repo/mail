#!/usr/bin/env bash
# Native host installer. Python helpers implement validation and security operations.
if [ -z "${BASH_VERSION:-}" ]; then
  printf '%s\n' 'This installer requires Bash. Run: bash install.sh' >&2
  exit 2
fi
set -Eeuo pipefail
umask 077
INSTALL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'HELP'
EricServices-Mail-Server — native Rocky Linux 9 installer

  sudo bash install.sh                         Prompt for settings, then install
  sudo bash install.sh --config /root/site.json Deploy an explicit site configuration
  bash install.sh configure --output FILE      Prompt and save JSON without installing
  bash install.sh COMMAND [OPTIONS]            Run an installer/operations command

Core commands:
  init-secrets, render, deploy, validate, health, fingerprint, activate, close,
  domain, domain-enable, domain-disable, mailbox, admin, upgrade, backup,
  restore, resume-backup, renew-certificate, debug-on, debug-off, alert

Feature commands (append --help for their options):
  mailbox-mfa      Built-in TOTP and mail-client device credentials
  content-security  Malware scanning and Postfix quarantine
  web-egress       Web-worker network restrictions
  domain-security  DNS readiness, DKIM rotation and DANE
  security-ops     Inventory, advisories, signatures, drift and SQL rotation
  remote-audit     Independent TLS log forwarding
  canary           Independent SMTP/IMAP delivery check
  replication      Optional private MariaDB disaster-recovery replica

Installs distribution packages and systemd services directly on the host.
Docker is not required for installation or runtime. Supply --config FILE to skip
prompts. Interactive setup creates private JSON; it does not issue certificates,
fetch application archives, configure repository trust or initialize backups.
Requires Bash and Python 3.9+; see README.md and docs/DEPLOYMENT.md.
HELP
}

case "${1:-}" in
  -h|--help|help) usage; exit 0 ;;
esac

# A bare invocation is the installation command; options may select its config.
if [[ $# -eq 0 || "$1" == --config || "$1" == --config=* ]]; then
  set -- deploy "$@"
fi

module=mailctl.py
case "$1" in
  mailbox-mfa) module=mail_auth.py; shift ;;
  content-security) module=content_security.py; shift ;;
  web-egress) module=web_egress.py; shift ;;
  domain-security) module=domain_security.py; shift ;;
  security-ops) module=security_ops.py; shift ;;
  remote-audit) module=remote_audit.py; shift ;;
  canary) module=mail_canary.py; shift ;;
  replication) module=replication.py; shift ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3.9+ is required. Install python3 from a trusted signed distribution repository.' >&2
  exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  printf '%s\n' 'Python 3.9+ is required by the installer security helpers.' >&2
  exit 1
fi
if [[ ! -f "$INSTALL_ROOT/lib/$module" ]]; then
  printf '%s\n' 'Installer files are missing. Use the complete reviewed checkout/release, not install.sh alone.' >&2
  exit 1
fi
export PYTHONDONTWRITEBYTECODE=1

setup_config() {
  local requested_output="${1:-}" key label default value
  if [[ ! -t 0 || ! -t 1 ]]; then
    printf '%s\n' 'Interactive setup requires a terminal. Supply --config /path/to/site.json for unattended installation.' >&2
    return 1
  fi
  if [[ ! -f "$INSTALL_ROOT/lib/setup_config.py" || ! -f "$INSTALL_ROOT/config/site.example.json" ]]; then
    printf '%s\n' 'Interactive setup files are missing; use the complete reviewed release.' >&2
    return 1
  fi
  SETUP_WORK="$(mktemp -d "${TMPDIR:-/tmp}/eric-mail-setup.XXXXXXXX")"
  trap 'rm -rf -- "$SETUP_WORK"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf '%s\n' 'Mail server setup: enter deployment settings. No passwords are requested.' \
    'Prepare trusted repositories, certificates/CA/CRL, verified application archives,' \
    'an initialized backup repository and an alert executable before deployment.' \
    'Press Ctrl-C to cancel. Existing configuration files are never overwritten.'

  prompt() {
    key="$1"; label="$2"; default="${3:-}"
    while true; do
      if [[ -n "$default" ]]; then
        if ! IFS= read -r -p "$label [$default]: " value; then
          printf '\nSetup cancelled; installation was not started.\n' >&2; return 1
        fi
        value="${value:-$default}"
      else
        if ! IFS= read -r -p "$label: " value; then
          printf '\nSetup cancelled; installation was not started.\n' >&2; return 1
        fi
      fi
      printf '%s' "$value" > "$SETUP_WORK/$key"
      if python3 "$INSTALL_ROOT/lib/setup_config.py" validate --directory "$SETUP_WORK"; then
        return 0
      fi
    done
  }
  schema_default() { python3 "$INSTALL_ROOT/lib/setup_config.py" default --field "$1"; }

  prompt hostname 'Mail hostname (for example mail.your-domain.tld)'
  prompt domains 'Hosted domains (space-separated)'
  prompt admin_hostname 'Admin hostname (must differ from mail hostname)'
  prompt management_networks 'Management CIDRs (space-separated; IPv4 /24 or narrower, IPv6 /64 or narrower)'
  prompt interface 'Dedicated network interface (for example ens192)'
  prompt certificate 'Full-chain server certificate path' "/etc/letsencrypt/live/$(cat "$SETUP_WORK/hostname")/fullchain.pem"
  prompt private_key 'Server private-key path' "/etc/letsencrypt/live/$(cat "$SETUP_WORK/hostname")/privkey.pem"
  prompt admin_client_ca 'Admin client CA path' "$(schema_default admin_client_ca)"
  prompt admin_client_crl 'Admin client CRL path' "$(schema_default admin_client_crl)"
  prompt roundcube_version 'Roundcube archive version' "$(schema_default roundcube_version)"
  prompt roundcube_archive 'Complete Roundcube tar.gz archive path' "/root/artifacts/roundcubemail-$(cat "$SETUP_WORK/roundcube_version")-complete.tar.gz"
  prompt roundcube_sha256 'Independently verified Roundcube SHA-256'
  prompt postfixadmin_version 'PostfixAdmin archive version' "$(schema_default postfixadmin_version)"
  prompt postfixadmin_archive 'Complete PostfixAdmin tar.gz archive path' "$(schema_default postfixadmin_archive)"
  prompt postfixadmin_sha256 'Independently verified PostfixAdmin SHA-256'
  prompt backup_environment 'Private backup environment file path' "$(schema_default backup_environment)"
  prompt alert_command 'Alert executable and optional quoted arguments (not shell code)' "$(schema_default alert_command)"
  prompt dkim_selector 'Default DKIM selector' "$(schema_default dkim_selector)"
  prompt mailbox_quota_mb 'Mailbox quota (MiB)' "$(schema_default mailbox_quota_mb)"
  prompt outbound_per_minute 'Outbound recipients per minute' "$(schema_default outbound_per_minute)"
  prompt outbound_burst 'Outbound burst limit' "$(schema_default outbound_burst)"
  prompt queue_max_age_seconds 'Queue age alert threshold (seconds)' "$(schema_default queue_max_age_seconds)"
  prompt queue_max_messages 'Queue count alert threshold' "$(schema_default queue_max_messages)"
  prompt operator 'Responsible operator name'

  if [[ -n "$requested_output" ]]; then
    SETUP_CONFIG="$requested_output"
    python3 "$INSTALL_ROOT/lib/setup_config.py" save --directory "$SETUP_WORK" --output "$SETUP_CONFIG"
  else
    while true; do
      if ! IFS= read -r -p 'Save configuration to [/root/site.json]: ' value; then
        printf '\nSetup cancelled; installation was not started.\n' >&2; return 1
      fi
      SETUP_CONFIG="${value:-/root/site.json}"
      if python3 "$INSTALL_ROOT/lib/setup_config.py" save --directory "$SETUP_WORK" --output "$SETUP_CONFIG"; then break; fi
    done
  fi
  rm -rf -- "$SETUP_WORK"
  trap - EXIT INT TERM
  printf 'Validated configuration saved privately to %s\n' "$SETUP_CONFIG"
}

if [[ "$module" == mailctl.py && "$1" == configure ]]; then
  shift
  case "${1:-}" in
    -h|--help) printf '%s\n' 'bash install.sh configure [--output /absolute/site.json]'; exit 0 ;;
  esac
  output=''
  if [[ $# -eq 2 && "$1" == --output ]]; then output="$2"
  elif [[ $# -ne 0 ]]; then printf '%s\n' 'Usage: bash install.sh configure [--output /absolute/site.json]' >&2; exit 2
  fi
  setup_config "$output"
  exit 0
fi

if [[ "$module" == mailctl.py && "$1" == deploy ]]; then
  supplied_config=false
  show_help=false
  for arg in "$@"; do
    case "$arg" in
      --config|--config=*) supplied_config=true ;;
      --help|-h) show_help=true ;;
    esac
  done
  if [[ "$supplied_config" == false && "$show_help" == false ]]; then
    if [[ "$EUID" -ne 0 ]]; then
      printf '%s\n' 'Installation requires root. Run: sudo bash install.sh' >&2; exit 1
    fi
    setup_config
    set -- "$@" --config "$SETUP_CONFIG"
  fi
fi
exec python3 "$INSTALL_ROOT/lib/$module" "$@"
