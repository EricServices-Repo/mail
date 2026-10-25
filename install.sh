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

  sudo bash install.sh                         Deploy /etc/eric-mail/site.json
  sudo bash install.sh --config /root/site.json Deploy an explicit site configuration
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
Docker is not required for installation or runtime. Prepare private configuration,
trusted repositories, application archives, certificates and backups first.
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
exec python3 "$INSTALL_ROOT/lib/$module" "$@"
