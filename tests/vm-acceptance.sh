#!/usr/bin/env bash
# Destructive: dedicated disposable self-hosted lab runner only.
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ "$EUID" -ne 0 || ! -f /etc/eric-mail-disposable-lab ]]; then
  echo 'Requires root on a disposable VM with /etc/eric-mail-disposable-lab present.' >&2
  exit 1
fi
if [[ "${ERIC_MAIL_DISPOSABLE_LAB:-}" != 'I_ACCEPT_DESTRUCTIVE_LAB_PROVISIONING' ]]; then
  echo 'Explicit disposable-lab environment acknowledgement required.' >&2
  exit 1
fi
./install.sh deploy --config /root/eric-mail-lab-site.json
cp /var/lib/eric-mail/configuration-manifest.json /root/eric-mail-first-manifest.json
cp /etc/eric-mail/secrets.json /root/eric-mail-first-secrets.json
./install.sh deploy --config /root/eric-mail-lab-site.json
cmp /root/eric-mail-first-manifest.json /var/lib/eric-mail/configuration-manifest.json
cmp /root/eric-mail-first-secrets.json /etc/eric-mail/secrets.json
./install.sh validate
./install.sh health
./install.sh debug-on
./install.sh debug-off
if [[ "$(getenforce)" != Enforcing ]]; then exit 1; fi
firewall-cmd --zone=eric-mail --list-all
printf '%s\n' 'Local VM gates passed. External probes, failure injection, reboot, upgrade and restore evidence are still required.'
