#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
/opt/eric-mail/current/install.sh validate --config /etc/eric-mail/site.json
systemctl reload nginx postfix dovecot
