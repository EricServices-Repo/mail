#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
exec /opt/eric-mail/current/install.sh renew-certificate --config /etc/eric-mail/site.json
