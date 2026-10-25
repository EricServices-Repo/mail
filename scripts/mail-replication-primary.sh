#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' 'Replication is unsupported and disabled. Use verified offsite backups; see docs/OPERATIONS.md.' >&2
exit 1
