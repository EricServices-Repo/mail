#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
while IFS= read -r file; do
  bash -n "$file"
done < <(find . -path './.git' -prune -o -path './.venv' -prune -o -name '*.sh' -print)
if command -v shellcheck >/dev/null 2>&1; then
  find . -path './.git' -prune -o -path './.venv' -prune -o -name '*.sh' -print0 | xargs -0 shellcheck
else
  echo 'ShellCheck is required. Install it before running the release checks.' >&2
  exit 1
fi
python3 -m unittest discover -s tests -v
