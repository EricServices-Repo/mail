#!/usr/bin/env bash
# Build from a signed, committed revision; signing key remains outside the bundle.
set -Eeuo pipefail
umask 077
if [[ $# -ne 3 ]]; then
  echo 'Usage: package-release.sh SIGNED_GIT_REF OUTPUT_DIRECTORY SIGNING_KEY' >&2
  exit 1
fi
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ref="$1"
output="$2"
signing_key="$3"
cd -- "$ROOT"
commit="$(git rev-parse --verify "${ref}^{commit}")"
git verify-commit "$commit"
if [[ -e "$output" ]]; then
  echo 'Output directory must be new.' >&2
  exit 1
fi
mkdir -m 700 -- "$output"
git archive --format=tar.gz --prefix=eric-mail/ --output="$output/eric-mail.tar.gz" "$commit"
python3 - "$output" "$commit" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1])
archive=p/'eric-mail.tar.gz'
(p/'manifest.json').write_text(json.dumps({'commit':sys.argv[2], 'archive':archive.name,
    'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()},sort_keys=True)+'\n')
PY
openssl dgst -sha256 -sign "$signing_key" -out "$output/manifest.sig" "$output/manifest.json"
echo 'Release archive and signed manifest created. Distribute the trusted verification key separately.'
