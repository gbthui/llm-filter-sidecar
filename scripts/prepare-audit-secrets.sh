#!/bin/sh
set -eu

secrets_dir=${1:-./secrets}
mkdir -p "$secrets_dir"
chmod 700 "$secrets_dir"

api_key_file="$secrets_dir/audit_api_key"
fingerprint_key_file="$secrets_dir/audit_fingerprint_key"

umask 077
if [ ! -e "$api_key_file" ]; then
  touch "$api_key_file"
fi
if [ ! -s "$fingerprint_key_file" ]; then
  if [ -e "$fingerprint_key_file" ]; then
    echo "Refusing to overwrite empty fingerprint key: $fingerprint_key_file" >&2
    exit 1
  fi
  openssl rand -hex 32 >"$fingerprint_key_file"
fi

chmod 600 "$api_key_file" "$fingerprint_key_file"
echo "Prepared $secrets_dir without overwriting existing secrets."
echo "Write the audit provider key to $api_key_file, then enable compose.audit.yaml."
echo "On Linux, set SIDECAR_UID=$(id -u) and SIDECAR_GID=$(id -g) so the non-root container can read these 0600 files."
