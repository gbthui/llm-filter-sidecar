#!/bin/sh
set -eu

base_url=${1:-http://127.0.0.1:8080}
expected_upstream_status=${2:-401}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

health_status=$(curl -sS -o "$work_dir/health.json" -w '%{http_code}' "$base_url/health")
if [ "$health_status" != "200" ] || ! grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' "$work_dir/health.json"; then
  echo "Health verification failed with HTTP $health_status" >&2
  exit 1
fi

printf '%s\n' '{"model":"sidecar-smoke-test","messages":[{"role":"user","content":"Reply with OK."}],"stream":false}' >"$work_dir/request.json"

smoke_status=$(curl -sS -o "$work_dir/response.json" -w '%{http_code}' \
  -H 'Authorization: Bearer sidecar-smoke-test-invalid-key' \
  -H 'Content-Type: application/json' \
  --data-binary @"$work_dir/request.json" \
  "$base_url/v1/chat/completions")

if [ "$smoke_status" != "$expected_upstream_status" ]; then
  echo "Gateway traversal returned HTTP $smoke_status; expected $expected_upstream_status" >&2
  exit 1
fi
if grep -Eq 'redaction_unavailable|audit_unavailable|prompt_flagged|audit_input_too_large' "$work_dir/response.json"; then
  echo "Gateway traversal returned a filter-layer error (HTTP $smoke_status)" >&2
  exit 1
fi

echo "Health and OpenAI-route traversal verified (upstream HTTP $smoke_status)."
