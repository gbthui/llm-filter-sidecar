# LLM Filter Sidecar

[简体中文](README.zh-CN.md)

An OpenAI-compatible reverse-proxy sidecar that redacts PII and secrets before requests reach an LLM gateway, with an optional fail-closed semantic safety audit.

```text
client / nginx
      |
      v
llm-filter-sidecar ----> privacy-filter (/redact/batch)
      |
      +---------------> optional OpenAI-compatible auditor
      |
      v
OpenAI-compatible upstream
```

The sidecar is deliberately upstream-agnostic. It does not own accounts, billing, model routing, databases, or response storage.

## Properties

- Schema-aware filtering for exact `POST /v1/chat/completions` and `POST /v1/responses` routes.
- Irreversible PII/secret redaction through [packyme/privacy-filter](https://github.com/packyme/privacy-filter), pinned in the sample Compose build.
- Fail-closed target-route behavior when redaction is unavailable or invalid.
- Optional semantic audit that receives only already-redacted user-role text.
- Stateless open-segment audit: user messages after the last assistant message are evaluated together.
- Exact, case-sensitive model selection with explicit `allow` or `audit` list modes.
- Keyed HMAC-SHA256 input fingerprints for retry correlation without prompt logging.
- Streaming-preserving reverse proxy; upstream SSE responses are not buffered by the sidecar.
- Non-target routes pass through unchanged.
- Standard-library-only Go gateway with unit tests and a non-root, read-only container profile.

## Request Coverage

| Route | Redacted fields |
| --- | --- |
| Chat Completions | Message text, legacy/function tool-call arguments, function descriptions, and nested JSON Schema descriptions |
| Responses | `instructions`, string/array `input`, content/output text, function-call arguments, function descriptions, and nested JSON Schema descriptions |

Binary image, audio, and uploaded-file contents are not inspected. Route aliases that could be normalized to a protected route are rejected instead of being passed through.

## Quick Start

Requirements: Docker Engine with Compose v2 and outbound access for the pinned `privacy-filter` source build.

```bash
cp .env.example .env
# Edit UPSTREAM_URL. It must be reachable from the sidecar container.
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 240
./scripts/verify.sh http://127.0.0.1:8080 401
```

The second verification argument is the exact status your upstream returns for the script's fake API key. Use that known value; the script intentionally does not guess a range of acceptable statuses.

This smoke test deliberately uses `sidecar-smoke-test-invalid-key`. It proves health and traversal through the protected route, but it does not prove that a real upstream credential works.

`compose.yaml` binds to `127.0.0.1` by default and builds `privacy-filter` from commit `64b8de3c206059b187d65381189b70c267550392`. Override `PRIVACY_FILTER_CONTEXT` only as an explicit dependency upgrade.

For an upstream running on the Docker host, use `http://host.docker.internal:<port>`. For an upstream in another Compose project, attach both services to a shared Docker network and use its service name.

## Upstream Key And Real Request Test

There is intentionally no `UPSTREAM_API_KEY` setting. The client sends its real upstream credential to the sidecar in `Authorization: Bearer ...`; the sidecar preserves that header when it forwards the redacted request. For example, an OpenAI-compatible SDK uses the sidecar URL as `base_url` and the upstream credential as its normal `api_key`.

For a command-line test, keep the credential out of shell history and process arguments by putting the complete header in an ignored, owner-readable file:

```bash
mkdir -p secrets
chmod 700 secrets
umask 077
read -rsp "Upstream API key: " upstream_key
printf 'Authorization: Bearer %s\n' "$upstream_key" > secrets/upstream-authorization-header
unset upstream_key
echo

UPSTREAM_MODEL=your-real-upstream-model
curl --silent --show-error --include \
  --header @secrets/upstream-authorization-header \
  --header 'Content-Type: application/json' \
  --data-binary "{\"model\":\"$UPSTREAM_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK. My test email is alice@example.invalid.\"}],\"stream\":false}" \
  http://127.0.0.1:8080/v1/chat/completions
```

A successful upstream response confirms real authentication and traversal through the redaction path. The header file is only a local test fixture under the gitignored `secrets/` directory; delete it when it is no longer needed.

## Optional Semantic Audit

Audit is off in the base Compose file, so ordinary deployments acquire no audit-provider dependency.

```bash
./scripts/prepare-audit-secrets.sh
read -rsp "Audit provider API key: " audit_key
printf '%s' "$audit_key" > secrets/audit_api_key
unset audit_key
echo
# On Linux, set SIDECAR_UID and SIDECAR_GID in .env to `id -u` and `id -g`.
# Set AUDIT_URL and AUDIT_MODEL in .env.
docker compose -f compose.yaml -f compose.audit.yaml config --quiet
docker compose -f compose.yaml -f compose.audit.yaml up -d --build --wait --wait-timeout 240
./scripts/verify.sh http://127.0.0.1:8080 401
```

The script creates `secrets/audit_api_key` with mode `0600` and generates the independent HMAC fingerprint key at `secrets/audit_fingerprint_key`. It never generates or guesses the audit-provider credential; the interactive commands above write that credential without placing it in shell history or command arguments. Compose mounts the two files at `/run/secrets/audit_api_key` and `/run/secrets/audit_fingerprint_key`.

After enabling the overlay, repeat the real request test from the previous section. With the sample empty model list in `allow` mode, the request must be audited and then reach the upstream. A missing, empty, or rejected audit-provider key must instead fail closed with `502 audit_unavailable`. Paired `403 prompt_flagged` and allow-path policy tests are described in [`skills/llm-filter-sidecar-deploy/references/policy-testing.md`](skills/llm-filter-sidecar-deploy/references/policy-testing.md).

The audit endpoint must use HTTPS. `AUDIT_ALLOW_INSECURE_HTTP=true` is an explicit escape hatch for a trusted private Docker network, not a production default.

The model list is stored in [`audit-model-list.txt`](audit-model-list.txt):

- `allow`: listed models skip semantic audit; unlisted models audit. An empty list audits all valid model IDs.
- `audit`: listed models audit; unlisted models skip semantic audit. An empty list audits none.
- A missing or non-string model always audits.

Every target request is still redacted, regardless of model selection.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | Sidecar listen address |
| `UPSTREAM_URL` | `http://upstream:8080` | OpenAI-compatible upstream base URL |
| `UPSTREAM_HEALTH_URL` | empty | Optional absolute upstream health URL |
| `REDACTION_URL` | `http://privacy-filter:8088` | Redaction-service base URL |
| `REDACTION_TIMEOUT` | `2s` | Per-request redaction timeout |
| `AUDIT_ENABLED` | `false` | Enable semantic audit |
| `AUDIT_URL` | required when enabled | OpenAI-compatible chat-completions endpoint |
| `AUDIT_MODEL` | required when enabled | Auditor model ID |
| `AUDIT_MODEL_LIST_MODE` | `allow` | `allow` or `audit` |
| `AUDIT_TIMEOUT` | `10s` | Audit timeout |
| `AUDIT_MAX_INPUT_BYTES` | `262144` | Encoded audit input limit |
| `AUDIT_API_KEY_FILE` | `/run/secrets/audit_api_key` | File containing the audit-provider API key |
| `AUDIT_FINGERPRINT_KEY_FILE` | `/run/secrets/audit_fingerprint_key` | File containing at least 32 bytes of independent HMAC key material |

Upstream credentials are request headers, not sidecar configuration. Audit keys are file-only. See the complete matrix and security constraints in [`skills/llm-filter-sidecar-deploy/references/configuration.md`](skills/llm-filter-sidecar-deploy/references/configuration.md).

Docker Compose implements local file-backed secrets as bind mounts. The sample therefore runs the sidecar as `SIDECAR_UID:SIDECAR_GID` (default `1000:1000`) so `0600` secret files remain readable without making them world-readable. Set both values to the deployment user's `id -u` and `id -g` on Linux. The image itself still defaults to the dedicated UID/GID 65532 when run outside Compose.

## Errors And Health

Filter-layer failures use OpenAI-compatible error envelopes:

- `502 redaction_unavailable`
- `502 audit_unavailable`
- `403 prompt_flagged`
- `413 audit_input_too_large`
- `404 unsupported_target_route`

`GET /health` checks redaction readiness and, when configured, the upstream health URL. It reports component booleans, audit mode/count, fingerprint availability, and version without returning prompts or secrets.

## Security Model

- Target routes fail closed; non-target routes are explicitly outside filter scope.
- Request bodies, prompts, authorization headers, keys, and provider responses are never intentionally logged.
- Audit logs contain metadata and a keyed fingerprint. A short audit reason may be logged and returned.
- Redaction happens before audit, so the semantic provider never receives the original selected user text.
- This project cannot recover messages omitted or rewritten by a client; open-segment auditing is stateless by design.
- The included policy is a deployable baseline, not a guarantee that a probabilistic auditor will classify every input correctly. Validate it against your policy and model before enabling it.

Read [SECURITY.md](SECURITY.md) before exposing the gateway beyond loopback.

## Development

```bash
gofmt -w main.go main_test.go
go test ./...
go vet ./...
go build ./...
```

The module and sample container target Go 1.26 or newer.

## Deployment Skill

The public Codex skill lives at [`skills/llm-filter-sidecar-deploy`](skills/llm-filter-sidecar-deploy). It covers new deployments, brownfield port-preserving cutovers, rollback, prompt-policy candidates, privacy-safe diagnosis, and Docker disk hygiene.

## License

Apache License 2.0. `packyme/privacy-filter` is an independent MIT-licensed project built as a separate service by the sample Compose configuration.
