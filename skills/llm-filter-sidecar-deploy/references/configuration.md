# Configuration Reference

## Base Gateway

| Variable | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | HTTP listen address inside the container. |
| `UPSTREAM_URL` | `http://upstream:8080` | Credential-free HTTP(S) base URL of the OpenAI-compatible upstream. |
| `UPSTREAM_HEALTH_URL` | empty | Optional absolute health URL. When empty, readiness does not guess an upstream health route. |
| `REDACTION_URL` | `http://privacy-filter:8088` | Base URL of a service implementing `POST /redact/batch` and `GET /health`. |
| `REDACTION_TIMEOUT` | `2s` | Per-request redaction timeout. |

`UPSTREAM_URL` and `REDACTION_URL` reject userinfo, query parameters, fragments, and non-HTTP(S) schemes. Put authentication in normal request headers; the gateway forwards them to the upstream.

The public Compose file binds `127.0.0.1:8080` by default. Set `BIND_ADDRESS` and `GATEWAY_PORT` only after checking the reverse proxy and firewall.

Set `SIDECAR_UID` and `SIDECAR_GID` to the Linux deployment user's `id -u` and `id -g`. Local Compose file secrets are bind mounts, so the non-root container must match the owner of `0600` secret files. Do not make secret files world-readable as a workaround.

## Semantic Audit

Audit stays disabled unless the `compose.audit.yaml` overlay is used or equivalent settings are supplied.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUDIT_ENABLED` | `false` | Enable synchronous semantic audit. |
| `AUDIT_URL` | required when enabled | Absolute OpenAI-compatible chat-completions URL. HTTPS is required by default. |
| `AUDIT_MODEL` | required when enabled | Auditor model ID. |
| `AUDIT_ALLOW_INSECURE_HTTP` | `false` | Permit HTTP only on a deliberately trusted private network. |
| `AUDIT_TIMEOUT` | `10s` | Total audit request timeout. |
| `AUDIT_MAX_INPUT_BYTES` | `262144` | Maximum encoded open-user-segment input. |
| `AUDIT_MODEL_LIST_MODE` | `allow` | Interpret the exact model list as `allow` or `audit`. |
| `AUDIT_API_KEY_FILE` | `/run/secrets/audit_api_key` | File containing the auditor bearer token. |
| `AUDIT_FINGERPRINT_KEY_FILE` | `/run/secrets/audit_fingerprint_key` | File containing at least 32 bytes of HMAC key material. |
| `AUDIT_PROMPT_FILE` | `/etc/llm-filter-sidecar/audit-prompt.txt` | Deployed semantic policy. |
| `AUDIT_MODEL_LIST_FILE` | `/etc/llm-filter-sidecar/audit-model-list.txt` | Exact, case-sensitive model IDs, one per line. |

Keep both keys out of environment variables and `.env`. Use the repository's `scripts/prepare-audit-secrets.sh`; it refuses to overwrite an existing fingerprint key.

### Model Selection

- `allow`: listed models bypass semantic audit; unlisted models are audited. An empty list audits every valid model.
- `audit`: listed models are audited; unlisted models bypass semantic audit. An empty list audits no valid model.
- Missing or non-string request models always audit in both modes.
- Blank lines, duplicate IDs, and lines beginning with `#` are ignored. Matching remains exact and case-sensitive.
- Model selection never bypasses privacy redaction.

## Request Coverage

The sidecar filters the exact target routes only:

- Chat Completions: message content text, legacy/function tool-call arguments, function descriptions, and JSON Schema descriptions.
- Responses: `instructions`, string or array `input`, content/output text, function-call arguments, function descriptions, and JSON Schema descriptions.

It does not inspect binary image, audio, or uploaded-file contents. Non-target routes pass through unchanged by design.

## Health

`GET /health` always checks the redaction service. It checks the upstream only when `UPSTREAM_HEALTH_URL` is set. A successful response reports audit state, model-list count/mode, fingerprint availability, component readiness, and the sidecar version without including secrets or prompts.
