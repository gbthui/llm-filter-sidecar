---
name: llm-filter-sidecar-deploy
description: Deploy, update, verify, roll back, and troubleshoot llm-filter-sidecar in front of an OpenAI-compatible upstream using Docker Compose, privacy-filter redaction, and optional semantic prompt audit. Use for new installations, port-preserving brownfield cutovers, nginx integration, audit enablement or policy changes, privacy-safe incident diagnosis, image/log disk hygiene, and migrations from a direct upstream exposure to the filtered gateway.
---

# LLM Filter Sidecar Deploy

Operate the public, upstream-agnostic filtering gateway without exposing prompts or coupling the deployment to a particular LLM backend.

## Read The Relevant Reference

- Read [references/configuration.md](references/configuration.md) before creating or changing environment, secret, model-list, network, or health settings.
- Read [references/operations.md](references/operations.md) for concrete install, cutover, update, rollback, nginx, or disk-hygiene commands.
- Read [references/policy-testing.md](references/policy-testing.md) before enabling semantic audit or changing `audit-prompt.txt`.

## Preserve These Invariants

- Filter exact `POST /v1/chat/completions` and `POST /v1/responses` routes before proxying them.
- Redact every selected request regardless of whether semantic audit selects its model.
- Fail closed on target-route redaction failure. When audit is enabled and selected, fail closed on timeout, non-2xx, malformed decision JSON, or oversized audit input.
- Pass non-target routes through unchanged and preserve upstream streaming.
- Send only already-redacted open-segment user text to the auditor. Never send system, developer, assistant, or tool text to semantic audit.
- Keep audit disabled by default. Require explicit configuration and file-backed secrets to enable it.
- Log no raw bodies, prompts, authorization headers, API keys, `.env` contents, or audit-provider response bodies.
- Use keyed HMAC-SHA256 fingerprints for retry correlation. Never substitute an unkeyed prompt hash.
- Bind the public sample to loopback by default. Expose another interface only when the user explicitly requires it and the surrounding firewall/proxy is understood.
- Never use `docker compose down -v` during a switch or rollback.

## Workflow

1. Inspect before changing anything.
   - Locate the current Compose files, published port, upstream health route, reverse proxy, Docker networks, data mounts, and currently running image IDs.
   - Read configuration names and safe metadata only. Do not print `.env`, secret files, request bodies, or prompt-bearing logs.
   - Confirm whether the upstream runs in the same Compose project, another Docker network, or on the host.

2. Choose the deployment shape.
   - For a new installation, use this repository's `compose.yaml` and optionally `compose.audit.yaml`.
   - For an existing stack, keep its original Compose file unchanged. Create a dedicated overlay or sibling Compose file that removes the upstream's host-port publication and publishes the same host port from `sidecar`.
   - Keep application databases, volumes, and bind mounts owned by the original stack.

3. Stage a candidate.
   - Pin external source builds and use a unique image tag.
   - Validate with `docker compose ... config --quiet`; do not print expanded Compose configuration into shared logs.
   - Start the candidate on a separate loopback port when changing audit policy or a production routing path.

4. Verify before cutover.
   - Require a healthy redaction service and sidecar.
   - Run `scripts/verify.sh <base-url> <expected-upstream-status>` from the repository.
   - When audit is enabled, run the paired policy suite in [references/policy-testing.md](references/policy-testing.md).
   - Confirm the running prompt SHA-256 and inspect only metadata-only audit logs.

5. Cut over with rollback prepared.
   - Record current container image IDs and retain one known-good rollback tag.
   - Stop only the component that owns the old host port, then start the sidecar stack on that port.
   - If readiness or smoke verification fails, stop the candidate and restart the original owner immediately without deleting volumes.

6. Report exact evidence.
   - State image IDs/tags, bound addresses, health result, test counts, prompt hash when applicable, and retained rollback point.
   - State any unverified item explicitly. Never claim Docker or policy verification from static inspection alone.

## Updates And Troubleshooting

- Pull explicitly before recreating a moving image tag. A local `latest` tag is not proof of freshness.
- Recreate only the changed service when dependencies and data stores are healthy.
- Treat `502 redaction_unavailable` and `502 audit_unavailable` as fail-closed signals; inspect dependency health and metadata-only errors before changing policy.
- Treat a growing open user segment after a blocked turn as intentional stateless behavior. The client-supplied history is the only state.
- Add Docker `json-file` rotation instead of periodically truncating live logs.
- Run `docker image prune -f` only after the live stack passes health and smoke checks. Never use `docker system prune -a` for routine maintenance.

## Prompt Changes

Treat `audit-prompt.txt` as deployed policy code. Build a unique candidate image because the Dockerfile copies the prompt into the image. Do not assume editing the host file changes a running container. Follow the candidate, paired-test, hash-verification, and rollback sequence in [references/policy-testing.md](references/policy-testing.md).
