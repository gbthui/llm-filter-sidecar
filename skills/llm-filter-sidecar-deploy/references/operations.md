# Operations Runbook

## Inspect Safely

From the deployment directory, identify the actual Compose files before substituting them into commands:

```bash
docker compose -f compose.yaml ps
docker inspect --format '{{.Name}} {{.Image}} {{json .NetworkSettings.Ports}}' <gateway-container>
ss -ltnp
docker system df -v
```

If nginx owns the public route, read its site configuration and confirm the upstream host port. Avoid `nginx -T` without considering whether its output contains unrelated sensitive configuration.

Do not print `.env`, secret files, expanded authorization values, or raw application logs.

## New Installation

```bash
git clone https://github.com/gbthui/llm-filter-sidecar.git
cd llm-filter-sidecar
cp .env.example .env
# Edit UPSTREAM_URL and, optionally, UPSTREAM_HEALTH_URL.
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 240
./scripts/verify.sh http://127.0.0.1:8080 401
```

The expected status is the known response from the upstream for the script's fake API key. Supply the upstream's actual deterministic status instead of accepting a range.

The default `privacy-filter` build context is pinned to a public commit. Change that pin only as an explicit dependency update and rerun gateway tests.

## Enable Audit

```bash
./scripts/prepare-audit-secrets.sh
# Populate secrets/audit_api_key without placing the value on a shell command line.
# Set SIDECAR_UID/SIDECAR_GID to `id -u`/`id -g` on Linux.
# Set AUDIT_URL, AUDIT_MODEL, and model-list settings in .env.
docker compose -f compose.yaml -f compose.audit.yaml config --quiet
docker compose -f compose.yaml -f compose.audit.yaml up -d --build --wait --wait-timeout 240
./scripts/verify.sh http://127.0.0.1:8080 401
```

Use `AUDIT_ALLOW_INSECURE_HTTP=true` only when the auditor is reached exclusively over a trusted private network. HTTPS remains the public default.

## Brownfield Port-Preserving Cutover

1. Keep the original Compose file unchanged.
2. Create a sibling or overlay Compose definition that places the existing upstream, `privacy-filter`, and `sidecar` on a shared network.
3. Remove the host-port publication from the upstream in the candidate definition.
4. Publish the old host address and port from `sidecar`.
5. Start the candidate on a different loopback port first and verify it.
6. Record exact image IDs before stopping the original port owner.

Perform the final switch without volumes:

```bash
docker compose -f <original-compose> down
if ! docker compose -f <filtered-compose> up -d --wait --wait-timeout 240; then
  docker compose -f <filtered-compose> down
  docker compose -f <original-compose> up -d --wait --wait-timeout 240
  exit 1
fi
```

Run the health and fake-key traversal check immediately. If either fails, perform the same explicit rollback. Never add `-v`.

## Update A Source-Built Sidecar

Tag the running image as a known-good rollback point, build a unique candidate, and recreate only the sidecar:

```bash
docker inspect --format '{{.Image}}' <sidecar-container>
docker image tag <resolved-image-id> llm-filter-sidecar:rollback-<timestamp>
SIDECAR_IMAGE=llm-filter-sidecar:candidate-<timestamp> docker compose build --pull sidecar
SIDECAR_IMAGE=llm-filter-sidecar:candidate-<timestamp> docker compose up -d --no-deps --force-recreate --wait sidecar
```

Verify before retagging or removing anything. Keep the current image and one known-good rollback tag.

For a registry image, run an explicit `docker compose pull sidecar` before recreation. Do not assume a local moving tag is current.

## Nginx

Keep nginx pointed at the same loopback host port used before the cutover. Preserve streaming settings: disable response buffering for SSE routes and use timeouts appropriate to long LLM responses. Test nginx configuration before reload, then verify through both the loopback port and public hostname.

## Disk Hygiene

Inspect first:

```bash
df -hT
df -ih
docker system df -v
journalctl --disk-usage 2>/dev/null || true
find /var/lib/docker/containers -name '*-json.log' -printf '%s %p\n' 2>/dev/null | sort -n | tail -20
```

After the live stack passes health and smoke checks, remove only dangling images with `docker image prune -f`, then recheck usage. Do not remove application data mounts, active images, or the most recent rollback image. Do not use `docker system prune -a` for routine maintenance.

The repository Compose file applies `json-file` rotation (`20m`, three files) to both services. Recreating a service applies future rotation but does not erase its existing log file.
