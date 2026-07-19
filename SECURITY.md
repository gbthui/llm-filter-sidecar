# Security Policy

## Reporting

Report vulnerabilities through this repository's private GitHub security-advisory workflow. Do not place real prompts, credentials, API keys, request bodies, fingerprints, or production topology in a public issue.

The latest revision on `main` is the supported security line until tagged releases are published.

## Intended Boundary

The sidecar protects text fields on exact OpenAI-compatible Chat Completions and Responses routes. It does not inspect binary image/audio/file data or non-target routes. Deployers must decide whether other upstream routes should be disabled, separately filtered, or intentionally passed through.

The design assumes:

- the redaction service and upstream network path are trusted;
- audit secrets are mounted as files and are not exposed through environment variables;
- the audit endpoint uses HTTPS unless it is isolated on an explicitly trusted private network;
- callers cannot bypass the sidecar and reach the upstream's old published port;
- reverse proxies preserve streaming and enforce their own TLS, authentication, and request-size controls.

## Operational Invariants

- Keep audit disabled until its policy/model pair passes deployment-specific tests.
- Keep the sidecar bound to loopback unless a deliberate network design requires otherwise.
- Do not log raw target-route bodies or enable generic HTTP body tracing around this service.
- Retain a known-good image before policy or gateway changes.
- Never delete application volumes during a gateway rollback.
- Pin and review external source-build revisions.

The included semantic policy and any LLM auditor remain probabilistic controls. They supplement rather than replace upstream authorization, abuse monitoring, rate limits, and incident response.
