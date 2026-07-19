# Contributing

Keep changes aligned with the gateway's narrow boundary: structured redaction, optional semantic audit, and streaming proxying for OpenAI-compatible routes.

Before opening a pull request:

```bash
gofmt -w main.go main_test.go
go test ./...
go vet ./...
go build ./...
```

Add focused tests for schema changes, route-normalization behavior, fail-closed paths, and privacy-safe logging. Do not commit `.env`, secret files, production prompts, request bodies, hostnames, IP addresses, or deployment-specific model allowlists.

Changes to `audit-prompt.txt` must include paired block/allow evidence across the affected policy boundary without including operational harmful instructions or real user content.
