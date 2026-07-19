FROM golang:1.26-alpine AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY main.go main_test.go ./
RUN go test ./...
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/llm-filter-sidecar ./main.go

FROM alpine:3.23

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 sidecar \
    && adduser -S -D -H -u 65532 -G sidecar sidecar
COPY --from=build /out/llm-filter-sidecar /usr/local/bin/llm-filter-sidecar
COPY audit-prompt.txt audit-model-list.txt /etc/llm-filter-sidecar/

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -T 3 -O /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/llm-filter-sidecar"]
