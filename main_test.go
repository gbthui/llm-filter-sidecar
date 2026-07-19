package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type auditRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type auditResponder func(http.ResponseWriter, *http.Request, auditRequest)
type redactionResponder func(http.ResponseWriter, *http.Request)
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type gatewayHarness struct {
	server         *httptest.Server
	auditCalls     atomic.Int32
	upstreamCalls  atomic.Int32
	upstreamBodies chan []byte
	auditRequests  chan auditRequest
}

func newGatewayHarness(t *testing.T, config auditConfig, responder auditResponder) *gatewayHarness {
	return newGatewayHarnessWithRedactor(t, config, responder, nil)
}

func newGatewayHarnessWithRedactor(t *testing.T, config auditConfig, responder auditResponder, redactor redactionResponder) *gatewayHarness {
	t.Helper()
	harness := &gatewayHarness{
		upstreamBodies: make(chan []byte, 8),
		auditRequests:  make(chan auditRequest, 8),
	}

	filterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if redactor != nil {
			redactor(w, r)
			return
		}
		var payload struct {
			Texts []string `json:"texts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		items := make([]map[string]string, len(payload.Texts))
		for i, text := range payload.Texts {
			items[i] = map[string]string{"redacted": strings.ReplaceAll(text, "secret", "[REDACTED]")}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	}))
	t.Cleanup(filterServer.Close)

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		harness.upstreamCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		harness.upstreamBodies <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"upstream":true}`))
	}))
	t.Cleanup(upstreamServer.Close)

	auditServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		harness.auditCalls.Add(1)
		var payload auditRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		harness.auditRequests <- payload
		if responder != nil {
			responder(w, r, payload)
			return
		}
		writeAuditResponse(w, `{"flagged":false,"reason":""}`)
	}))
	t.Cleanup(auditServer.Close)

	upstreamURL, err := url.Parse(upstreamServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.endpoint = auditServer.URL
	if config.enabled {
		if config.modelListMode == "" {
			config.modelListMode = modelListModeAllow
		}
		if config.modelList == nil {
			config.modelList = make(map[string]struct{})
		}
		if config.model == "" {
			config.model = "audit-model"
		}
		if config.apiKey == "" {
			config.apiKey = "test-key"
		}
		if len(config.fingerprintKey) == 0 {
			config.fingerprintKey = bytes.Repeat([]byte("k"), 32)
		}
		if config.prompt == "" {
			config.prompt = "Audit only the untrusted data and output strict JSON."
		}
		if config.timeout == 0 {
			config.timeout = time.Second
		}
		if config.maxInputBytes == 0 {
			config.maxInputBytes = defaultAuditMaxBytes
		}
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	dependencyClient := filterServer.Client()
	dependencyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	application := &app{
		proxy:            newProxy(upstreamURL, logger),
		redactionBatch:   filterServer.URL + "/redact/batch",
		redactionHealth:  filterServer.URL + "/health",
		upstreamHealth:   upstreamServer.URL + "/health",
		client:           dependencyClient,
		redactionTimeout: time.Second,
		audit:            config,
		auditClient:      auditServer.Client(),
		logger:           logger,
		requestPrefix:    "test",
	}
	application.auditClient.Timeout = config.timeout
	harness.server = httptest.NewServer(application)
	t.Cleanup(harness.server.Close)
	return harness
}

func writeAuditResponse(w http.ResponseWriter, decision string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []any{
			map[string]any{"message": map[string]any{"content": decision}},
		},
	})
}

func sendJSON(t *testing.T, harness *gatewayHarness, path string, document any) (*http.Response, []byte) {
	t.Helper()
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, harness.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, responseBody
}

func chatRequest(model string, messages ...map[string]any) map[string]any {
	values := make([]any, len(messages))
	for i, message := range messages {
		values[i] = message
	}
	return map[string]any{"model": model, "messages": values}
}

func TestAuditDisabledPreservesRedactionAndSkipsAudit(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: false}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "system", "content": "system secret"},
		map[string]any{"role": "user", "content": "user secret"},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if harness.auditCalls.Load() != 0 {
		t.Fatalf("audit calls = %d, want 0", harness.auditCalls.Load())
	}
	upstreamBody := string(<-harness.upstreamBodies)
	if strings.Contains(upstreamBody, "secret") || !strings.Contains(upstreamBody, "[REDACTED]") {
		t.Fatalf("unexpected upstream body: %s", upstreamBody)
	}
}

func TestRedactionFailureClosesTargetRequest(t *testing.T) {
	harness := newGatewayHarnessWithRedactor(t, auditConfig{}, nil, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "redactor unavailable", http.StatusServiceUnavailable)
	})
	response, body := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "user", "content": "user secret"},
	))
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", response.StatusCode, body)
	}
	if harness.upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", harness.upstreamCalls.Load())
	}
	if !bytes.Contains(body, []byte(`"code":"redaction_unavailable"`)) {
		t.Fatalf("unexpected error body: %s", body)
	}
}

func TestRedactionRedirectDoesNotForwardRawText(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	defer redirectTarget.Close()
	harness := newGatewayHarnessWithRedactor(t, auditConfig{}, nil, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	})
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "user", "content": "user secret"},
	))
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.StatusCode)
	}
	if redirectedCalls.Load() != 0 || harness.upstreamCalls.Load() != 0 {
		t.Fatalf("redirect target calls = %d, upstream calls = %d; want 0, 0", redirectedCalls.Load(), harness.upstreamCalls.Load())
	}
}

func TestNonTargetRoutePassesThroughUnchanged(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	response, _ := sendJSON(t, harness, "/v1/embeddings", map[string]any{"input": "user secret"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if harness.auditCalls.Load() != 0 {
		t.Fatalf("audit calls = %d, want 0", harness.auditCalls.Load())
	}
	if upstreamBody := string(<-harness.upstreamBodies); !strings.Contains(upstreamBody, "user secret") {
		t.Fatalf("non-target body was modified: %s", upstreamBody)
	}
}

func TestNonTargetStreamingResponseIsFlushed(t *testing.T) {
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := httptest.NewServer(&app{proxy: newProxy(upstreamURL, logger), logger: logger})
	defer server.Close()

	response, err := http.Get(server.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "data: first\n" {
		t.Fatalf("first streamed line = %q", line)
	}
	close(release)
	remainder, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(remainder, []byte("data: second")) {
		t.Fatalf("missing second streamed event: %q", remainder)
	}
}

func TestToolTextFieldsAreRedacted(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{}, nil)
	document := chatRequest("normal-model",
		map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type":     "function",
				"function": map[string]any{"name": "lookup", "arguments": `{"token":"secret"}`},
			}},
		},
	)
	document["tools"] = []any{map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        "lookup",
			"description": "uses a secret service",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"token": map[string]any{"type": "string", "description": "the secret token"},
				},
			},
		},
	}}
	response, _ := sendJSON(t, harness, "/v1/chat/completions", document)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	upstreamBody := string(<-harness.upstreamBodies)
	if strings.Contains(upstreamBody, "secret") || strings.Count(upstreamBody, "[REDACTED]") < 3 {
		t.Fatalf("tool text was not fully redacted: %s", upstreamBody)
	}
}

func TestResponsesFunctionOutputAndArgumentsAreRedacted(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{}, nil)
	document := map[string]any{
		"model": "normal-model",
		"input": []any{
			map[string]any{"type": "function_call", "arguments": `{"token":"secret"}`},
			map[string]any{"type": "function_call_output", "output": "returned secret"},
		},
	}
	response, _ := sendJSON(t, harness, "/v1/responses", document)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	upstreamBody := string(<-harness.upstreamBodies)
	if strings.Contains(upstreamBody, "secret") || strings.Count(upstreamBody, "[REDACTED]") != 2 {
		t.Fatalf("Responses function data was not redacted: %s", upstreamBody)
	}
}

func TestTargetRouteAliasesFailClosedWithoutAuditOrUpstream(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	for _, route := range []string{"/v1/responses/responses", "/v1/responses/", "/v1/chat/completions/extra", "/v1//responses", "/v1/chat/../chat/completions"} {
		t.Run(route, func(t *testing.T) {
			response, body := sendJSON(t, harness, route, chatRequest("normal-model",
				map[string]any{"role": "user", "content": "user secret"},
			))
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body=%s", response.StatusCode, body)
			}
			if !bytes.Contains(body, []byte(`"code":"unsupported_target_route"`)) {
				t.Fatalf("unexpected body: %s", body)
			}
		})
	}
	if harness.auditCalls.Load() != 0 || harness.upstreamCalls.Load() != 0 {
		t.Fatalf("audit calls = %d, upstream calls = %d; want 0, 0", harness.auditCalls.Load(), harness.upstreamCalls.Load())
	}
}

func TestAllowModeListedModelSkipsAuditButStillRedacts(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{
		enabled:       true,
		modelListMode: modelListModeAllow,
		modelList:     map[string]struct{}{"safe-model": {}},
	}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("safe-model",
		map[string]any{"role": "user", "content": "user secret"},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if harness.auditCalls.Load() != 0 {
		t.Fatalf("audit calls = %d, want 0", harness.auditCalls.Load())
	}
	if upstreamBody := string(<-harness.upstreamBodies); strings.Contains(upstreamBody, "secret") || !strings.Contains(upstreamBody, "[REDACTED]") {
		t.Fatalf("unexpected upstream body: %s", upstreamBody)
	}
}

func TestModelListMatchingIsCaseSensitive(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{
		enabled:       true,
		modelListMode: modelListModeAllow,
		modelList:     map[string]struct{}{"Safe-Model": {}},
	}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("safe-model",
		map[string]any{"role": "user", "content": "hello"},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if harness.auditCalls.Load() != 1 {
		t.Fatalf("audit calls = %d, want 1", harness.auditCalls.Load())
	}
}

func TestAuditModeSelectsOnlyListedModels(t *testing.T) {
	tests := []struct {
		name       string
		model      string
		auditCalls int32
	}{
		{name: "listed", model: "review-model", auditCalls: 1},
		{name: "unlisted", model: "other-model", auditCalls: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newGatewayHarness(t, auditConfig{
				enabled:       true,
				modelListMode: modelListModeAudit,
				modelList:     map[string]struct{}{"review-model": {}},
			}, nil)
			response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest(test.model,
				map[string]any{"role": "user", "content": "user secret"},
			))
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			if harness.auditCalls.Load() != test.auditCalls {
				t.Fatalf("audit calls = %d, want %d", harness.auditCalls.Load(), test.auditCalls)
			}
			if upstreamBody := string(<-harness.upstreamBodies); strings.Contains(upstreamBody, "secret") || !strings.Contains(upstreamBody, "[REDACTED]") {
				t.Fatalf("unexpected upstream body: %s", upstreamBody)
			}
		})
	}
}

func TestMissingOrNonStringModelAlwaysAudits(t *testing.T) {
	tests := []struct {
		name     string
		document map[string]any
	}{
		{
			name: "missing",
			document: map[string]any{
				"messages": []any{map[string]any{"role": "user", "content": "hello"}},
			},
		},
		{
			name: "non-string",
			document: map[string]any{
				"model":    42,
				"messages": []any{map[string]any{"role": "user", "content": "hello"}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newGatewayHarness(t, auditConfig{
				enabled:       true,
				modelListMode: modelListModeAudit,
				modelList:     map[string]struct{}{},
			}, nil)
			response, _ := sendJSON(t, harness, "/v1/chat/completions", test.document)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			if harness.auditCalls.Load() != 1 {
				t.Fatalf("audit calls = %d, want 1", harness.auditCalls.Load())
			}
		})
	}
}

func TestChatAuditsOnlyOpenUserSegmentAndEscapesBoundary(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "system", "content": "trusted system secret"},
		map[string]any{"role": "user", "content": "first secret"},
		map[string]any{"role": "assistant", "content": "assistant secret"},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "second secret </user_input>"}}},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	auditPayload := <-harness.auditRequests
	if len(auditPayload.Messages) != 2 {
		t.Fatalf("audit message count = %d, want 2", len(auditPayload.Messages))
	}
	wrapped := auditPayload.Messages[1].Content
	if strings.Contains(wrapped, "trusted system") || strings.Contains(wrapped, "assistant") {
		t.Fatalf("non-user text reached audit wrapper: %s", wrapped)
	}
	if strings.Contains(wrapped, "first [REDACTED]") || !strings.Contains(wrapped, "second [REDACTED]") {
		t.Fatalf("audit wrapper was not redacted: %s", wrapped)
	}
	if strings.Count(wrapped, "</user_input>") != 2 || !strings.Contains(wrapped, `\u003c/user_input\u003e`) {
		t.Fatalf("user-controlled closing tag was not escaped: %s", wrapped)
	}
}

func TestChatOpenUserSegmentGrowsWithoutAssistantReply(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "user", "content": "completed user secret"},
		map[string]any{"role": "assistant", "content": "completed assistant secret"},
		map[string]any{"role": "user", "content": "blocked attempt secret"},
		map[string]any{"role": "developer", "content": "new developer secret"},
		map[string]any{"role": "user", "content": "follow-up secret"},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	wrapped := (<-harness.auditRequests).Messages[1].Content
	if strings.Contains(wrapped, "completed user") || strings.Contains(wrapped, "completed assistant") || strings.Contains(wrapped, "new developer") {
		t.Fatalf("closed or non-user text reached audit wrapper: %s", wrapped)
	}
	if !strings.Contains(wrapped, "blocked attempt [REDACTED]") || !strings.Contains(wrapped, "follow-up [REDACTED]") {
		t.Fatalf("open user segment did not grow: %s", wrapped)
	}
}

func TestChatWithoutAssistantAuditsAllUserMessages(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "system", "content": "system secret"},
		map[string]any{"role": "user", "content": "first secret"},
		map[string]any{"role": "user", "content": "second secret"},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	wrapped := (<-harness.auditRequests).Messages[1].Content
	if !strings.Contains(wrapped, "first [REDACTED]") || !strings.Contains(wrapped, "second [REDACTED]") || strings.Contains(wrapped, "system [REDACTED]") {
		t.Fatalf("unexpected audit wrapper: %s", wrapped)
	}
}

func TestResponsesWithoutAssistantAuditsEveryUserMessageOnly(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	document := map[string]any{
		"model":        "normal-model",
		"instructions": "developer secret",
		"input": []any{
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "one secret"}}},
			map[string]any{"role": "developer", "content": []any{map[string]any{"type": "input_text", "text": "skip secret"}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "two secret"}}},
		},
	}
	response, _ := sendJSON(t, harness, "/v1/responses", document)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	wrapped := (<-harness.auditRequests).Messages[1].Content
	if !strings.Contains(wrapped, "one [REDACTED]") || !strings.Contains(wrapped, "two [REDACTED]") || strings.Contains(wrapped, "skip [REDACTED]") || strings.Contains(wrapped, "developer [REDACTED]") {
		t.Fatalf("unexpected Responses audit wrapper: %s", wrapped)
	}
}

func TestResponsesAuditsOnlyOpenUserSegment(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	document := map[string]any{
		"model": "normal-model",
		"input": []any{
			map[string]any{"role": "user", "content": "completed user secret"},
			map[string]any{"role": "assistant", "content": "completed assistant secret"},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "ambiguous secret"}}},
			map[string]any{"role": "developer", "content": "new developer secret"},
			map[string]any{"role": "user", "content": "explicit follow-up secret"},
		},
	}
	response, _ := sendJSON(t, harness, "/v1/responses", document)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	wrapped := (<-harness.auditRequests).Messages[1].Content
	if strings.Contains(wrapped, "completed user") || strings.Contains(wrapped, "completed assistant") || strings.Contains(wrapped, "new developer") {
		t.Fatalf("closed or non-user text reached Responses audit wrapper: %s", wrapped)
	}
	if !strings.Contains(wrapped, "ambiguous [REDACTED]") || !strings.Contains(wrapped, "explicit follow-up [REDACTED]") {
		t.Fatalf("Responses open user segment did not grow: %s", wrapped)
	}
}

func TestAuditInputFingerprintIsKeyedAndDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte("a"), 32)
	input := []byte(`[{"message_index":0,"parts":["sensitive prompt"]}]`)
	fingerprint := auditInputFingerprint(key, input)
	if fingerprint != auditInputFingerprint(key, input) {
		t.Fatal("same key and input produced different fingerprints")
	}
	if fingerprint == auditInputFingerprint(bytes.Repeat([]byte("b"), 32), input) {
		t.Fatal("different keys produced the same fingerprint")
	}
	if fingerprint == auditInputFingerprint(key, append(append([]byte(nil), input...), '!')) {
		t.Fatal("different inputs produced the same fingerprint")
	}
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("fingerprint = %q, want 32-byte hex SHA-256: %v", fingerprint, err)
	}
	if strings.Contains(fingerprint, "sensitive") {
		t.Fatalf("fingerprint leaked input: %s", fingerprint)
	}
	if auditInputFingerprint(nil, input) != "" {
		t.Fatal("missing key should not produce a fingerprint")
	}
}

func TestLogAuditIncludesFingerprint(t *testing.T) {
	var output bytes.Buffer
	application := &app{
		audit:  auditConfig{modelListMode: modelListModeAudit},
		logger: slog.New(slog.NewJSONHandler(&output, nil)),
	}
	application.logAudit("req-1", "/v1/responses", "model-a", "allowed", "", time.Millisecond, 1, 42, strings.Repeat("a", 64))
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["input_fingerprint"] != strings.Repeat("a", 64) {
		t.Fatalf("input_fingerprint = %#v", record["input_fingerprint"])
	}
}

func TestFlaggedDecisionBlocksUpstream(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, func(w http.ResponseWriter, _ *http.Request, _ auditRequest) {
		writeAuditResponse(w, `{"flagged":true,"reason":"网络攻击"}`)
	})
	response, body := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "user", "content": "attack"},
	))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", response.StatusCode, body)
	}
	if harness.upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", harness.upstreamCalls.Load())
	}
	if !bytes.Contains(body, []byte(`"code":"prompt_flagged"`)) || !bytes.Contains(body, []byte("网络攻击")) {
		t.Fatalf("unexpected error body: %s", body)
	}
}

func TestAuditFailureClosesRequest(t *testing.T) {
	tests := map[string]auditResponder{
		"non-2xx": func(w http.ResponseWriter, _ *http.Request, _ auditRequest) {
			http.Error(w, "provider failure", http.StatusInternalServerError)
		},
		"invalid decision": func(w http.ResponseWriter, _ *http.Request, _ auditRequest) {
			writeAuditResponse(w, "```json\n{\"flagged\":false,\"reason\":\"\"}\n```")
		},
		"reason too long": func(w http.ResponseWriter, _ *http.Request, _ auditRequest) {
			writeAuditResponse(w, `{"flagged":true,"reason":"这是一个超过二十个字符限制的审核判定原因文本"}`)
		},
	}
	for name, responder := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newGatewayHarness(t, auditConfig{enabled: true}, responder)
			response, body := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
				map[string]any{"role": "user", "content": "hello"},
			))
			if response.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body=%s", response.StatusCode, body)
			}
			if harness.upstreamCalls.Load() != 0 {
				t.Fatalf("upstream calls = %d, want 0", harness.upstreamCalls.Load())
			}
			if !bytes.Contains(body, []byte(`"code":"audit_unavailable"`)) {
				t.Fatalf("unexpected error body: %s", body)
			}
		})
	}
}

func TestAuditNetworkErrorDoesNotExposeEndpointPath(t *testing.T) {
	application := &app{
		audit: auditConfig{
			endpoint: "https://audit.example/private-deployment-token/v1/chat/completions",
			model:    "audit-model",
			apiKey:   "test-key",
			prompt:   "Return strict JSON.",
			timeout:  time.Second,
		},
		auditClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("synthetic network failure")
		})},
	}
	_, err := application.auditPrompt(context.Background(), []byte(`[{"message_index":0,"parts":["hello"]}]`))
	if err == nil {
		t.Fatal("auditPrompt returned no error")
	}
	if strings.Contains(err.Error(), "private-deployment-token") || !strings.Contains(err.Error(), "synthetic network failure") {
		t.Fatalf("unsafe or unexpected audit error: %v", err)
	}
}

func TestAuditTimeoutClosesRequest(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true, timeout: 20 * time.Millisecond}, func(_ http.ResponseWriter, r *http.Request, _ auditRequest) {
		<-r.Context().Done()
	})
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "user", "content": "hello"},
	))
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.StatusCode)
	}
	if harness.upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", harness.upstreamCalls.Load())
	}
}

func TestOversizedAuditInputReturns413WithoutAuditOrUpstream(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true, maxInputBytes: 8}, nil)
	response, body := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "user", "content": "long user input"},
	))
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", response.StatusCode, body)
	}
	if harness.auditCalls.Load() != 0 || harness.upstreamCalls.Load() != 0 {
		t.Fatalf("audit calls = %d, upstream calls = %d; want 0, 0", harness.auditCalls.Load(), harness.upstreamCalls.Load())
	}
}

func TestNoUserTextSkipsAudit(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{enabled: true}, nil)
	response, _ := sendJSON(t, harness, "/v1/chat/completions", chatRequest("normal-model",
		map[string]any{"role": "system", "content": "system only"},
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if harness.auditCalls.Load() != 0 || harness.upstreamCalls.Load() != 1 {
		t.Fatalf("audit calls = %d, upstream calls = %d; want 0, 1", harness.auditCalls.Load(), harness.upstreamCalls.Load())
	}
}

func TestDisabledAuditIgnoresStubConfiguration(t *testing.T) {
	t.Setenv("AUDIT_ENABLED", "false")
	t.Setenv("AUDIT_URL", "not a URL")
	t.Setenv("AUDIT_ALLOW_INSECURE_HTTP", "not-a-boolean")
	t.Setenv("AUDIT_MODEL", "")
	t.Setenv("AUDIT_TIMEOUT", "broken")
	t.Setenv("AUDIT_MAX_INPUT_BYTES", "broken")
	t.Setenv("AUDIT_MODEL_LIST_MODE", "broken")
	t.Setenv("AUDIT_API_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("AUDIT_FINGERPRINT_KEY_FILE", filepath.Join(t.TempDir(), "missing-fingerprint"))
	t.Setenv("AUDIT_MODEL_LIST_FILE", filepath.Join(t.TempDir(), "missing"))
	config, err := loadAuditConfig()
	if err != nil {
		t.Fatalf("disabled audit rejected stubs: %v", err)
	}
	if config.enabled {
		t.Fatal("audit unexpectedly enabled")
	}
	if config.modelListMode != modelListModeAllow || len(config.modelList) != 0 {
		t.Fatalf("disabled defaults = mode %q, list %#v", config.modelListMode, config.modelList)
	}
}

func TestParseBaseURLAcceptsOnlyCredentialFreeHTTPURLs(t *testing.T) {
	for _, test := range []struct {
		value   string
		wantErr bool
	}{
		{value: "http://upstream:8080"},
		{value: "https://api.example/v1"},
		{value: "ftp://api.example", wantErr: true},
		{value: "http://user:password@api.example", wantErr: true},
		{value: "http://api.example?token=secret", wantErr: true},
		{value: "not-a-url", wantErr: true},
	} {
		_, err := parseBaseURL(test.value)
		if (err != nil) != test.wantErr {
			t.Fatalf("parseBaseURL(%q) error = %v, wantErr %t", test.value, err, test.wantErr)
		}
	}
}

func TestEnabledAuditLoadsStrictConfigurationAndModelList(t *testing.T) {
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "key")
	fingerprintKeyFile := filepath.Join(directory, "fingerprint-key")
	promptFile := filepath.Join(directory, "prompt")
	modelListFile := filepath.Join(directory, "model-list")
	if err := os.WriteFile(keyFile, []byte("test-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fingerprintKeyFile, bytes.Repeat([]byte("f"), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptFile, []byte("test prompt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modelListFile, []byte("# exact, case-sensitive IDs\n model-a \n\nmodel-a\nModel-B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_ENABLED", "true")
	t.Setenv("AUDIT_URL", "https://audit.example/v1/chat/completions")
	t.Setenv("AUDIT_MODEL", "audit-model")
	t.Setenv("AUDIT_MODEL_LIST_MODE", "audit")
	t.Setenv("AUDIT_API_KEY_FILE", keyFile)
	t.Setenv("AUDIT_FINGERPRINT_KEY_FILE", fingerprintKeyFile)
	t.Setenv("AUDIT_PROMPT_FILE", promptFile)
	t.Setenv("AUDIT_MODEL_LIST_FILE", modelListFile)
	config, err := loadAuditConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.modelListMode != modelListModeAudit {
		t.Fatalf("model list mode = %q, want audit", config.modelListMode)
	}
	if len(config.modelList) != 2 {
		t.Fatalf("model list count = %d, want 2", len(config.modelList))
	}
	if _, ok := config.modelList["model-a"]; !ok {
		t.Fatal("trimmed model-a missing")
	}
	if _, ok := config.modelList["Model-B"]; !ok {
		t.Fatal("case-sensitive Model-B missing")
	}
	if !bytes.Equal(config.fingerprintKey, bytes.Repeat([]byte("f"), 32)) {
		t.Fatalf("fingerprint key length = %d, want 32", len(config.fingerprintKey))
	}
}

func TestEnabledAuditRequiresHTTPSUnlessExplicitlyAllowed(t *testing.T) {
	directory := t.TempDir()
	apiKeyFile := filepath.Join(directory, "api-key")
	fingerprintKeyFile := filepath.Join(directory, "fingerprint-key")
	promptFile := filepath.Join(directory, "prompt")
	modelListFile := filepath.Join(directory, "model-list")
	if err := os.WriteFile(apiKeyFile, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fingerprintKeyFile, bytes.Repeat([]byte("f"), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptFile, []byte("test prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modelListFile, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		endpoint  string
		allowHTTP string
		wantErr   bool
	}{
		{name: "HTTPS", endpoint: "https://audit.example/v1/chat/completions"},
		{name: "HTTP rejected by default", endpoint: "http://audit:8080/v1/chat/completions", wantErr: true},
		{name: "HTTP allowed explicitly", endpoint: "http://audit:8080/v1/chat/completions", allowHTTP: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("AUDIT_ENABLED", "true")
			t.Setenv("AUDIT_URL", test.endpoint)
			t.Setenv("AUDIT_ALLOW_INSECURE_HTTP", test.allowHTTP)
			t.Setenv("AUDIT_MODEL", "audit-model")
			t.Setenv("AUDIT_API_KEY_FILE", apiKeyFile)
			t.Setenv("AUDIT_FINGERPRINT_KEY_FILE", fingerprintKeyFile)
			t.Setenv("AUDIT_PROMPT_FILE", promptFile)
			t.Setenv("AUDIT_MODEL_LIST_FILE", modelListFile)
			_, err := loadAuditConfig()
			if (err != nil) != test.wantErr {
				t.Fatalf("loadAuditConfig() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestEnabledAuditRejectsShortFingerprintKey(t *testing.T) {
	directory := t.TempDir()
	apiKeyFile := filepath.Join(directory, "api-key")
	fingerprintKeyFile := filepath.Join(directory, "fingerprint-key")
	if err := os.WriteFile(apiKeyFile, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fingerprintKeyFile, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_ENABLED", "true")
	t.Setenv("AUDIT_URL", "https://audit.example/v1/chat/completions")
	t.Setenv("AUDIT_MODEL", "audit-model")
	t.Setenv("AUDIT_API_KEY_FILE", apiKeyFile)
	t.Setenv("AUDIT_FINGERPRINT_KEY_FILE", fingerprintKeyFile)
	if _, err := loadAuditConfig(); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("short fingerprint key error = %v", err)
	}
}

func TestEnabledAuditRejectsInvalidModelListMode(t *testing.T) {
	t.Setenv("AUDIT_ENABLED", "true")
	t.Setenv("AUDIT_URL", "https://audit.example/v1/chat/completions")
	t.Setenv("AUDIT_MODEL", "audit-model")
	t.Setenv("AUDIT_MODEL_LIST_MODE", "ALLOW")
	if _, err := loadAuditConfig(); err == nil || !strings.Contains(err.Error(), "AUDIT_MODEL_LIST_MODE") {
		t.Fatalf("invalid mode error = %v", err)
	}
}

func TestHealthReportsAuditStateAndModelList(t *testing.T) {
	harness := newGatewayHarness(t, auditConfig{
		enabled:       true,
		modelListMode: modelListModeAudit,
		modelList:     map[string]struct{}{"one": {}, "two": {}},
	}, nil)
	response, err := http.Get(harness.server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["audit_enabled"] != true || body["audit_model_list_mode"] != "audit" || body["audit_model_list_count"] != float64(2) || body["audit_input_fingerprint_enabled"] != true {
		t.Fatalf("unexpected health body: %#v", body)
	}
}
