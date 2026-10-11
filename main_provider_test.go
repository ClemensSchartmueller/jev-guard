package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

func TestTraceGateEvaluationUsesConfiguredProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			fmt.Fprint(w, `{"choices":[{"message":{"content":"{\"is_workspace_contained\":1,\"destructive_level\":3,\"destructive_confidence\":0.9,\"violation_category\":\"none\",\"violation_confidence\":0.9}"},"finish_reason":"stop"}]}`)
		case "/v1/messages":
			fmt.Fprint(w, `{"content":[{"type":"text","text":"{\"is_workspace_contained\":1,\"destructive_level\":1,\"destructive_confidence\":0.8,\"violation_category\":\"none\",\"violation_confidence\":0.9}"}],"stop_reason":"end_turn"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "make deploy", Cwd: t.TempDir()}
	for _, tc := range []struct {
		provider   string
		wantDec    harness.Decision
		wantSource string
	}{
		{"openai", harness.DecisionDeny, "policy_jev_destructive"},
		{"anthropic", harness.DecisionAllow, "policy_jev_allow"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Provider, cfg.APIKey, cfg.BaseURL, cfg.Model = tc.provider, "test-key", server.URL+"/v1", "test-model"
			trace := traceGateEvaluation(call, cfg, false)
			if trace.EvalErr != nil || trace.Final == nil || trace.Final.Decision != tc.wantDec || trace.Final.Source != tc.wantSource {
				t.Fatalf("final=%+v err=%v; want %s from %s", trace.Final, trace.EvalErr, tc.wantDec, tc.wantSource)
			}
		})
	}
}

func TestTraceGateEvaluationProviderErrorsFailSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[{"message":{"content":null,"refusal":"no"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()

	call := &harness.NormalizedToolCall{ToolName: "Bash", Command: "make deploy", Cwd: t.TempDir()}
	for name, mutate := range map[string]func(*config.Config){
		"unknown provider": func(c *config.Config) { c.Provider, c.Model = "gemini", "m" },
		"missing model":    func(c *config.Config) { c.Provider = "anthropic" },
		"missing key": func(c *config.Config) {
			c.Provider, c.APIKey, c.BaseURL, c.Model = "anthropic", "", "https://anthropic.invalid/v1", "m"
		},
		"model refusal": func(c *config.Config) { c.Provider, c.BaseURL, c.Model = "openai", server.URL, "m" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.APIKey = "test-key"
			mutate(cfg)
			trace := traceGateEvaluation(call, cfg, false)
			if trace.EvalErr == nil || trace.Final == nil || trace.Final.Decision != harness.DecisionAsk || trace.Final.Source != "policy_failsafe" {
				t.Fatalf("final=%+v err=%v; want ask from policy_failsafe", trace.Final, trace.EvalErr)
			}
		})
	}
}
