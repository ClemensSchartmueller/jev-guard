package evaluator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

const validJudgmentJSON = `{"is_workspace_contained":0.97,"destructive_level":1,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.95}`

var validJudgment = JevJudgments{
	IsWorkspaceContained:  0.97,
	DestructivePotential:  1,
	DestructiveConfidence: 0.9,
	ViolationCategory:     "none",
	ViolationConfidence:   0.95,
}

func newTestEvaluator(t *testing.T, provider, apiKey, baseURL string) Evaluator {
	t.Helper()
	ev, err := New(Options{Provider: provider, APIKey: apiKey, APIKeyEnv: "TEST_KEY_ENV", BaseURL: baseURL, Model: "test-model", Timeout: time.Second})
	if err != nil {
		t.Fatalf("New(%s): %v", provider, err)
	}
	return ev
}

func chatCompletion(content string) string {
	encoded, _ := json.Marshal(content)
	return fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":%s},"finish_reason":"stop"}]}`, encoded)
}

func anthropicMessage(text string) string {
	encoded, _ := json.Marshal(text)
	return fmt.Sprintf(`{"type":"message","role":"assistant","content":[{"type":"text","text":%s}],"stop_reason":"end_turn"}`, encoded)
}

func decodeBody(t *testing.T, r *http.Request) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return body
}

func requiredFields(t *testing.T, schema interface{}) []interface{} {
	t.Helper()
	object, ok := schema.(map[string]interface{})
	if !ok {
		t.Fatalf("schema is not an object: %#v", schema)
	}
	if object["additionalProperties"] != false {
		t.Errorf("schema additionalProperties = %#v, want false", object["additionalProperties"])
	}
	required, _ := object["required"].([]interface{})
	return required
}

func TestNew_SelectsProvider(t *testing.T) {
	for _, tc := range []struct {
		provider string
		want     interface{}
	}{
		{"", &Client{}},
		{"typesafe", &Client{}},
		{"OpenAI", &OpenAIClient{}},
		{"anthropic", &AnthropicClient{}},
	} {
		ev, err := New(Options{Provider: tc.provider, Model: "m"})
		if err != nil {
			t.Fatalf("New(%q): %v", tc.provider, err)
		}
		if reflect.TypeOf(ev) != reflect.TypeOf(tc.want) {
			t.Errorf("New(%q) = %T, want %T", tc.provider, ev, tc.want)
		}
	}
}

func TestNew_RejectsUnknownProviderAndMissingModel(t *testing.T) {
	if _, err := New(Options{Provider: "gemini", Model: "m"}); !errors.Is(err, ErrUnsupportedProvider) {
		t.Errorf("unknown provider error = %v, want ErrUnsupportedProvider", err)
	}
	for _, provider := range []string{"openai", "anthropic"} {
		if _, err := New(Options{Provider: provider}); !errors.Is(err, ErrMissingModel) {
			t.Errorf("%s without model error = %v, want ErrMissingModel", provider, err)
		}
	}
}

func TestNewFromConfig_DefaultsToTypeSafe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.APIKey = "k"
	ev, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := ev.(*Client)
	if !ok {
		t.Fatalf("NewFromConfig = %T, want *Client", ev)
	}
	if client.BaseURL != DefaultBaseURL || client.Model != DefaultModel || client.APIKey != "k" {
		t.Errorf("client = %+v, want TypeSafe defaults", client)
	}
}

func TestOpenAIClient_RequestShapeAndJudgments(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("request = %s %s, want POST /v1/chat/completions", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		body := decodeBody(t, r)
		if body["model"] != "test-model" {
			t.Errorf("model = %#v", body["model"])
		}
		messages, _ := body["messages"].([]interface{})
		if len(messages) != 2 || messages[0].(map[string]interface{})["role"] != "system" || messages[1].(map[string]interface{})["role"] != "user" {
			t.Errorf("messages = %#v, want system and user", messages)
		}
		format, _ := body["response_format"].(map[string]interface{})
		if format["type"] != "json_schema" {
			t.Errorf("response_format.type = %#v", format["type"])
		}
		spec, _ := format["json_schema"].(map[string]interface{})
		if spec["name"] != judgmentSchemaName || spec["strict"] != true {
			t.Errorf("json_schema = %#v", spec)
		}
		if got := requiredFields(t, spec["schema"]); len(got) != 5 {
			t.Errorf("required = %#v, want the five intent-free fields", got)
		}
		fmt.Fprint(w, chatCompletion(validJudgmentJSON))
	}))
	defer server.Close()

	// A trailing slash on the API root must not produce a double slash.
	ev := newTestEvaluator(t, "openai", "sk-test", server.URL+"/v1/")
	got, err := ev.Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Write", TargetPath: "a.go"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if *got != validJudgment {
		t.Errorf("judgments = %+v, want %+v", *got, validJudgment)
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want 1", requests.Load())
	}
}

func TestOpenAIClient_IntentAlignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		spec := body["response_format"].(map[string]interface{})["json_schema"].(map[string]interface{})
		if got := requiredFields(t, spec["schema"]); len(got) != 7 {
			t.Errorf("required = %#v, want intent fields included", got)
		}
		fmt.Fprint(w, chatCompletion(`{"is_workspace_contained":1,"destructive_level":2,"destructive_confidence":0.8,"violation_category":"none","violation_confidence":0.9,"intent_alignment":"explicitly_requested","intent_confidence":0.85}`))
	}))
	defer server.Close()

	got, err := newTestEvaluator(t, "openai", "sk-test", server.URL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Bash", Command: "npm install", UserIntent: "install deps"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := JevJudgments{IsWorkspaceContained: 1, DestructivePotential: 2, DestructiveConfidence: 0.8, ViolationCategory: "none", ViolationConfidence: 0.9, IntentAlignment: "explicitly_requested", IntentConfidence: 0.85}
	if *got != want {
		t.Errorf("judgments = %+v, want %+v", *got, want)
	}
}

func TestOpenAIClient_IgnoresIntentClaimWithoutUserIntent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, chatCompletion(`{"is_workspace_contained":1,"destructive_level":3,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9,"intent_alignment":"explicitly_requested","intent_confidence":1}`))
	}))
	defer server.Close()

	got, err := newTestEvaluator(t, "openai", "sk-test", server.URL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Bash", Command: "rm -rf /"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.IntentAlignment != "" || got.IntentConfidence != 0 {
		t.Errorf("intent = %q/%v, want ignored", got.IntentAlignment, got.IntentConfidence)
	}
}

func TestOpenAIClient_LoopbackEndpointNeedsNoKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want none", got)
		}
		fmt.Fprint(w, chatCompletion(validJudgmentJSON))
	}))
	defer server.Close()

	got, err := newTestEvaluator(t, "openai", "", server.URL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if *got != validJudgment {
		t.Errorf("judgments = %+v", *got)
	}
}

func TestLLMClients_MissingKeyFailsBeforeRequest(t *testing.T) {
	for _, tc := range []struct{ provider, baseURL string }{
		{"openai", "https://openai.invalid/v1"},
		{"anthropic", "https://anthropic.invalid/v1"},
	} {
		_, err := newTestEvaluator(t, tc.provider, "", tc.baseURL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"})
		if !errors.Is(err, ErrMissingProviderAPIKey) {
			t.Errorf("%s error = %v, want ErrMissingProviderAPIKey", tc.provider, err)
		}
	}
}

func TestLLMClients_RejectUnsafeEndpoint(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic"} {
		_, err := newTestEvaluator(t, provider, "k", "http://example.invalid/v1").Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"})
		if !errors.Is(err, ErrUnsafeEndpoint) {
			t.Errorf("%s error = %v, want ErrUnsafeEndpoint", provider, err)
		}
	}
}

func TestOpenAIClient_FailureResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"http error", http.StatusTooManyRequests, `{"error":"rate limited"}`, ErrAPIFailure},
		{"refusal", 200, `{"choices":[{"message":{"content":null,"refusal":"I can't help"},"finish_reason":"stop"}]}`, ErrModelRefused},
		{"content filter", 200, `{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}]}`, ErrModelRefused},
		{"truncated", 200, `{"choices":[{"message":{"content":"{\"is_work"},"finish_reason":"length"}]}`, ErrInvalidJudgment},
		{"no choices", 200, `{"choices":[]}`, ErrInvalidJudgment},
		{"null content", 200, `{"choices":[{"message":{"content":null},"finish_reason":"stop"}]}`, ErrInvalidJudgment},
		{"not json", 200, `<html>`, ErrInvalidJudgment},
		{"prose content", 200, chatCompletion("Looks safe to me."), ErrInvalidJudgment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			got, err := newTestEvaluator(t, "openai", "sk-test", server.URL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"})
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Evaluate = %+v, %v; want nil, %v", got, err, tc.want)
			}
		})
	}
}

func TestParseLLMJudgment_RejectsInvalidOutput(t *testing.T) {
	for name, text := range map[string]string{
		"missing containment":     `{"destructive_level":1,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9}`,
		"missing level":           `{"is_workspace_contained":1,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9}`,
		"fractional level":        `{"is_workspace_contained":1,"destructive_level":1.5,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9}`,
		"level above scale":       `{"is_workspace_contained":1,"destructive_level":4,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9}`,
		"probability above one":   `{"is_workspace_contained":1.2,"destructive_level":1,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9}`,
		"negative confidence":     `{"is_workspace_contained":1,"destructive_level":1,"destructive_confidence":-0.1,"violation_category":"none","violation_confidence":0.9}`,
		"unknown category":        `{"is_workspace_contained":1,"destructive_level":1,"destructive_confidence":0.9,"violation_category":"harmless","violation_confidence":0.9}`,
		"missing category":        `{"is_workspace_contained":1,"destructive_level":1,"destructive_confidence":0.9,"violation_confidence":0.9}`,
		"markdown fenced":         "```json\n" + validJudgmentJSON + "\n```",
		"json array":              `[]`,
		"missing intent with ask": `{"is_workspace_contained":1,"destructive_level":1,"destructive_confidence":0.9,"violation_category":"none","violation_confidence":0.9}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseLLMJudgment(text, name == "missing intent with ask")
			if got != nil || !errors.Is(err, ErrInvalidJudgment) {
				t.Fatalf("parseLLMJudgment = %+v, %v; want ErrInvalidJudgment", got, err)
			}
		})
	}
}

func TestAnthropicClient_RequestShapeAndJudgments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
			t.Errorf("request = %s %s, want POST /v1/messages", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "ak-test" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want none", got)
		}
		body := decodeBody(t, r)
		if body["model"] != "test-model" || body["max_tokens"] != float64(anthropicMaxTokens) {
			t.Errorf("model/max_tokens = %#v/%#v", body["model"], body["max_tokens"])
		}
		if system, _ := body["system"].(string); system == "" {
			t.Error("system prompt missing")
		}
		messages, _ := body["messages"].([]interface{})
		if len(messages) != 1 || messages[0].(map[string]interface{})["role"] != "user" {
			t.Errorf("messages = %#v, want one user message", messages)
		}
		format := body["output_config"].(map[string]interface{})["format"].(map[string]interface{})
		if format["type"] != "json_schema" {
			t.Errorf("output_config.format.type = %#v", format["type"])
		}
		if got := requiredFields(t, format["schema"]); len(got) != 7 {
			t.Errorf("required = %#v, want intent fields included", got)
		}
		// Enum values may differ in capitalization; they are normalized.
		fmt.Fprint(w, anthropicMessage(`{"is_workspace_contained":0.5,"destructive_level":0,"destructive_confidence":0.99,"violation_category":"Workspace_Escape","violation_confidence":0.7,"intent_alignment":"Incidental_or_unclear","intent_confidence":0.6}`))
	}))
	defer server.Close()

	got, err := newTestEvaluator(t, "anthropic", "ak-test", server.URL+"/v1").Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read", TargetPath: "/etc/hosts", UserIntent: "fix the build"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := JevJudgments{IsWorkspaceContained: 0.5, DestructivePotential: 0, DestructiveConfidence: 0.99, ViolationCategory: "workspace_escape", ViolationConfidence: 0.7, IntentAlignment: "incidental_or_unclear", IntentConfidence: 0.6}
	if *got != want {
		t.Errorf("judgments = %+v, want %+v", *got, want)
	}
}

func TestAnthropicClient_FailureResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"http error", http.StatusUnauthorized, `{"type":"error"}`, ErrAPIFailure},
		{"refusal", 200, `{"content":[{"type":"text","text":"no"}],"stop_reason":"refusal"}`, ErrModelRefused},
		{"max tokens", 200, `{"content":[{"type":"text","text":"{\"is_"}],"stop_reason":"max_tokens"}`, ErrInvalidJudgment},
		{"no text block", 200, `{"content":[],"stop_reason":"end_turn"}`, ErrInvalidJudgment},
		{"invalid judgment", 200, anthropicMessage(`{"is_workspace_contained":1}`), ErrInvalidJudgment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			got, err := newTestEvaluator(t, "anthropic", "ak-test", server.URL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"})
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Evaluate = %+v, %v; want nil, %v", got, err, tc.want)
			}
		})
	}
}

func TestLLMClients_DoNotFollowRedirects(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic"} {
		t.Run(provider, func(t *testing.T) {
			var redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
			}))
			defer target.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
			}))
			defer source.Close()

			_, err := newTestEvaluator(t, provider, "secret", source.URL).Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"})
			if !errors.Is(err, ErrAPIFailure) {
				t.Fatalf("error = %v, want ErrAPIFailure", err)
			}
			if redirected.Load() != 0 {
				t.Fatalf("client followed a redirect (%d requests)", redirected.Load())
			}
		})
	}
}

func TestLLMClients_TimeoutFailsEvaluation(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	ev, err := New(Options{Provider: "openai", APIKey: "k", BaseURL: server.URL, Model: "m", Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ev.Evaluate(context.Background(), &harness.NormalizedToolCall{ToolName: "Read"}); got != nil || err == nil {
		t.Fatalf("Evaluate = %+v, %v; want timeout error", got, err)
	}
}
