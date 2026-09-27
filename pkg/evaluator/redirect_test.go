package evaluator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestClient_EvaluateDoesNotFollowRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	var sourceRequests atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"answers":{}}`))
	}))
	defer redirectTarget.Close()

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceRequests.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("request did not carry its configured API key: got %q", got)
		}
		w.Header().Set("Location", redirectTarget.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirectSource.Close()

	client := NewClient("secret-token", redirectSource.URL, "jev-latest", time.Second)
	_, err := client.Evaluate(context.Background(), &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "read private workspace state",
	})
	if err == nil {
		t.Fatal("expected the redirect response to fail evaluation")
	}
	if !errors.Is(err, ErrAPIFailure) || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("expected the original 307 response to be reported, got %v", err)
	}
	if sourceRequests.Load() != 1 {
		t.Fatalf("expected one request to the configured endpoint, got %d", sourceRequests.Load())
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("HTTP client followed a redirect and sent the tool call to another origin (%d requests)", redirectedRequests.Load())
	}
}
