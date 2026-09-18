package evaluator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/typesafe-ai/jev-guard/pkg/harness"
)

func TestClient_Evaluate_Success(t *testing.T) {
	mockResponse := `{
		"model": "jev-latest",
		"answers": {
			"is_workspace_contained": {
				"type": "noul",
				"noul": 0.98
			},
			"destructive_potential": {
				"type": "score",
				"score": 0.45,
				"confidence": 0.91
			},
			"violation_category": {
				"type": "choice",
				"choice": "none",
				"confidence": 0.96
			}
		},
		"usage": {
			"input_tokens": 120,
			"output_tokens": 30
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}

		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		if reqBody["model"] != "jev-latest" {
			http.Error(w, "wrong model", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	client := NewClient("test-key", server.URL, 1*time.Second)

	call := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: "pkg/foo/bar.go",
		Cwd:        "/app",
	}

	judgments, err := client.Evaluate(context.Background(), call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if judgments.IsWorkspaceContained != 0.98 {
		t.Errorf("expected IsWorkspaceContained 0.98, got %f", judgments.IsWorkspaceContained)
	}
	if judgments.DestructivePotential != 0.45 {
		t.Errorf("expected DestructivePotential 0.45, got %f", judgments.DestructivePotential)
	}
	if judgments.ViolationCategory != "none" {
		t.Errorf("expected ViolationCategory 'none', got %s", judgments.ViolationCategory)
	}
}

func TestClient_Evaluate_MissingKey(t *testing.T) {
	client := NewClient("", "", 1*time.Second)
	_, err := client.Evaluate(context.Background(), &harness.NormalizedToolCall{})
	if err != ErrMissingAPIKey {
		t.Errorf("expected ErrMissingAPIKey, got %v", err)
	}
}

func TestClient_Evaluate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient("test-key", server.URL, 1*time.Second)
	_, err := client.Evaluate(context.Background(), &harness.NormalizedToolCall{})
	if err == nil {
		t.Fatal("expected error from server, got nil")
	}
}
