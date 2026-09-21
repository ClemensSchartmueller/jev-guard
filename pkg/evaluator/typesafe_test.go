package evaluator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"jev-guard/pkg/harness"
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
		t.Errorf("expected error on 500 status, got nil")
	}
}

func TestClient_Evaluate_WithUserIntent(t *testing.T) {
	mockResponse := `{
		"model": "jev-latest",
		"answers": {
			"is_workspace_contained": { "type": "noul", "noul": 0.99 },
			"destructive_potential": { "type": "score", "score": 1.5, "confidence": 0.95 },
			"violation_category": { "type": "choice", "choice": "none", "confidence": 0.99 },
			"intent_alignment": { "type": "choice", "choice": "explicitly_requested", "confidence": 0.98 }
		}
	}`

	var receivedUserIntent string
	var hasIntentQuestion bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)

		if state, ok := reqBody["state"].(map[string]interface{}); ok {
			if intent, ok := state["user_intent"].(string); ok {
				receivedUserIntent = intent
			}
		}

		if questions, ok := reqBody["questions"].(map[string]interface{}); ok {
			if _, ok := questions["intent_alignment"]; ok {
				hasIntentQuestion = true
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	client := NewClient("test-key", server.URL, 1*time.Second)

	call := &harness.NormalizedToolCall{
		ToolName:   "run_command",
		Command:    "rm -rf dist",
		UserIntent: "Please clean up the dist folder",
	}

	judgments, err := client.Evaluate(context.Background(), call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedUserIntent != "Please clean up the dist folder" {
		t.Errorf("expected user_intent to be sent in state, got %q", receivedUserIntent)
	}
	if !hasIntentQuestion {
		t.Errorf("expected intent_alignment question to be sent when user_intent is present")
	}
	if judgments.IntentAlignment != "explicitly_requested" {
		t.Errorf("expected IntentAlignment 'explicitly_requested', got %q", judgments.IntentAlignment)
	}
	if judgments.IntentConfidence != 0.98 {
		t.Errorf("expected IntentConfidence 0.98, got %f", judgments.IntentConfidence)
	}
}
