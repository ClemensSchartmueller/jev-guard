package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"jev-guard/pkg/evaluator"
	"jev-guard/pkg/harness"
	"jev-guard/pkg/policy"
)

type responseTransport string

func (body responseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
}

func safeAnswers() map[string]interface{} {
	return map[string]interface{}{
		"is_workspace_contained": map[string]interface{}{"type": "noul", "noul": 1.0},
		"destructive_potential":  map[string]interface{}{"type": "score", "score": 0.0, "confidence": 0.9},
		"violation_category":     map[string]interface{}{"type": "choice", "choice": "none", "confidence": 0.9},
		"intent_alignment":       map[string]interface{}{"type": "choice", "choice": "explicitly_requested", "confidence": 0.9},
	}
}

func TestJudgeResponseFailsafe(t *testing.T) {
	check := func(t *testing.T, body, intent string, want harness.Decision) {
		t.Helper()
		client := evaluator.NewClient("test-key", "", "", 0)
		client.HTTPClient.Transport = responseTransport(body)
		j, err := client.Evaluate(context.Background(), &harness.NormalizedToolCall{
			ToolName: "Write", TargetPath: "/workspace/file.go", Cwd: "/workspace",
			WorkspaceRoots: []string{"/workspace"}, UserIntent: intent,
		})
		if want == harness.DecisionAsk && !errors.Is(err, evaluator.ErrAPIFailure) {
			t.Fatalf("expected ErrAPIFailure, got judgments=%+v err=%v", j, err)
		}
		if want == harness.DecisionAllow && err != nil {
			t.Fatal(err)
		}
		if intent == "" && j != nil && (j.IntentAlignment != "" || j.IntentConfidence != 0) {
			t.Fatalf("unsolicited intent was used: %+v", j)
		}
		result := policy.NewDefaultPolicy().ResolveWithEvidence(j, policy.BoundaryEvidence{
			Contained: true, PathVerified: true,
		}, err)
		if result.Decision != want || (want == harness.DecisionAsk && result.Source != "policy_failsafe") {
			t.Fatalf("unexpected result: %+v", result)
		}
	}
	for _, body := range []string{"{}", `{"answers":{}}`, "null", "not JSON", `{"answers":null}`} {
		t.Run(body, func(t *testing.T) { check(t, body, "write the file", harness.DecisionAsk) })
	}
	run := func(name string, mutate func(map[string]interface{})) {
		t.Run(name, func(t *testing.T) {
			answers := safeAnswers()
			mutate(answers)
			body, err := json.Marshal(map[string]interface{}{"answers": answers})
			if err != nil {
				t.Fatal(err)
			}
			check(t, string(body), "write the file", harness.DecisionAsk)
		})
	}
	for name := range safeAnswers() {
		run(name+"/missing", func(a map[string]interface{}) { delete(a, name) })
		run(name+"/null", func(a map[string]interface{}) { a[name] = nil })
		run(name+"/wrong envelope", func(a map[string]interface{}) { a[name] = "wrong" })
		run(name+"/wrong tag", func(a map[string]interface{}) { a[name].(map[string]interface{})["type"] = "boolean" })
		fields := map[string]string{"is_workspace_contained": "noul", "destructive_potential": "score", "violation_category": "choice", "intent_alignment": "choice"}
		field := fields[name]
		for _, value := range []interface{}{nil, true, "wrong", []int{1}} {
			run(name+"/invalid value/"+stringify(value), func(a map[string]interface{}) { a[name].(map[string]interface{})[field] = value })
		}
		run(name+"/missing value", func(a map[string]interface{}) { delete(a[name].(map[string]interface{}), field) })
		if field != "choice" {
			max := 1.0
			if field == "score" {
				max = 3
			}
			for _, value := range []float64{-0.01, max + 0.01} {
				run(name+"/range/"+stringify(value), func(a map[string]interface{}) { a[name].(map[string]interface{})[field] = value })
			}
		}
		if field == "choice" {
			run(name+"/unknown choice", func(a map[string]interface{}) { a[name].(map[string]interface{})[field] = "unknown" })
		}
		if field != "noul" {
			run(name+"/missing confidence", func(a map[string]interface{}) { delete(a[name].(map[string]interface{}), "confidence") })
			for _, value := range []interface{}{nil, -0.01, 1.01, "wrong"} {
				run(name+"/confidence/"+stringify(value), func(a map[string]interface{}) { a[name].(map[string]interface{})["confidence"] = value })
			}
		}
	}
	safeBody, _ := json.Marshal(map[string]interface{}{"answers": safeAnswers()})
	for name, body := range map[string]string{
		"trailing garbage": string(safeBody) + "xyz",
		"second object":    string(safeBody) + "{}",
		// Valid apart from its size, so only the body cap turns it into ASK.
		"oversized body": `{"pad":"` + strings.Repeat("x", 1<<20) + `","answers":` + string(mustJSON(safeAnswers())) + `}`,
	} {
		t.Run(name, func(t *testing.T) { check(t, body, "write the file", harness.DecisionAsk) })
	}
	t.Run("ignore fields of other answer types", func(t *testing.T) {
		a := safeAnswers()
		a["is_workspace_contained"].(map[string]interface{})["score"] = 0.0
		a["violation_category"].(map[string]interface{})["noul"] = 0.0
		body, _ := json.Marshal(map[string]interface{}{"answers": a})
		check(t, string(body), "write the file", harness.DecisionAllow)
	})
	t.Run("safe without intent", func(t *testing.T) {
		a := safeAnswers()
		delete(a, "intent_alignment")
		body, _ := json.Marshal(map[string]interface{}{"answers": a})
		check(t, string(body), "", harness.DecisionAllow)
	})
	t.Run("ignore unsolicited malformed intent", func(t *testing.T) {
		a := safeAnswers()
		a["intent_alignment"] = "invalid"
		body, _ := json.Marshal(map[string]interface{}{"answers": a})
		check(t, string(body), "", harness.DecisionAllow)
	})
	t.Run("safe with intent", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{"answers": safeAnswers()})
		check(t, string(body), "write the file", harness.DecisionAllow)
	})
}

func mustJSON(value interface{}) []byte {
	b, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return b
}

func stringify(value interface{}) string {
	b, _ := json.Marshal(value)
	return string(b)
}

func TestUnknownViolationCategoryAsks(t *testing.T) {
	result := policy.NewDefaultPolicy().ResolveWithEvidence(&evaluator.JevJudgments{
		IsWorkspaceContained: 1, ViolationCategory: "unknown",
	}, policy.BoundaryEvidence{Contained: true, PathVerified: true}, nil)
	if result.Decision != harness.DecisionAsk || result.Source != "policy_jev_violation" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
