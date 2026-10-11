package main

import (
	"errors"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/fastpath"
	"jev-guard/pkg/harness"
)

type countingBoundaryChecker struct {
	calls     int
	contained bool
	err       error
}

func (c *countingBoundaryChecker) IsPathContained(target, cwd string) (bool, error) {
	c.calls++
	return c.contained, c.err
}

func TestTraceAndFastpathShareBoundaryResolution(t *testing.T) {
	for _, contained := range []bool{true, false} {
		underlying := &countingBoundaryChecker{contained: contained}
		checker := &cachedBoundaryChecker{checker: underlying}
		call := &harness.NormalizedToolCall{ToolName: "view_file", TargetPath: "README.md", Cwd: t.TempDir()}
		if got := checkWorkspaceBoundary(call, checker); got != contained {
			t.Fatalf("contained = %t, want %t", got, contained)
		}
		result := fastpath.NewFilter(checker, config.DefaultConfig()).Evaluate(call)
		want := harness.DecisionAllow
		if !contained {
			want = harness.DecisionAsk
		}
		if result == nil || result.Decision != want || underlying.calls != 1 {
			t.Fatalf("result=%v boundary checks=%d; want %s and one check", result, underlying.calls, want)
		}
	}
}

func TestCachedBoundaryCheckerPreservesErrorsAndDistinctPaths(t *testing.T) {
	wantErr := errors.New("resolution failed")
	underlying := &countingBoundaryChecker{err: wantErr}
	checker := &cachedBoundaryChecker{checker: underlying}
	for _, query := range [][2]string{{"file:///tmp/x", "/tmp"}, {"file:///tmp/x", "/tmp"}, {"/tmp/x", "/tmp"}, {"/tmp/x", "/other"}} {
		contained, err := checker.IsPathContained(query[0], query[1])
		if contained || err != wantErr {
			t.Fatalf("resolution changed: contained=%t err=%v", contained, err)
		}
	}
	if underlying.calls != 3 {
		t.Fatalf("distinct paths/cwd should remain independent: checks=%d", underlying.calls)
	}
}

func TestResolveUserIntent(t *testing.T) {
	tests := []struct {
		name          string
		callTurnID    int
		sessionTurnID int
		prompt        string
		expected      string
	}{
		{
			name:          "both turn IDs zero",
			callTurnID:    0,
			sessionTurnID: 0,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "call turn ID zero, session non-zero",
			callTurnID:    0,
			sessionTurnID: 2,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "call turn ID non-zero, session zero",
			callTurnID:    2,
			sessionTurnID: 0,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "matching turn IDs",
			callTurnID:    3,
			sessionTurnID: 3,
			prompt:        "do something safe",
			expected:      "do something safe",
		},
		{
			name:          "mismatched turn IDs",
			callTurnID:    4,
			sessionTurnID: 3,
			prompt:        "stale previous turn prompt",
			expected:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveUserIntent(tc.callTurnID, tc.sessionTurnID, tc.prompt)
			if got != tc.expected {
				t.Errorf("resolveUserIntent(%d, %d, %q) = %q; want %q",
					tc.callTurnID, tc.sessionTurnID, tc.prompt, got, tc.expected)
			}
		})
	}
}

func TestApplyAuditMode(t *testing.T) {
	res := &harness.EvaluationResult{
		Decision: harness.DecisionDeny,
		Reason:   "unsafe action",
	}

	auditRes := applyAuditMode(res, "audit")
	if auditRes.Decision != harness.DecisionAllow {
		t.Errorf("expected DecisionAllow in audit mode, got %v", auditRes.Decision)
	}

	enforceRes := applyAuditMode(res, "enforce")
	if enforceRes.Decision != harness.DecisionDeny {
		t.Errorf("expected DecisionDeny in enforce mode, got %v", enforceRes.Decision)
	}
}
