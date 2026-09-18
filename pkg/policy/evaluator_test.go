package policy

import (
	"errors"
	"testing"

	"github.com/typesafe-ai/jev-guard/pkg/evaluator"
	"github.com/typesafe-ai/jev-guard/pkg/harness"
)

func TestPolicy_Resolve_Allow(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  0.6,
		ViolationCategory:     "none",
		DestructiveConfidence: 0.9,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_ModerateAsk(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  1.9,
		ViolationCategory:     "none",
		DestructiveConfidence: 0.85,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for moderate score, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_CatastrophicDeny(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  2.9,
		ViolationCategory:     "catastrophic_deletion",
		DestructiveConfidence: 0.99,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionDeny {
		t.Errorf("expected DENY for catastrophic score, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_BoundaryViolation(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.95,
		DestructivePotential:  0.5,
		ViolationCategory:     "none",
		DestructiveConfidence: 0.9,
	}

	res := policy.Resolve(j, false, nil)
	if res.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK when boundary not contained, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_ApiErrorFailsafe(t *testing.T) {
	policy := NewDefaultPolicy()

	res := policy.Resolve(nil, true, errors.New("timeout"))
	if res.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK on API timeout failsafe, got %v", res.Decision)
	}
}
