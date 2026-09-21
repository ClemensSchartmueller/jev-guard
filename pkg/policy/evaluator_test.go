package policy

import (
	"errors"
	"testing"

	"jev-guard/pkg/evaluator"
	"jev-guard/pkg/harness"
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

func TestPolicy_Resolve_ExplicitIntent_ModerateAllow(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  1.9,
		ViolationCategory:     "none",
		DestructiveConfidence: 0.9,
		IntentAlignment:       "explicitly_requested",
		IntentConfidence:      0.95,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAllow {
		t.Fatalf("expected ALLOW for moderate operation explicitly requested by user, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_ExplicitIntent_CatastrophicCappedAtForceAsk(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  2.9,
		ViolationCategory:     "catastrophic_deletion",
		DestructiveConfidence: 0.99,
		IntentAlignment:       "explicitly_requested",
		IntentConfidence:      0.99,
	}

	res := policy.Resolve(j, true, nil)
	// Must cap at ForceAsk, NEVER auto-allow
	if res.Decision != harness.DecisionForceAsk {
		t.Fatalf("expected force_ask cap for catastrophic operation explicitly requested, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_ExplicitIntent_CredentialAccess(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  0.8,
		ViolationCategory:     "credential_leak",
		ViolationConfidence:   0.9,
		IntentAlignment:       "explicitly_requested",
		IntentConfidence:      0.95,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAllow {
		t.Fatalf("expected ALLOW for credential access explicitly requested by user, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_Unprompted_CredentialAccessRequiresConfirmation(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  0.8,
		ViolationCategory:     "credential_leak",
		ViolationConfidence:   0.9,
		IntentAlignment:       "unprompted_or_contrary",
		IntentConfidence:      0.95,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for unprompted credential access, got %v", res.Decision)
	}
}
