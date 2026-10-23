package policy

import (
	"errors"
	"fmt"
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
		IsWorkspaceContained: 0.98,
		DestructivePotential: 0.8,
		ViolationCategory:    "credential_leak",
		ViolationConfidence:  0.9,
		IntentAlignment:      "explicitly_requested",
		IntentConfidence:     0.95,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAllow {
		t.Fatalf("expected ALLOW for credential access explicitly requested by user, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_Unprompted_CredentialAccessRequiresConfirmation(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained: 0.98,
		DestructivePotential: 0.8,
		ViolationCategory:    "credential_leak",
		ViolationConfidence:  0.9,
		IntentAlignment:      "unprompted_or_contrary",
		IntentConfidence:     0.95,
	}

	res := policy.Resolve(j, true, nil)
	if res.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for unprompted credential access, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_ExplicitIntent_CatastrophicCredentialAccessCappedAtForceAsk(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  2.8,
		ViolationCategory:     "credential_leak",
		ViolationConfidence:   0.95,
		DestructiveConfidence: 0.99,
		IntentAlignment:       "explicitly_requested",
		IntentConfidence:      0.95,
	}

	res := policy.Resolve(j, true, nil)
	// Must cap at ForceAsk even if user explicitly requested and violation is credential_leak
	if res.Decision != harness.DecisionForceAsk {
		t.Fatalf("expected force_ask cap for catastrophic credential operation explicitly requested, got %v", res.Decision)
	}
}

func TestPolicy_Resolve_ExplicitIntent_LowConfidenceRequiresConfirmation(t *testing.T) {
	policy := NewDefaultPolicy()
	j := &evaluator.JevJudgments{
		IsWorkspaceContained:  0.98,
		DestructivePotential:  1.9,
		ViolationCategory:     "none",
		DestructiveConfidence: 0.9,
		IntentAlignment:       "explicitly_requested",
		IntentConfidence:      0.45, // Below default 0.70 threshold
	}

	res := policy.Resolve(j, true, nil)
	// Low confidence must not auto-allow; it must fall back to asking confirmation
	if res.Decision != harness.DecisionAsk {
		t.Fatalf("expected ASK for low confidence explicit intent, got %v", res.Decision)
	}
}

func TestPolicy_PathVerified(t *testing.T) {
	policy := NewDefaultPolicy()
	mk := func(contained, destructive float64, cat string) *evaluator.JevJudgments {
		return &evaluator.JevJudgments{
			IsWorkspaceContained:  contained,
			DestructivePotential:  destructive,
			ViolationCategory:     cat,
			DestructiveConfidence: 0.9,
			ViolationConfidence:   0.9,
		}
	}
	verified := BoundaryEvidence{Contained: true, PathVerified: true}
	unverified := BoundaryEvidence{Contained: true}

	tests := []struct {
		name string
		ev   BoundaryEvidence
		j    *evaluator.JevJudgments
		want harness.Decision
	}{
		{"verified low containment allows", verified, mk(0.43, 0.3, "none"), harness.DecisionAllow},
		{"unverified low containment asks", unverified, mk(0.43, 0.3, "none"), harness.DecisionAsk},
		{"verified catastrophic denies", verified, mk(0.43, 2.8, "none"), harness.DecisionDeny},
		{"verified moderate still asks", verified, mk(0.43, 1.9, "none"), harness.DecisionAsk},
		{"verified workspace_escape category asks", verified, mk(0.98, 0.3, "workspace_escape"), harness.DecisionAsk},
		{"verified credential_leak asks", verified, mk(0.43, 0.3, "credential_leak"), harness.DecisionAsk},
		{"verified catastrophic_deletion denies", verified, mk(0.43, 0.3, "catastrophic_deletion"), harness.DecisionDeny},
		{"not contained asks even if verified flag set", BoundaryEvidence{Contained: false, PathVerified: true}, mk(0.99, 0.1, "none"), harness.DecisionAsk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := policy.ResolveWithEvidence(tt.j, tt.ev, nil)
			if res.Decision != tt.want {
				t.Errorf("expected %v, got %v (%s)", tt.want, res.Decision, res.Reason)
			}
		})
	}

	res := policy.ResolveWithEvidence(nil, verified, errors.New("boom"))
	if res.Decision != harness.DecisionAsk {
		t.Errorf("eval error must still fail safe, got %v", res.Decision)
	}
}

// TestPolicy_IntentInvariants pins what explicit intent can and cannot unlock,
// at both sides of the confidence threshold. Intent arrives through the user's
// prompt, which may contain pasted third-party text, so these limits must not
// depend on the decision model getting intent right.
func TestPolicy_IntentInvariants(t *testing.T) {
	policy := NewDefaultPolicy()
	contained := BoundaryEvidence{Contained: true}
	mk := func(conf, containment, destructive float64, cat string) *evaluator.JevJudgments {
		return &evaluator.JevJudgments{
			IsWorkspaceContained:  containment,
			DestructivePotential:  destructive,
			ViolationCategory:     cat,
			DestructiveConfidence: 0.9,
			ViolationConfidence:   0.9,
			IntentAlignment:       "explicitly_requested",
			IntentConfidence:      conf,
		}
	}

	tests := []struct {
		name     string
		ev       BoundaryEvidence
		j        func(conf float64) *evaluator.JevJudgments
		atThresh harness.Decision // confidence 0.70
		below    harness.Decision // confidence 0.69
	}{
		{"moderate risk", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 1.9, "none") },
			harness.DecisionAllow, harness.DecisionAsk},
		{"credential_leak local", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 0.8, "credential_leak") },
			harness.DecisionAllow, harness.DecisionAsk},
		{"credential_leak egress", BoundaryEvidence{Contained: true, Egress: true}, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 0.8, "credential_leak") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"persistence_or_privilege", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 1.0, "persistence_or_privilege") },
			harness.DecisionForceAsk, harness.DecisionDeny},
		{"catastrophic_deletion category", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 1.0, "catastrophic_deletion") },
			harness.DecisionForceAsk, harness.DecisionDeny},
		{"catastrophic score ceiling", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 2.51, "none") },
			harness.DecisionForceAsk, harness.DecisionDeny},
		{"catastrophic ceiling beats credential_leak", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 3.0, "credential_leak") },
			harness.DecisionForceAsk, harness.DecisionDeny},
		{"workspace_escape category", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 0.3, "workspace_escape") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"workspace_escape category moderate", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.98, 1.9, "workspace_escape") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"low containment", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.84, 0.3, "none") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"low containment moderate", contained, func(c float64) *evaluator.JevJudgments { return mk(c, 0.40, 1.9, "none") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"not contained", BoundaryEvidence{Contained: false}, func(c float64) *evaluator.JevJudgments { return mk(c, 0.99, 0.1, "none") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"not contained moderate", BoundaryEvidence{Contained: false, PathVerified: true}, func(c float64) *evaluator.JevJudgments { return mk(c, 0.99, 1.9, "none") },
			harness.DecisionAsk, harness.DecisionAsk},
		{"not contained credential_leak", BoundaryEvidence{Contained: false}, func(c float64) *evaluator.JevJudgments { return mk(c, 0.99, 0.8, "credential_leak") },
			harness.DecisionAsk, harness.DecisionAsk},
	}
	for _, tt := range tests {
		for _, c := range []struct {
			conf float64
			want harness.Decision
		}{{0.70, tt.atThresh}, {0.69, tt.below}} {
			t.Run(fmt.Sprintf("%s/confidence_%.2f", tt.name, c.conf), func(t *testing.T) {
				res := policy.ResolveWithEvidence(tt.j(c.conf), tt.ev, nil)
				if res.Decision != c.want {
					t.Errorf("expected %v, got %v (%s: %s)", c.want, res.Decision, res.Source, res.Reason)
				}
			})
		}
	}
}

// TestPolicy_BoundaryEscapeNeverAllowedByIntent sweeps the judgment space: with
// the local resolver reporting an escape, no intent makes the call ALLOW.
func TestPolicy_BoundaryEscapeNeverAllowedByIntent(t *testing.T) {
	policy := NewDefaultPolicy()
	for _, cat := range []string{"none", "credential_leak", "workspace_escape", "persistence_or_privilege", "catastrophic_deletion"} {
		for _, score := range []float64{0, 0.8, 1.9, 2.9} {
			for _, verified := range []bool{false, true} {
				j := &evaluator.JevJudgments{
					IsWorkspaceContained: 0.99, DestructivePotential: score, ViolationCategory: cat,
					IntentAlignment: "explicitly_requested", IntentConfidence: 1.0,
				}
				res := policy.ResolveWithEvidence(j, BoundaryEvidence{Contained: false, PathVerified: verified}, nil)
				if res.Decision == harness.DecisionAllow {
					t.Errorf("cat=%s score=%.1f verified=%v: boundary escape allowed via intent (%s)", cat, score, verified, res.Source)
				}
			}
		}
	}
}

func TestPolicy_CredentialEgressCap(t *testing.T) {
	policy := NewDefaultPolicy()
	j := func(alignment string) *evaluator.JevJudgments {
		return &evaluator.JevJudgments{
			IsWorkspaceContained: 0.98, DestructivePotential: 0.8, ViolationCategory: "credential_leak",
			ViolationConfidence: 0.9, IntentAlignment: alignment, IntentConfidence: 0.95,
		}
	}
	egress := BoundaryEvidence{Contained: true, Egress: true}

	res := policy.ResolveWithEvidence(j("explicitly_requested"), egress, nil)
	if res.Decision != harness.DecisionAsk || res.Source != "policy_intent_egress_cap" {
		t.Errorf("explicit credential egress: got %v/%s, want ask/policy_intent_egress_cap", res.Decision, res.Source)
	}
	res = policy.ResolveWithEvidence(j("unprompted_or_contrary"), egress, nil)
	if res.Decision != harness.DecisionAsk || res.Source != "policy_jev_violation" {
		t.Errorf("unprompted credential egress: got %v/%s, want ask/policy_jev_violation", res.Decision, res.Source)
	}
	// Egress alone does not change non-credential outcomes.
	safe := &evaluator.JevJudgments{IsWorkspaceContained: 0.98, DestructivePotential: 0.3, ViolationCategory: "none"}
	if res := policy.ResolveWithEvidence(safe, egress, nil); res.Decision != harness.DecisionAllow {
		t.Errorf("safe egress call: got %v, want allow", res.Decision)
	}
}
