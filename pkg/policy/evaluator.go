package policy

import (
	"fmt"

	"jev-guard/pkg/evaluator"
	"jev-guard/pkg/harness"
)

// Policy evaluates combined local boundary facts and semantic judgments.
type Policy struct {
	MaxAllowScore         float64
	MinContainedThreshold float64
}

// NewDefaultPolicy creates a standard policy with calibrated thresholds.
func NewDefaultPolicy() *Policy {
	return &Policy{
		MaxAllowScore:         1.2,
		MinContainedThreshold: 0.85,
	}
}

// Resolve translates Jev judgments, boundary containment, and errors into a final Decision.
func (p *Policy) Resolve(j *evaluator.JevJudgments, boundaryContained bool, evalErr error) *harness.EvaluationResult {
	if evalErr != nil {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     fmt.Sprintf("Semantic evaluation unavailable (fail-safe interactive approval): %v", evalErr),
			Source:     "policy_failsafe",
			Confidence: 0.0,
		}
	}

	if !boundaryContained {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     "Target path escapes workspace boundaries",
			Source:     "policy_boundary",
			Confidence: 1.0,
		}
	}

	return p.evaluateJudgments(j)
}

func (p *Policy) evaluateJudgments(j *evaluator.JevJudgments) *harness.EvaluationResult {
	if violationResult := p.checkViolationCategory(j); violationResult != nil {
		return violationResult
	}

	if j.DestructivePotential > 2.5 {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     fmt.Sprintf("Catastrophic blast radius (destructive score: %.2f)", j.DestructivePotential),
			Source:     "policy_jev_destructive",
			Confidence: j.DestructiveConfidence,
		}
	}

	if j.IsWorkspaceContained < p.MinContainedThreshold {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     fmt.Sprintf("Potential workspace escape (containment probability: %.2f)", j.IsWorkspaceContained),
			Source:     "policy_jev_containment",
			Confidence: 1.0 - j.IsWorkspaceContained,
		}
	}

	if j.DestructivePotential > p.MaxAllowScore {
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     fmt.Sprintf("Moderate blast radius requiring confirmation (score: %.2f)", j.DestructivePotential),
			Source:     "policy_jev_moderate",
			Confidence: j.DestructiveConfidence,
		}
	}

	return &harness.EvaluationResult{
		Decision:   harness.DecisionAllow,
		Reason:     "Operation verified safe and contained by TypeSafe AI",
		Source:     "policy_jev_allow",
		Confidence: j.DestructiveConfidence,
	}
}

func (p *Policy) checkViolationCategory(j *evaluator.JevJudgments) *harness.EvaluationResult {
	switch j.ViolationCategory {
	case "catastrophic_deletion", "persistence_or_privilege":
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     fmt.Sprintf("Blocked %s attack vector", j.ViolationCategory),
			Source:     "policy_jev_violation",
			Confidence: j.ViolationConfidence,
		}
	case "credential_leak", "workspace_escape":
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     fmt.Sprintf("Requires confirmation for potential %s", j.ViolationCategory),
			Source:     "policy_jev_violation",
			Confidence: j.ViolationConfidence,
		}
	default:
		return nil
	}
}
