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
	isExplicitlyRequested := j.IntentAlignment == "explicitly_requested"

	if violationResult := p.checkViolationCategory(j, isExplicitlyRequested); violationResult != nil {
		return violationResult
	}

	if j.DestructivePotential > 2.5 {
		if isExplicitlyRequested {
			return &harness.EvaluationResult{
				Decision:   harness.DecisionForceAsk,
				Reason:     fmt.Sprintf("Catastrophic operation explicitly requested by user (destructive score: %.2f); confirmation required", j.DestructivePotential),
				Source:     "policy_jev_intent_catastrophic",
				Confidence: j.DestructiveConfidence,
			}
		}
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
		if isExplicitlyRequested {
			return &harness.EvaluationResult{
				Decision:   harness.DecisionAllow,
				Reason:     fmt.Sprintf("Moderate operation authorized by explicit user intent (destructive score: %.2f)", j.DestructivePotential),
				Source:     "policy_jev_intent_allow",
				Confidence: j.DestructiveConfidence,
			}
		}
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

func (p *Policy) checkViolationCategory(j *evaluator.JevJudgments, isExplicitlyRequested bool) *harness.EvaluationResult {
	switch j.ViolationCategory {
	case "catastrophic_deletion":
		if isExplicitlyRequested {
			return &harness.EvaluationResult{
				Decision:   harness.DecisionForceAsk,
				Reason:     "Catastrophic deletion explicitly requested by user; confirmation required",
				Source:     "policy_jev_intent_catastrophic",
				Confidence: j.ViolationConfidence,
			}
		}
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     "Blocked catastrophic_deletion attack vector",
			Source:     "policy_jev_violation",
			Confidence: j.ViolationConfidence,
		}
	case "persistence_or_privilege":
		if isExplicitlyRequested {
			return &harness.EvaluationResult{
				Decision:   harness.DecisionForceAsk,
				Reason:     "Privilege or persistence modification explicitly requested; confirmation required",
				Source:     "policy_jev_intent_privilege",
				Confidence: j.ViolationConfidence,
			}
		}
		return &harness.EvaluationResult{
			Decision:   harness.DecisionDeny,
			Reason:     "Blocked persistence_or_privilege attack vector",
			Source:     "policy_jev_violation",
			Confidence: j.ViolationConfidence,
		}
	case "credential_leak":
		if isExplicitlyRequested {
			return &harness.EvaluationResult{
				Decision:   harness.DecisionAllow,
				Reason:     "Credential or environment file access authorized by explicit user intent",
				Source:     "policy_jev_intent_allow",
				Confidence: j.ViolationConfidence,
			}
		}
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     "Requires confirmation for potential credential_leak",
			Source:     "policy_jev_violation",
			Confidence: j.ViolationConfidence,
		}
	case "workspace_escape":
		return &harness.EvaluationResult{
			Decision:   harness.DecisionAsk,
			Reason:     "Requires confirmation for potential workspace_escape",
			Source:     "policy_jev_violation",
			Confidence: j.ViolationConfidence,
		}
	default:
		return nil
	}
}
