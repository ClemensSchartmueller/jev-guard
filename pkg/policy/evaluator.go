package policy

import (
	"fmt"

	"jev-guard/pkg/evaluator"
	"jev-guard/pkg/harness"
)

// Default policy thresholds. They are hand-set, not yet calibrated against a
// labelled corpus; change them only with evidence (see docs/policy-benchmark.md).
const (
	// DefaultMaxAllowScore is the highest destructive_potential score allowed
	// without confirmation or explicit intent.
	DefaultMaxAllowScore = 1.2
	// DefaultCatastrophicScore is the destructive_potential score above which an
	// operation is catastrophic: denied, or force_ask when explicitly requested.
	DefaultCatastrophicScore = 2.5
	// DefaultMinContainedThreshold is the lowest model containment probability
	// accepted when the local resolver did not verify the path.
	DefaultMinContainedThreshold = 0.85
	// DefaultMinIntentConfidence is the lowest intent_alignment confidence that
	// counts as an explicit user request.
	DefaultMinIntentConfidence = 0.70
)

// Policy evaluates combined local boundary facts and semantic judgments.
type Policy struct {
	MaxAllowScore         float64
	CatastrophicScore     float64 // <= 0 means DefaultCatastrophicScore
	MinContainedThreshold float64
	MinIntentConfidence   float64 // <= 0 means DefaultMinIntentConfidence
}

// NewDefaultPolicy creates a standard policy with the default thresholds.
func NewDefaultPolicy() *Policy {
	return &Policy{
		MaxAllowScore:         DefaultMaxAllowScore,
		CatastrophicScore:     DefaultCatastrophicScore,
		MinContainedThreshold: DefaultMinContainedThreshold,
		MinIntentConfidence:   DefaultMinIntentConfidence,
	}
}

// BoundaryEvidence carries the deterministic local boundary facts for a tool call.
type BoundaryEvidence struct {
	// Contained is the local resolver's containment result.
	Contained bool
	// PathVerified is true only when the local resolver positively proved a
	// concrete filesystem target path (non-empty, not a URL, not a shell command)
	// is inside the workspace. Contained alone can be true vacuously.
	PathVerified bool
}

// Resolve translates Jev judgments, boundary containment, and errors into a final Decision.
// It treats containment as unverified; use ResolveWithEvidence for verified file-path proofs.
func (p *Policy) Resolve(j *evaluator.JevJudgments, boundaryContained bool, evalErr error) *harness.EvaluationResult {
	return p.ResolveWithEvidence(j, BoundaryEvidence{Contained: boundaryContained}, evalErr)
}

// ResolveWithEvidence is like Resolve but accepts richer local boundary evidence.
func (p *Policy) ResolveWithEvidence(j *evaluator.JevJudgments, ev BoundaryEvidence, evalErr error) *harness.EvaluationResult {
	boundaryContained := ev.Contained
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

	return p.evaluateJudgments(j, ev.PathVerified)
}

func (p *Policy) evaluateJudgments(j *evaluator.JevJudgments, pathVerified bool) *harness.EvaluationResult {
	minConfidence := p.MinIntentConfidence
	if minConfidence <= 0 {
		minConfidence = DefaultMinIntentConfidence
	}
	catastrophicScore := p.CatastrophicScore
	if catastrophicScore <= 0 {
		catastrophicScore = DefaultCatastrophicScore
	}
	isExplicitlyRequested := j.IntentAlignment == "explicitly_requested" && j.IntentConfidence >= minConfidence

	// Strict Catastrophic Ceiling: Operations with catastrophic blast radius (score > CatastrophicScore)
	// strictly cap at force_ask even if explicitly commanded by the user, and are blocked (deny) otherwise.
	// This invariant takes precedence over all violation categories, including credential allowances.
	if j.DestructivePotential > catastrophicScore {
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

	if violationResult := p.checkViolationCategory(j, isExplicitlyRequested); violationResult != nil {
		return violationResult
	}

	// For pure file-path operations the deterministic local resolver is authoritative:
	// the model's containment probability is a guess and must not override a proof.
	// Only this check is skipped; a model-reported workspace_escape category still asks above.
	if !pathVerified && j.IsWorkspaceContained < p.MinContainedThreshold {
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
