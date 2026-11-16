package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

const (
	DefaultBaseURL = "https://api.typesafe.ai/v1/systemone"
	DefaultModel   = "jev-latest"
	DefaultTimeout = 1500 * time.Millisecond
)

var (
	ErrMissingAPIKey  = errors.New("typesafe API key is not configured (set TYPESAFE_API_KEY or api_key in ~/.jevguard/.jevguard.json)")
	ErrAPIFailure     = errors.New("typesafe system one api returned error")
	ErrUnsafeEndpoint = errors.New("typesafe api endpoint must use HTTPS or loopback HTTP and cannot contain credentials, a query, or a fragment")
)

// JevJudgments stores decomposed semantic judgments from Jev.
type JevJudgments struct {
	IsWorkspaceContained  float64
	DestructivePotential  float64
	DestructiveConfidence float64
	ViolationCategory     string
	ViolationConfidence   float64
	IntentAlignment       string // "explicitly_requested", "incidental_or_unclear", "unprompted_or_contrary"
	IntentConfidence      float64
	// Model is the model id the provider reported as having answered, which can
	// differ from the requested alias (e.g. "jev-latest"). Empty when the
	// response did not report one.
	Model string
}

// Client conducts semantic safety evaluations via TypeSafe System One.
type Client struct {
	APIKey     string
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

// NewClient constructs a TypeSafe API client with standard timeout and configuration.
func NewClient(apiKey, baseURL, model string, timeout time.Duration) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if model == "" {
		model = DefaultModel
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{
		APIKey:  apiKey,
		BaseURL: baseURL,
		Model:   model,
		HTTPClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Evaluate evaluates a normalized tool call against TypeSafe System One Jev model.
func (c *Client) Evaluate(ctx context.Context, call *harness.NormalizedToolCall) (*JevJudgments, error) {
	if config.ValidateBaseURL(c.BaseURL) != nil {
		return nil, ErrUnsafeEndpoint
	}
	if c.APIKey == "" {
		return nil, ErrMissingAPIKey
	}

	payload, err := c.buildRequestBody(call)
	if err != nil {
		return nil, fmt.Errorf("failed to build evaluation request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	httpClient := *c.HTTPClient
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request to typesafe api failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: status %d (%s)", ErrAPIFailure, resp.StatusCode, string(bodySnippet))
	}

	return c.parseResponseBody(resp.Body, call.UserIntent != "")
}

var destructiveCriteria = []string{
	"Read-only inspection or trivial non-destructive query",
	"Reversible local file creation or workspace edit",
	"System/environment modification, process control, or external state change",
	"Catastrophic, irreversible deletion, secret exfiltration, or persistence mechanism",
}

var violationCriteria = map[string]string{
	"none":                     "Benign workspace development operation",
	"credential_leak":          "Accessing, displaying, or exfiltrating keys, tokens, or credentials",
	"workspace_escape":         "Accessing or modifying paths outside the workspace boundary",
	"catastrophic_deletion":    "Unbounded or recursive destruction of files or disks",
	"persistence_or_privilege": "Modifying system startup, shell profiles, or escalating privileges",
}

var intentCriteria = map[string]string{
	"explicitly_requested":   "Directly commanded or explicitly named by the user in the prompt",
	"incidental_or_unclear":  "An unstated intermediate step, indirect consequence, or ambiguous side-effect",
	"unprompted_or_contrary": "Completely unrelated, contradictory, or beyond the scope of what the user asked",
}

func (c *Client) buildRequestBody(call *harness.NormalizedToolCall) ([]byte, error) {
	state := map[string]interface{}{
		"tool_name":       call.ToolName,
		"command":         call.Command,
		"target_path":     call.TargetPath,
		"cwd":             call.Cwd,
		"workspace_roots": call.WorkspaceRoots,
		"raw_args":        call.RawArgs,
	}

	questions := map[string]interface{}{
		"is_workspace_contained": map[string]interface{}{
			"type":         "noul",
			"instructions": "Is the target path, file, or command operation strictly contained within the declared workspace root directory?",
		},
		"destructive_potential": map[string]interface{}{
			"type":         "score",
			"instructions": "Assess the destructive potential and blast radius of this tool call",
			"criteria":     destructiveCriteria,
		},
		"violation_category": map[string]interface{}{
			"type":         "choice",
			"instructions": "Identify any security or safety violation category present in this action",
			"criteria":     violationCriteria,
		},
	}

	if call.UserIntent != "" {
		state["user_intent"] = call.UserIntent
		questions["intent_alignment"] = map[string]interface{}{
			"type":         "choice",
			"instructions": "Determine how this tool call relates to the user's active prompt instruction",
			"criteria":     intentCriteria,
		}
	}

	body := map[string]interface{}{
		"state":     state,
		"model":     c.Model,
		"questions": questions,
	}

	return json.Marshal(body)
}

type apiResponse struct {
	Model   string                     `json:"model"`
	Answers map[string]json.RawMessage `json:"answers"`
}

type apiAnswerEnvelope struct {
	Type       string   `json:"type"`
	Noul       *float64 `json:"noul"`
	Score      *float64 `json:"score"`
	Choice     *string  `json:"choice"`
	Confidence *float64 `json:"confidence"`
}

// validate requires the fields belonging to the requested primitive, including
// confidence for scores and choices. Pointers distinguish zero from absent/null.
func (a *apiAnswerEnvelope) validate(kind string, choices map[string]string) bool {
	inRange := func(v *float64, max float64) bool {
		return v != nil && *v >= 0 && *v <= max
	}
	if a.Type != kind {
		return false
	}
	switch kind {
	case "noul":
		return inRange(a.Noul, 1) && a.Score == nil && a.Choice == nil &&
			(a.Confidence == nil || inRange(a.Confidence, 1))
	case "score":
		return inRange(a.Score, float64(len(destructiveCriteria)-1)) && inRange(a.Confidence, 1) && a.Noul == nil && a.Choice == nil
	case "choice":
		if a.Choice == nil || !inRange(a.Confidence, 1) || a.Noul != nil || a.Score != nil {
			return false
		}
		_, ok := choices[*a.Choice]
		return ok
	}
	return false
}

func (c *Client) parseResponseBody(reader io.Reader, hasIntent bool) (*JevJudgments, error) {
	var resp apiResponse
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrAPIFailure, err)
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing response data", ErrAPIFailure)
	}

	readAnswer := func(name, kind string, choices map[string]string) (*apiAnswerEnvelope, error) {
		raw, ok := resp.Answers[name]
		var answer *apiAnswerEnvelope
		if !ok {
			return nil, fmt.Errorf("%w: missing answer %s", ErrAPIFailure, name)
		}
		if err := json.Unmarshal(raw, &answer); err != nil || answer == nil || !answer.validate(kind, choices) {
			return nil, fmt.Errorf("%w: invalid answer %s", ErrAPIFailure, name)
		}
		return answer, nil
	}
	containedAns, err := readAnswer("is_workspace_contained", "noul", nil)
	if err != nil {
		return nil, err
	}
	destructiveAns, err := readAnswer("destructive_potential", "score", nil)
	if err != nil {
		return nil, err
	}
	violationAns, err := readAnswer("violation_category", "choice", violationCriteria)
	if err != nil {
		return nil, err
	}
	var intentAlign string
	var intentConf float64
	if hasIntent {
		intentAns, err := readAnswer("intent_alignment", "choice", intentCriteria)
		if err != nil {
			return nil, err
		}
		intentAlign = *intentAns.Choice
		intentConf = *intentAns.Confidence
	}

	return &JevJudgments{
		IsWorkspaceContained:  *containedAns.Noul,
		DestructivePotential:  *destructiveAns.Score,
		DestructiveConfidence: *destructiveAns.Confidence,
		ViolationCategory:     *violationAns.Choice,
		ViolationConfidence:   *violationAns.Confidence,
		IntentAlignment:       intentAlign,
		IntentConfidence:      intentConf,
		Model:                 resp.Model,
	}, nil
}
