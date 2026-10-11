package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

// maxResponseBytes bounds how much of a provider response is read.
const maxResponseBytes = 1 << 20

var (
	// ErrUnsupportedProvider means the configured provider name is unknown.
	ErrUnsupportedProvider = errors.New("decision model provider is not supported")
	// ErrMissingModel means a provider without a default model has no model configured.
	ErrMissingModel = errors.New("decision model is not configured (set model in ~/.jevguard/.jevguard.json)")
	// ErrMissingProviderAPIKey means a non-TypeSafe provider has no API key.
	ErrMissingProviderAPIKey = errors.New("decision model API key is not configured")
	// ErrInvalidJudgment means the provider answered but not with usable judgments.
	ErrInvalidJudgment = errors.New("decision model returned an invalid judgment")
	// ErrModelRefused means the provider declined to answer.
	ErrModelRefused = errors.New("decision model refused to evaluate the tool call")
)

// Evaluator produces semantic judgments for a tool call. Every error must be
// treated by the caller as "no judgment", which the policy resolves fail-safe.
type Evaluator interface {
	Evaluate(ctx context.Context, call *harness.NormalizedToolCall) (*JevJudgments, error)
}

var (
	_ Evaluator = (*Client)(nil)
	_ Evaluator = (*OpenAIClient)(nil)
	_ Evaluator = (*AnthropicClient)(nil)
)

// Options selects and configures a provider adapter.
type Options struct {
	Provider  string
	APIKey    string
	APIKeyEnv string // only used to explain a missing key
	BaseURL   string
	Model     string
	Timeout   time.Duration
}

// NewFromConfig builds the evaluator selected by the user configuration.
func NewFromConfig(cfg *config.Config) (Evaluator, error) {
	return New(Options{
		Provider:  cfg.EffectiveProvider(),
		APIKey:    cfg.APIKey,
		APIKeyEnv: cfg.EffectiveAPIKeyEnv(),
		BaseURL:   cfg.EffectiveBaseURL(),
		Model:     cfg.EffectiveModel(),
		Timeout:   cfg.Timeout,
	})
}

// New builds the evaluator for opts.Provider. An empty provider selects TypeSafe.
func New(opts Options) (Evaluator, error) {
	provider := strings.ToLower(strings.TrimSpace(opts.Provider))
	switch provider {
	case "", config.ProviderTypeSafe:
		return NewClient(opts.APIKey, opts.BaseURL, opts.Model, opts.Timeout), nil
	case config.ProviderOpenAI:
		if opts.Model == "" {
			return nil, ErrMissingModel
		}
		return &OpenAIClient{llmClient: newLLMClient(opts, config.DefaultOpenAIBaseURL)}, nil
	case config.ProviderAnthropic:
		if opts.Model == "" {
			return nil, ErrMissingModel
		}
		return &AnthropicClient{llmClient: newLLMClient(opts, config.DefaultAnthropicBaseURL)}, nil
	default:
		return nil, fmt.Errorf("%w: %q (expected one of %s)", ErrUnsupportedProvider, opts.Provider, strings.Join(config.SupportedProviders(), ", "))
	}
}

// llmClient holds the settings shared by the general-purpose LLM adapters.
type llmClient struct {
	APIKey     string
	APIKeyEnv  string
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

func newLLMClient(opts Options, defaultBaseURL string) llmClient {
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return llmClient{
		APIKey:     opts.APIKey,
		APIKeyEnv:  opts.APIKeyEnv,
		BaseURL:    baseURL,
		Model:      opts.Model,
		HTTPClient: newHTTPClient(opts.Timeout),
	}
}

func newHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// endpoint validates the base URL and appends the provider path.
func (c *llmClient) endpoint(path string) (string, error) {
	if config.ValidateBaseURL(c.BaseURL) != nil {
		return "", ErrUnsafeEndpoint
	}
	return strings.TrimRight(strings.TrimSpace(c.BaseURL), "/") + path, nil
}

func (c *llmClient) missingKeyError() error {
	if c.APIKeyEnv != "" {
		return fmt.Errorf("%w (set %s or api_key in ~/.jevguard/.jevguard.json)", ErrMissingProviderAPIKey, c.APIKeyEnv)
	}
	return fmt.Errorf("%w (set api_key in ~/.jevguard/.jevguard.json)", ErrMissingProviderAPIKey)
}

// postJSON sends body to endpoint without following redirects and returns the
// bounded response body of a 200 response. Any other status is ErrAPIFailure.
func postJSON(ctx context.Context, httpClient *http.Client, endpoint string, headers map[string]string, body interface{}) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to build evaluation request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	client := *httpClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request to decision model failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: status %d (%s)", ErrAPIFailure, resp.StatusCode, string(bodySnippet))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read decision model response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidJudgment, maxResponseBytes)
	}
	return data, nil
}
