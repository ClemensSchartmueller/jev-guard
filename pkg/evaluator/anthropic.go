package evaluator

import (
	"context"
	"encoding/json"
	"fmt"

	"jev-guard/pkg/harness"
)

const (
	// anthropicVersion is the Messages API version header value.
	anthropicVersion = "2023-06-01"
	// anthropicMaxTokens bounds the judgment output, which is a small JSON object.
	anthropicMaxTokens = 1024
)

// AnthropicClient evaluates tool calls through the Anthropic Messages API.
// BaseURL is the API root; the client posts to BaseURL + "/messages" with
// output_config.format set to the judgment JSON schema.
type AnthropicClient struct {
	llmClient
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
}

// Evaluate implements Evaluator.
func (c *AnthropicClient) Evaluate(ctx context.Context, call *harness.NormalizedToolCall) (*JevJudgments, error) {
	endpoint, err := c.endpoint("/messages")
	if err != nil {
		return nil, err
	}
	if c.APIKey == "" {
		return nil, c.missingKeyError()
	}

	system, user, err := llmPrompts(call)
	if err != nil {
		return nil, err
	}
	withIntent := call.UserIntent != ""
	body := map[string]interface{}{
		"model":      c.Model,
		"max_tokens": anthropicMaxTokens,
		"system":     system,
		"messages": []map[string]string{
			{"role": "user", "content": user},
		},
		"output_config": map[string]interface{}{
			"format": map[string]interface{}{
				"type":   "json_schema",
				"schema": judgmentSchema(withIntent),
			},
		},
	}
	headers := map[string]string{
		"x-api-key":         c.APIKey,
		"anthropic-version": anthropicVersion,
	}

	data, err := postJSON(ctx, c.HTTPClient, endpoint, headers, body)
	if err != nil {
		return nil, err
	}
	var resp anthropicResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode message: %v", ErrInvalidJudgment, err)
	}
	switch resp.StopReason {
	case "refusal":
		return nil, fmt.Errorf("%w: stop_reason refusal", ErrModelRefused)
	case "max_tokens":
		return nil, fmt.Errorf("%w: output truncated (stop_reason max_tokens)", ErrInvalidJudgment)
	}
	for _, block := range resp.Content {
		if block.Type == "text" {
			return parseLLMJudgment(block.Text, withIntent)
		}
	}
	return nil, fmt.Errorf("%w: message has no text content", ErrInvalidJudgment)
}
