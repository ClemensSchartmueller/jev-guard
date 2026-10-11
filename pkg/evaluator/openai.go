package evaluator

import (
	"context"
	"encoding/json"
	"fmt"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

// OpenAIClient evaluates tool calls through an OpenAI-compatible Chat
// Completions endpoint (OpenAI, OpenRouter, Ollama, vLLM, LM Studio, and the
// Gemini OpenAI compatibility layer). BaseURL is the API root; the client posts
// to BaseURL + "/chat/completions" with a strict json_schema response format.
type OpenAIClient struct {
	llmClient
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content *string `json:"content"`
			Refusal *string `json:"refusal"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// Evaluate implements Evaluator.
func (c *OpenAIClient) Evaluate(ctx context.Context, call *harness.NormalizedToolCall) (*JevJudgments, error) {
	endpoint, err := c.endpoint("/chat/completions")
	if err != nil {
		return nil, err
	}
	// Local servers (Ollama, vLLM, LM Studio) usually need no key, so a missing
	// key is only an error for non-loopback endpoints.
	headers := map[string]string{}
	if c.APIKey != "" {
		headers["Authorization"] = "Bearer " + c.APIKey
	} else if !config.IsLoopbackBaseURL(c.BaseURL) {
		return nil, c.missingKeyError()
	}

	system, user, err := llmPrompts(call)
	if err != nil {
		return nil, err
	}
	withIntent := call.UserIntent != ""
	body := map[string]interface{}{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]interface{}{
			"type": "json_schema",
			"json_schema": map[string]interface{}{
				"name":   judgmentSchemaName,
				"strict": true,
				"schema": judgmentSchema(withIntent),
			},
		},
	}

	data, err := postJSON(ctx, c.HTTPClient, endpoint, headers, body)
	if err != nil {
		return nil, err
	}
	var resp openAIResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode chat completion: %v", ErrInvalidJudgment, err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("%w: chat completion has no choices", ErrInvalidJudgment)
	}
	choice := resp.Choices[0]
	if choice.Message.Refusal != nil && *choice.Message.Refusal != "" {
		return nil, fmt.Errorf("%w: %s", ErrModelRefused, *choice.Message.Refusal)
	}
	if choice.FinishReason == "content_filter" {
		return nil, fmt.Errorf("%w: finish_reason content_filter", ErrModelRefused)
	}
	if choice.FinishReason == "length" {
		return nil, fmt.Errorf("%w: output truncated (finish_reason length)", ErrInvalidJudgment)
	}
	if choice.Message.Content == nil {
		return nil, fmt.Errorf("%w: chat completion has no content", ErrInvalidJudgment)
	}
	return parseLLMJudgment(*choice.Message.Content, withIntent)
}
