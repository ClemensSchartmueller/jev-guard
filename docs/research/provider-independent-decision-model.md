# Provider-independent decision model

Issue: #37. Researched 2026-10-11.

## Question

jev-guard sends every tool call that the local fastpath cannot decide to a
"decision model" that returns semantic judgments. Today that model is always
TypeSafe System One. Which provider APIs should jev-guard support, how should
they be selected and configured, and how can this work without weakening the
config trust boundary or the fail-safe behavior?

## How the decision model is wired today

- `pkg/evaluator/typesafe.go`: `Client.Evaluate` posts one JSON request to
  `base_url` (default `https://api.typesafe.ai/v1/systemone`). It sends
  `Authorization: Bearer <key>`, does not follow redirects, and validates the
  endpoint with `config.ValidateBaseURL` (HTTPS, or HTTP on loopback only, and no
  credentials, query, or fragment). The request carries the tool call `state`
  and typed `questions` (`noul`, `score` with four criteria, `choice`). The
  response `answers` are mapped to `JevJudgments`.
- `JevJudgments` is the provider-neutral contract that `pkg/policy` consumes:
  containment probability (0-1), destructive potential (on the 0-3 scale of the
  four score criteria; the policy asks above 1.2 and denies above 2.5), violation
  category plus confidence, and intent alignment plus confidence.
- `main.go` `performSemanticEvaluation` builds the client from `cfg.APIKey`,
  `cfg.BaseURL`, `cfg.Model`, and `cfg.Timeout`. Any error goes to
  `policy.ResolveWithEvidence`, which returns `ASK` with source `policy_failsafe`.
  That is the fail-safe contract a new provider must keep.
- `pkg/config`: `base_url`, `model`, `api_key`, and `timeout_ms` are read only
  from the user-owned `~/.jevguard/.jevguard.json`. The only credential read
  from the environment is `TYPESAFE_API_KEY`. Project configs contribute only
  `sensitive_files`, even after hash-pinned trust. Every other key is reported
  in `IgnoredKeys`. An invalid `base_url` or `mode` forces `enforcing`.
  `pkg/config/trust_boundary_test.go` asserts these properties.
- README "Configuration Options" and the settings table document a
  TypeSafe-only setup.

## Provider APIs (primary sources)

### OpenAI Chat Completions and compatible servers

- Request: `POST {root}/chat/completions` with `Authorization: Bearer <key>`,
  `model`, and `messages` (`system`/`user` roles).
- Structured output: `response_format: {"type": "json_schema", "json_schema":
  {"name", "strict": true, "schema"}}`. With `strict: true` the output follows
  the schema. Strict schemas need `additionalProperties: false` and every
  property in `required`. Refusals arrive in a separate `refusal` field instead
  of schema-shaped content. `json_object` mode produces valid JSON but does not
  enforce a schema. [1][2]
- The reply is `choices[0].message.content`. `finish_reason` `length` means
  truncated output, and `content_filter` means the output was filtered.
- The same request shape works on:
  - **OpenRouter**: `response_format` `json_schema` with `name`/`strict`/`schema`.
    Support depends on the model and endpoint. Unsupported combinations return an
    error. Strictness is exact only where the upstream provider enforces it. [3]
  - **Ollama**: OpenAI-compatible endpoint at `http://localhost:11434/v1/`. It
    lists `response_format` as supported. The local server ignores the API key
    (clients pass a placeholder). Ollama Cloud is at `https://ollama.com/v1`. [4]
  - **vLLM**: the OpenAI-compatible server accepts `response_format`
    `json_schema` with `name` and `schema`. Structured outputs are on by default. [5]
  - **LM Studio**: `http://localhost:1234/v1`, `response_format` `json_schema`,
    and the local server needs no key. [6]
  - **Gemini**: an OpenAI compatibility layer at
    `https://generativelanguage.googleapis.com/v1beta/openai/` with
    `Authorization: Bearer $GEMINI_API_KEY`. Structured output is supported
    through `response_format`. [7]

### Anthropic Messages API

- Request: `POST https://api.anthropic.com/v1/messages` with headers
  `x-api-key`, `anthropic-version: 2023-06-01`, and `content-type:
  application/json`. Required body fields are `model`, `max_tokens`, and
  `messages`. The system prompt goes in the top-level `system` field. [8]
- Structured output: `output_config: {"format": {"type": "json_schema",
  "schema": ...}}`. It is GA, so no beta header is needed (the older
  `output_format` parameter is deprecated). The JSON arrives in a `text` content
  block. [9]
- Schema limits that matter here: every object needs `additionalProperties:
  false`. String and number `enum`s are supported. Numeric constraints such as
  `minimum` and `maximum` are **not** supported and return a 400 error.
  Enum values may come back with different capitalization. A `stop_reason` of
  `refusal` or `max_tokens` can produce output that does not match the schema. [9]

### Gemini native API

Gemini's native `generateContent` API uses a different shape
(`x-goog-api-key`, plus `responseMimeType` and a response schema in
`generationConfig`). Gemini is already reachable through its OpenAI
compatibility layer [7], so a native adapter adds little now.

## Findings

1. A single **OpenAI-compatible adapter** reaches the most providers: OpenAI,
   OpenRouter, Ollama, vLLM, LM Studio, and Gemini. All of them take the same
   `response_format` `json_schema` request.
2. **Anthropic** has a different wire format (headers, `system`,
   `output_config`, content blocks). It needs its own adapter.
3. One judgment schema can serve both adapters if it uses only the common
   subset: every property required, `additionalProperties: false`, enums for
   categories, and no numeric bounds. Range checks must then happen locally,
   because Anthropic does not enforce bounds and some OpenAI-compatible servers
   treat a schema only as a hint [3][9].
4. General-purpose LLMs do not return TypeSafe's typed answers. Asking for a
   **0-3 integer destructive level** with the same four criteria maps directly
   onto the policy's 0-3 score scale. Containment and confidences stay
   probabilities.
5. Local servers usually need no key, while hosted APIs do. Requiring a key
   except on loopback endpoints matches how those servers behave [4][6].
6. Reusing `TYPESAFE_API_KEY` for every provider would send a TypeSafe secret to
   a different vendor. Each provider needs its own default key variable.

## Recommendation (implemented in this change)

- Add an `evaluator.Evaluator` interface and an `evaluator.New` /
  `NewFromConfig` factory. The existing TypeSafe `Client` is unchanged and
  stays the default.
- Add two adapters: `openai` (OpenAI-compatible Chat Completions with a strict
  `json_schema`) and `anthropic` (Messages API with `output_config.format`).
  Both use the shared prompt and schema, the no-redirect HTTP client, the
  endpoint validation, and a 1 MiB response cap.
- Validate model output strictly. A missing field, a value out of range, a
  non-integer level, an unknown category, a refusal, or truncation is an error,
  so it fails safe to `ASK` / `policy_failsafe`. Without a user intent, any
  intent claim the model makes is ignored.
- Add user-config keys `provider` and `api_key_env`, alongside the existing
  `base_url`, `model`, and `api_key`.
  - No `provider` means `typesafe`, so existing configs keep their behavior.
  - Default key variables: `TYPESAFE_API_KEY`, `OPENAI_API_KEY`,
    `ANTHROPIC_API_KEY`.
  - `openai` and `anthropic` have no default model, because hosted model IDs
    change too quickly to hard-code.
  - An unknown `provider` is kept, not dropped. It forces `enforcing` and makes
    evaluation fail safe instead of quietly sending data and credentials to
    TypeSafe.
- Keep the trust boundary: project configs still apply only `sensitive_files`.
  The trust boundary tests now also assert that `provider`, `api_key_env`, and
  `model` from untrusted and trusted project configs are ignored.

## Deferred follow-ups

- Native Gemini `generateContent` adapter (Gemini works today through the
  OpenAI compatibility layer).
- Azure OpenAI (`api-key` header and deployment-scoped URLs), AWS Bedrock
  (SigV4 signing), and Google Vertex AI (OAuth). Each needs a cloud-specific
  auth flow.
- A `json_object` fallback for OpenAI-compatible servers without `json_schema`
  support.
- Provider-neutral wording in policy reasons. The allow reason still says
  "verified safe and contained by TypeSafe AI".
- A calibration corpus that compares LLM judgments with TypeSafe on the same
  tool calls before anyone relies on a general-purpose model for enforcement.

## Sources

1. OpenAI, "Introducing Structured Outputs in the API":
   https://openai.com/index/introducing-structured-outputs-in-the-api/
2. OpenAI, Structured Outputs guide:
   https://developers.openai.com/api/docs/guides/structured-outputs
3. OpenRouter, Structured outputs:
   https://openrouter.ai/docs/guides/features/structured-outputs
4. Ollama, OpenAI compatibility: https://docs.ollama.com/api/openai-compatibility
5. vLLM, Structured outputs:
   https://docs.vllm.ai/en/latest/features/structured_outputs.html
6. LM Studio, Structured output:
   https://lmstudio.ai/docs/developer/openai-compat/structured-output
7. Google, Gemini OpenAI compatibility: https://ai.google.dev/gemini-api/docs/openai
8. Anthropic, Messages API: https://platform.claude.com/docs/en/api/messages
9. Anthropic, Structured outputs:
   https://platform.claude.com/docs/en/build-with-claude/structured-outputs
