package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func loadUserConfig(t *testing.T, contents string) *Config {
	t.Helper()
	root := t.TempDir()
	userConfigPath := filepath.Join(root, "user", ".jevguard.json")
	writeConfig(t, userConfigPath, contents)
	return LoadConfigWithPaths(nil, userConfigPath, filepath.Join(root, "user", "trusted-project-configs.json"))
}

func TestProviderConfig_LegacyConfigKeepsTypeSafeDefaults(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("TYPESAFE_API_KEY", "ts-key")
	t.Setenv("OPENAI_API_KEY", "openai-key")

	cfg := loadUserConfig(t, `{"mode":"enforcing","base_url":"https://policy.example/v1/systemone"}`)
	if cfg.EffectiveProvider() != ProviderTypeSafe {
		t.Errorf("provider = %q, want typesafe", cfg.EffectiveProvider())
	}
	if cfg.EffectiveBaseURL() != "https://policy.example/v1/systemone" || cfg.EffectiveModel() != DefaultTypeSafeModel {
		t.Errorf("base_url/model = %q/%q", cfg.EffectiveBaseURL(), cfg.EffectiveModel())
	}
	if cfg.APIKey != "ts-key" || cfg.Sources["api_key"] != "TYPESAFE_API_KEY environment variable" {
		t.Errorf("api key = %q from %q, want ts-key from TYPESAFE_API_KEY", cfg.APIKey, cfg.Sources["api_key"])
	}
	if cfg.Sources["provider"] != "built-in default" {
		t.Errorf("provider source = %q", cfg.Sources["provider"])
	}

	defaults := loadUserConfig(t, `{}`)
	if defaults.EffectiveBaseURL() != DefaultTypeSafeBaseURL {
		t.Errorf("default base URL = %q", defaults.EffectiveBaseURL())
	}
}

func TestProviderConfig_UserSelectsProvider(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("TYPESAFE_API_KEY", "ts-key")
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-key")

	cfg := loadUserConfig(t, `{"provider":" Anthropic ","model":"claude-test"}`)
	if cfg.EffectiveProvider() != ProviderAnthropic || cfg.Sources["provider"] != "user config" {
		t.Errorf("provider = %q (%s)", cfg.EffectiveProvider(), cfg.Sources["provider"])
	}
	if cfg.EffectiveBaseURL() != DefaultAnthropicBaseURL || cfg.EffectiveModel() != "claude-test" {
		t.Errorf("base_url/model = %q/%q", cfg.EffectiveBaseURL(), cfg.EffectiveModel())
	}
	if cfg.APIKey != "anthropic-key" || cfg.Sources["api_key"] != "ANTHROPIC_API_KEY environment variable" {
		t.Errorf("api key = %q from %q, want anthropic-key", cfg.APIKey, cfg.Sources["api_key"])
	}
	if cfg.Mode != "enforcing" || len(cfg.Diagnostics) != 0 {
		t.Errorf("mode=%q diagnostics=%v", cfg.Mode, cfg.Diagnostics)
	}
}

func TestProviderConfig_TypeSafeKeyIsNotSentToOtherProviders(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("TYPESAFE_API_KEY", "ts-key")

	cfg := loadUserConfig(t, `{"provider":"openai","model":"gpt-test"}`)
	if cfg.APIKey != "" {
		t.Errorf("openai provider picked up %q; TYPESAFE_API_KEY must not be reused", cfg.APIKey)
	}
	if cfg.EffectiveAPIKeyEnv() != "OPENAI_API_KEY" || cfg.EffectiveModel() != "gpt-test" {
		t.Errorf("api_key_env/model = %q/%q", cfg.EffectiveAPIKeyEnv(), cfg.EffectiveModel())
	}
	if noModel := loadUserConfig(t, `{"provider":"openai"}`); noModel.EffectiveModel() != "" {
		t.Errorf("openai default model = %q, want none", noModel.EffectiveModel())
	}
}

func TestProviderConfig_APIKeyEnvOverridesDefaultAndFallsBackToFile(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("OPENAI_API_KEY", "default-env-key")
	t.Setenv("PROJECT_CHOSEN_KEY", "router-key")

	cfg := loadUserConfig(t, `{"provider":"openai","api_key_env":"PROJECT_CHOSEN_KEY","api_key":"file-key","base_url":"https://openrouter.example/api/v1","model":"m"}`)
	if cfg.APIKey != "router-key" || cfg.Sources["api_key"] != "PROJECT_CHOSEN_KEY environment variable" || cfg.Sources["api_key_env"] != "user config" {
		t.Errorf("api key = %q from %q (env source %q)", cfg.APIKey, cfg.Sources["api_key"], cfg.Sources["api_key_env"])
	}

	t.Setenv("PROJECT_CHOSEN_KEY", "")
	fallback := loadUserConfig(t, `{"provider":"openai","api_key_env":"PROJECT_CHOSEN_KEY","api_key":"file-key","model":"m"}`)
	if fallback.APIKey != "file-key" || fallback.Sources["api_key"] != "user config" {
		t.Errorf("api key = %q from %q, want file-key from user config", fallback.APIKey, fallback.Sources["api_key"])
	}
}

func TestProviderConfig_UnknownProviderFailsSafe(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("TYPESAFE_API_KEY", "ts-key")

	cfg := loadUserConfig(t, `{"mode":"audit","provider":"gemini","model":"m"}`)
	if cfg.EffectiveProvider() != "gemini" {
		t.Errorf("provider = %q, want the unknown value kept so evaluation fails safe", cfg.EffectiveProvider())
	}
	if cfg.APIKey != "" || cfg.EffectiveAPIKeyEnv() != "" || cfg.EffectiveBaseURL() != "" {
		t.Errorf("unknown provider resolved credentials or endpoint: key=%q env=%q base=%q", cfg.APIKey, cfg.EffectiveAPIKeyEnv(), cfg.EffectiveBaseURL())
	}
	if cfg.Mode != "enforcing" || cfg.Sources["mode"] != "safe fallback after invalid user config" {
		t.Errorf("mode = %q (%s), want enforcing safe fallback", cfg.Mode, cfg.Sources["mode"])
	}
	if len(cfg.Diagnostics) != 1 || !strings.HasPrefix(cfg.Diagnostics[0], `user config provider "gemini" is not supported`) {
		t.Errorf("diagnostics = %v", cfg.Diagnostics)
	}
}

func TestProviderConfig_InvalidAPIKeyEnvIgnored(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("OPENAI_API_KEY", "openai-key")

	for _, name := range []string{"1BAD", "BAD-NAME", "$OPENAI_API_KEY", "A B"} {
		cfg := loadUserConfig(t, `{"mode":"audit","provider":"openai","model":"m","api_key_env":"`+name+`"}`)
		if cfg.APIKeyEnv != "" || cfg.APIKey != "openai-key" {
			t.Errorf("%q: api_key_env=%q key=%q, want ignored with provider default", name, cfg.APIKeyEnv, cfg.APIKey)
		}
		if cfg.Mode != "enforcing" {
			t.Errorf("%q: mode = %q, want enforcing", name, cfg.Mode)
		}
	}
}

func TestProviderConfig_ResponseFormatNormalizedFromUserConfig(t *testing.T) {
	clearConfigEnvironment(t)

	cfg := loadUserConfig(t, `{"provider":"openai","model":"m","response_format":" JSON_Object "}`)
	if cfg.ResponseFormat != "json_object" {
		t.Errorf("ResponseFormat = %q, want json_object", cfg.ResponseFormat)
	}
	if cfg.Sources["response_format"] != "user config" {
		t.Errorf("response_format source = %q, want user config", cfg.Sources["response_format"])
	}
}

func TestProviderConfig_InvalidResponseFormatFallsBackToEnforcing(t *testing.T) {
	clearConfigEnvironment(t)

	cfg := loadUserConfig(t, `{"mode":"audit","provider":"openai","model":"m","response_format":"xml"}`)
	if cfg.ResponseFormat != "" {
		t.Errorf("ResponseFormat = %q, want empty", cfg.ResponseFormat)
	}
	if cfg.Mode != "enforcing" {
		t.Errorf("Mode = %q, want enforcing", cfg.Mode)
	}
	wantDiagnostics := []string{"user config response_format ignored: expected json_schema or json_object"}
	if !reflect.DeepEqual(cfg.Diagnostics, wantDiagnostics) {
		t.Errorf("Diagnostics = %#v, want %#v", cfg.Diagnostics, wantDiagnostics)
	}
}

func TestIsLoopbackBaseURL(t *testing.T) {
	for value, want := range map[string]bool{
		"http://localhost:11434/v1":  true,
		"http://127.0.0.1:8000/v1":   true,
		"http://[::1]:1234/v1":       true,
		"https://localhost/v1":       true,
		"https://api.openai.com/v1":  false,
		"http://example.com/v1":      false,
		"http://user:pw@localhost/":  false,
		"https://localhost.evil.com": false,
	} {
		if got := IsLoopbackBaseURL(value); got != want {
			t.Errorf("IsLoopbackBaseURL(%q) = %t, want %t", value, got, want)
		}
	}
}
