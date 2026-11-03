package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func transcriptDiagnostics(cfg *Config) []string {
	var found []string
	for _, d := range cfg.Diagnostics {
		if strings.Contains(d, "antigravity_transcript_intent") {
			found = append(found, d)
		}
	}
	return found
}

func TestAntigravityTranscriptIntentIsOptIn(t *testing.T) {
	if DefaultConfig().IsAntigravityTranscriptIntentEnabled() {
		t.Fatal("expected default off")
	}
	var empty Config
	if empty.IsAntigravityTranscriptIntentEnabled() {
		t.Fatal("expected unset to mean off")
	}
	for _, tc := range []struct {
		name       string
		value      string
		want       bool
		source     string
		diagnostic bool
	}{
		{name: "absent", value: "", want: false, source: "built-in default"},
		{name: "true", value: `true`, want: true, source: "user config"},
		{name: "false", value: `false`, want: false, source: "user config"},
		{name: "null", value: `null`, want: false, source: "built-in default"},
		{name: "string", value: `"true"`, want: false, source: "safe fallback after invalid user config", diagnostic: true},
		{name: "number", value: `1`, want: false, source: "safe fallback after invalid user config", diagnostic: true},
		{name: "object", value: `{"on":true}`, want: false, source: "safe fallback after invalid user config", diagnostic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			root := t.TempDir()
			userConfig := filepath.Join(root, ".jevguard.json")
			body := `{"mode":"audit"`
			if tc.value != "" {
				body += `,"antigravity_transcript_intent":` + tc.value
			}
			writeConfig(t, userConfig, body+`}`)
			cfg := LoadConfigWithPaths([]string{root}, userConfig, filepath.Join(root, "registry.json"))
			if got := cfg.IsAntigravityTranscriptIntentEnabled(); got != tc.want {
				t.Errorf("enabled = %t, want %t", got, tc.want)
			}
			if got := cfg.Sources["antigravity_transcript_intent"]; got != tc.source {
				t.Errorf("source = %q, want %q", got, tc.source)
			}
			if got := len(transcriptDiagnostics(cfg)) > 0; got != tc.diagnostic {
				t.Errorf("diagnostics = %q, want present=%t", cfg.Diagnostics, tc.diagnostic)
			}
			// One bad value must not discard the rest of the user's config.
			if cfg.Mode != "audit" {
				t.Errorf("mode = %q, the rest of the config was lost", cfg.Mode)
			}
			// The hook runs EnsureUserConfig first, and a bad value must not stop every hook.
			if err := ensureUserConfigAt(userConfig); err != nil {
				t.Errorf("ensureUserConfigAt: %v", err)
			}
		})
	}
}

func TestGeneratedUserConfigLeavesTranscriptIntentOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".jevguard", ".jevguard.json")
	if err := ensureUserConfigAt(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["antigravity_transcript_intent"]) != "false" {
		t.Fatalf("generated file: %s", data)
	}
}

// A project config cannot opt in, trusted or not, and an inspection names the ignored key.
func TestProjectConfigCannotEnableTranscriptIntent(t *testing.T) {
	clearConfigEnvironment(t)
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	userConfig := filepath.Join(root, "user", ".jevguard.json")
	registry := filepath.Join(root, "user", "trusted-project-configs.json")
	writeConfig(t, userConfig, `{}`)
	project := filepath.Join(repo, ".jevguard.json")
	writeConfig(t, project, `{"antigravity_transcript_intent":true,"sensitive_files":[".project-secret"]}`)

	untrusted := LoadConfigWithPaths([]string{repo}, userConfig, registry)
	if untrusted.IsAntigravityTranscriptIntentEnabled() {
		t.Error("untrusted project config enabled transcript intent")
	}

	info, err := inspectProjectConfigIsolated(t, project)
	if err != nil {
		t.Fatal(err)
	}
	if !containsConfigValue(info.IgnoredKeys, "antigravity_transcript_intent") {
		t.Errorf("IgnoredKeys = %q", info.IgnoredKeys)
	}
	data, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, registry, string(data))
	trusted := LoadConfigWithPaths([]string{repo}, userConfig, registry)
	if !containsConfigValue(trusted.SensitiveFiles, ".project-secret") {
		t.Fatal("the trust fixture did not apply")
	}
	if trusted.IsAntigravityTranscriptIntentEnabled() {
		t.Error("trusted project config enabled transcript intent")
	}
	// Nor can a trusted project turn off what the user turned on.
	writeConfig(t, userConfig, `{"antigravity_transcript_intent":true}`)
	writeConfig(t, project, `{"antigravity_transcript_intent":false,"sensitive_files":[".project-secret"]}`)
	info, err = inspectProjectConfigIsolated(t, project)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, registry, string(data))
	on := LoadConfigWithPaths([]string{repo}, userConfig, registry)
	if !containsConfigValue(on.SensitiveFiles, ".project-secret") {
		t.Fatal("the trust fixture did not apply")
	}
	if !on.IsAntigravityTranscriptIntentEnabled() {
		t.Error("trusted project config disabled the user's setting")
	}
}
