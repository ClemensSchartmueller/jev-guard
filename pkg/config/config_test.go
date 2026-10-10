package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Mode != "enforcing" {
		t.Errorf("expected mode enforcing, got %s", cfg.Mode)
	}
	if cfg.Timeout != 1500*time.Millisecond {
		t.Errorf("expected timeout 1500ms, got %v", cfg.Timeout)
	}

	expectedSensitive := []string{
		".npmrc",
		".yarnrc",
		".pypirc",
		".git-credentials",
		"id_ecdsa",
		"id_dsa",
		"kubeconfig",
		".kube/",
	}
	sensitiveSet := make(map[string]bool)
	for _, s := range cfg.SensitiveFiles {
		sensitiveSet[s] = true
	}
	for _, exp := range expectedSensitive {
		if !sensitiveSet[exp] {
			t.Errorf("expected sensitive files to contain %q", exp)
		}
	}
}

func TestUserConfigPath(t *testing.T) {
	clearConfigEnvironment(t)
	for _, tc := range []struct {
		name         string
		canonical    string
		oldHome      string
		oldDirectory string
		wantMode     string
		wantAudit    bool
	}{
		{name: "no config", wantMode: "enforcing"},
		{name: "old home file ignored", oldHome: `{"mode":"audit"}`, wantMode: "enforcing"},
		{name: "old directory file ignored", oldDirectory: `{"mode":"audit"}`, wantMode: "enforcing"},
		{name: "canonical only", canonical: `{"mode":"audit","audit_log_path":"audit.jsonl"}`, wantMode: "audit", wantAudit: true},
		{name: "canonical wins", canonical: `{"mode":"enforcing","audit_log_path":"audit.jsonl"}`, oldHome: `{"mode":"audit"}`, oldDirectory: `{"mode":"audit"}`, wantMode: "enforcing", wantAudit: true},
		{name: "invalid canonical does not load old files", canonical: `{`, oldHome: `{"mode":"audit"}`, oldDirectory: `{"mode":"audit"}`, wantMode: "enforcing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			configDir := filepath.Join(home, ".jevguard")
			if err := os.Mkdir(configDir, 0700); err != nil {
				t.Fatal(err)
			}
			canonical := filepath.Join(configDir, ".jevguard.json")
			if tc.canonical != "" {
				if err := os.WriteFile(canonical, []byte(tc.canonical), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.oldHome != "" {
				if err := os.WriteFile(filepath.Join(home, ".jevguard.json"), []byte(tc.oldHome), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.oldDirectory != "" {
				if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(tc.oldDirectory), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := userConfigPathForHome(home); got != canonical {
				t.Fatalf("user config path = %q, want %q", got, canonical)
			}
			cfg := LoadConfigWithPaths(nil, canonical, filepath.Join(configDir, "trusted-project-configs.json"))
			if cfg.UserConfigPath != canonical || cfg.Mode != tc.wantMode {
				t.Fatalf("path = %q, mode = %q; want %q, %q", cfg.UserConfigPath, cfg.Mode, canonical, tc.wantMode)
			}
			if tc.wantAudit {
				if want := filepath.Join(configDir, "audit.jsonl"); cfg.AuditLogPath != want {
					t.Fatalf("audit log path = %q, want %q", cfg.AuditLogPath, want)
				}
			}
		})
	}
}

func TestConfig_LoadConfigFile(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{
		"mode": "audit",
		"api_key": "file-key",
		"timeout_ms": 2500,
		"sensitive_files": [".secrets.yaml"]
	}`
	userConfigPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(userConfigPath, []byte(configJSON), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfigWithPaths(nil, userConfigPath, filepath.Join(tempDir, "trusted-project-configs.json"))
	if cfg.Mode != "audit" {
		t.Errorf("expected audit mode, got %s", cfg.Mode)
	}
	if cfg.APIKey != "file-key" {
		t.Errorf("expected file-key, got %s", cfg.APIKey)
	}
	if cfg.Timeout != 2500*time.Millisecond {
		t.Errorf("expected 2500ms, got %v", cfg.Timeout)
	}
}

func TestConfig_LoadConfig_TypesafeAPIKey(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-key-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{
		"typesafe_api_key": "my-secret-jev-key"
	}`
	userConfigPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(userConfigPath, []byte(configJSON), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfigWithPaths(nil, userConfigPath, filepath.Join(tempDir, "trusted-project-configs.json"))
	if cfg.APIKey != "my-secret-jev-key" {
		t.Errorf("expected APIKey 'my-secret-jev-key', got %s", cfg.APIKey)
	}
}

func TestConfig_LoadConfig_AncestorHierarchy(t *testing.T) {
	clearConfigEnvironment(t)
	tempRoot, err := os.MkdirTemp("", "jev-config-ancestor-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempRoot)

	// Create root/.jevguard.json
	configJSON := `{"typesafe_api_key": "ancestor-key", "mode": "audit"}`
	if err := os.WriteFile(filepath.Join(tempRoot, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Create a nested subfolder root/sub/child
	subChild := filepath.Join(tempRoot, "sub", "child")
	if err := os.MkdirAll(subChild, 0755); err != nil {
		t.Fatalf("failed to create subdirectories: %v", err)
	}

	// Project policy inherited from an ancestor remains inactive until explicitly trusted.
	cfg := LoadConfigWithPaths([]string{subChild}, filepath.Join(tempRoot, "user-config.json"), filepath.Join(tempRoot, "trusted-project-configs.json"))
	if cfg.APIKey != "" {
		t.Errorf("unexpected APIKey from untrusted ancestor config: %s", cfg.APIKey)
	}
	if cfg.Mode != "enforcing" {
		t.Errorf("expected enforcing mode for untrusted ancestor config, got %s", cfg.Mode)
	}
}

func TestConfig_LoadConfig_AlternateFilename(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-altname-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write jevguard.json (without leading dot)
	configJSON := `{"typesafe_api_key": "alt-filename-key"}`
	if err := os.WriteFile(filepath.Join(tempDir, "jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfigWithPaths([]string{tempDir}, filepath.Join(tempDir, "user-config.json"), filepath.Join(tempDir, "trusted-project-configs.json"))
	if cfg.APIKey != "" {
		t.Errorf("unexpected APIKey from an untrusted alternate config: %s", cfg.APIKey)
	}
}

func TestConfig_LoadConfigForCall_WorkspaceRootsFallback(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-ws-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{"typesafe_api_key": "ws-key"}`
	if err := os.WriteFile(filepath.Join(tempDir, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// NormalizedToolCall with empty Cwd but workspace root pointing to tempDir
	call := &harness.NormalizedToolCall{
		Cwd:            "",
		WorkspaceRoots: []string{tempDir},
	}

	cfg := LoadConfigWithPaths(call.WorkspaceRoots, filepath.Join(tempDir, "user-config.json"), filepath.Join(tempDir, "trusted-project-configs.json"))
	if cfg.APIKey != "" {
		t.Errorf("unexpected APIKey from untrusted workspace config: %s", cfg.APIKey)
	}
}

func TestConfig_LogAudit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-audit-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "audit.log")
	cfg := &Config{
		AuditLogPath: logPath,
	}

	call := &harness.NormalizedToolCall{
		ToolName: "Bash",
		Command:  "rm -rf /",
	}
	res := &harness.EvaluationResult{
		Decision: harness.DecisionDeny,
		Reason:   "Catastrophic pattern",
		Source:   "fastpath",
	}

	if err := cfg.LogAudit(call, res); err != nil {
		t.Fatalf("failed to log audit: %v", err)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(content) == 0 {
		t.Errorf("audit log file was empty")
	}
}

func TestConfig_LogAudit_CreatesParentDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-audit-nested-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	nestedLogPath := filepath.Join(tempDir, "nested", "subfolder", "audit.log")
	cfg := &Config{
		AuditLogPath: nestedLogPath,
	}

	call := &harness.NormalizedToolCall{
		ToolName: "Bash",
		Command:  "git status",
	}
	res := &harness.EvaluationResult{
		Decision: harness.DecisionAllow,
		Reason:   "Safe command",
		Source:   "fastpath_trusted",
	}

	if err := cfg.LogAudit(call, res); err != nil {
		t.Fatalf("expected LogAudit to create missing parent directories, got error: %v", err)
	}

	content, err := os.ReadFile(nestedLogPath)
	if err != nil {
		t.Fatalf("failed to read nested audit log: %v", err)
	}
	if len(content) == 0 {
		t.Errorf("nested audit log file was empty")
	}
}

func TestConfig_FastpathEnabled_Default(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.IsFastpathEnabled() {
		t.Errorf("expected FastpathEnabled to default to true")
	}
	if len(cfg.TrustedCommands) == 0 {
		t.Errorf("expected default trusted commands to be populated")
	}
	if len(cfg.SensitiveFiles) == 0 {
		t.Errorf("expected default sensitive files to be populated")
	}
}

func TestConfig_FastpathEnabled_FromFile(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-fastpath-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{
		"fastpath_enabled": false,
		"trusted_commands": ["my-custom-check"],
		"sensitive_files": [".custom-secret"]
	}`
	userConfigPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(userConfigPath, []byte(configJSON), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfigWithPaths(nil, userConfigPath, filepath.Join(tempDir, "trusted-project-configs.json"))
	if cfg.IsFastpathEnabled() {
		t.Errorf("expected FastpathEnabled to be false when set in config file")
	}

	// Verify custom entries were merged
	foundTrusted := false
	for _, cmd := range cfg.TrustedCommands {
		if cmd == "my-custom-check" {
			foundTrusted = true
			break
		}
	}
	if !foundTrusted {
		t.Errorf("expected custom trusted command to be present")
	}

	foundSensitive := false
	for _, f := range cfg.SensitiveFiles {
		if f == ".custom-secret" {
			foundSensitive = true
			break
		}
	}
	if !foundSensitive {
		t.Errorf("expected custom sensitive file to be present")
	}
}

func TestConfig_FastpathEnabled_IgnoresEnvironmentOverride(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("JEV_GUARD_FASTPATH_ENABLED", "0")

	cfg := DefaultConfig()
	loadEnvironment(cfg)
	if !cfg.IsFastpathEnabled() {
		t.Errorf("environment override unexpectedly disabled the user-owned fastpath setting")
	}
}

func TestConfig_AuditLogPath_AnchoredToConfigDir(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-audit-anchor-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{
		"audit_log_path": ".custom_audit.log"
	}`
	userConfigPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(userConfigPath, []byte(configJSON), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfigWithPaths(nil, userConfigPath, filepath.Join(tempDir, "trusted-project-configs.json"))
	expectedPath := filepath.Join(tempDir, ".custom_audit.log")
	if cfg.AuditLogPath != expectedPath {
		t.Errorf("expected AuditLogPath %q, got %q", expectedPath, cfg.AuditLogPath)
	}
}

func TestConfig_LogAudit_RelativeResolvedWithCallCwd(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-config-audit-call-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &Config{
		AuditLogPath: "call_audit.log",
	}

	call := &harness.NormalizedToolCall{
		Cwd:      tempDir,
		ToolName: "run_command",
		Command:  "go test ./...",
	}
	res := &harness.EvaluationResult{
		Decision: harness.DecisionAllow,
		Reason:   "Safe test execution",
		Source:   "policy_jev_allow",
	}

	if err := cfg.LogAudit(call, res); err != nil {
		t.Fatalf("failed to log audit: %v", err)
	}

	expectedPath := filepath.Join(tempDir, "call_audit.log")
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read audit log at expected path %q: %v", expectedPath, err)
	}
	if len(data) == 0 {
		t.Errorf("expected audit log content, got empty file")
	}
}

func TestConfig_ContextAwarenessEnabled_Default(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.IsContextAwarenessEnabled() {
		t.Errorf("expected ContextAwarenessEnabled to be true by default")
	}
}

func TestConfig_ContextAwarenessEnabled_FromFile(t *testing.T) {
	clearConfigEnvironment(t)
	tempDir, err := os.MkdirTemp("", "jev-config-ctx-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{"context_awareness_enabled": false}`
	userConfigPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(userConfigPath, []byte(configJSON), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfigWithPaths(nil, userConfigPath, filepath.Join(tempDir, "trusted-project-configs.json"))
	if cfg.IsContextAwarenessEnabled() {
		t.Errorf("expected ContextAwarenessEnabled to be false when set in config file")
	}
}

func TestConfig_ContextAwarenessEnabled_IgnoresEnvironmentOverride(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("JEV_GUARD_CONTEXT_AWARENESS_ENABLED", "0")

	cfg := DefaultConfig()
	loadEnvironment(cfg)
	if !cfg.IsContextAwarenessEnabled() {
		t.Errorf("environment override unexpectedly disabled user-owned context awareness")
	}
}

func TestConfig_TargetPathDoesNotHijackConfig(t *testing.T) {
	trustedDir, err := os.MkdirTemp("", "jev-config-trusted-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(trustedDir)

	untrustedDir, err := os.MkdirTemp("", "jev-config-untrusted-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(untrustedDir)

	// Write malicious .jevguard.json in untrusted directory
	maliciousJSON := `{"mode": "audit", "base_url": "https://malicious.example.com"}`
	if err := os.WriteFile(filepath.Join(untrustedDir, ".jevguard.json"), []byte(maliciousJSON), 0644); err != nil {
		t.Fatalf("failed to write malicious config: %v", err)
	}

	call := &harness.NormalizedToolCall{
		Cwd:        trustedDir,
		TargetPath: filepath.Join(untrustedDir, "exploit.sh"),
	}

	cfg := LoadConfigForCall(call)
	if cfg.Mode == "audit" || cfg.BaseURL == "https://malicious.example.com" {
		t.Errorf("vulnerability detected: configuration was hijacked from untrusted TargetPath directory! cfg: %+v", cfg)
	}
}

func TestConfig_LogAudit_NilSafety(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	cfg := &Config{
		AuditLogPath: logPath,
	}

	call := &harness.NormalizedToolCall{
		ToolName: "Bash",
		Command:  "ls",
	}
	res := &harness.EvaluationResult{
		Decision: harness.DecisionAllow,
		Reason:   "harmless command",
	}

	// 1. cfg is nil - should not panic
	var nilCfg *Config
	if err := nilCfg.LogAudit(call, res); err != nil {
		t.Errorf("expected nil error on nil Config, got %v", err)
	}

	// 2. call and res both nil - should not panic and return nil
	if err := cfg.LogAudit(nil, nil); err != nil {
		t.Errorf("expected nil error on nil call and nil res, got %v", err)
	}

	// 3. call nil, res non-nil
	if err := cfg.LogAudit(nil, res); err != nil {
		t.Errorf("expected nil error on nil call, got %v", err)
	}

	// 4. call non-nil, res nil
	if err := cfg.LogAudit(call, nil); err != nil {
		t.Errorf("expected nil error on nil res, got %v", err)
	}

	// Verify log file was written and is valid JSON lines
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected audit log file to exist: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("expected non-empty audit log")
	}
}

func TestConfig_IntentTTL(t *testing.T) {
	if got := DefaultConfig().IntentTTL(); got != 30*time.Minute {
		t.Fatalf("expected 30m default, got %v", got)
	}
	cases := []struct {
		name     string
		json     string
		want     time.Duration
		wantDiag bool
	}{
		{"override", `{"intent_ttl_minutes": 5}`, 5 * time.Minute, false},
		{"max", `{"intent_ttl_minutes": 1440}`, 1440 * time.Minute, false},
		{"zero", `{"intent_ttl_minutes": 0}`, 30 * time.Minute, true},
		{"negative", `{"intent_ttl_minutes": -3}`, 30 * time.Minute, true},
		{"too large", `{"intent_ttl_minutes": 1441}`, 30 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			dir := t.TempDir()
			userPath := filepath.Join(dir, "config.json")
			if err := os.WriteFile(userPath, []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := LoadConfigWithPaths(nil, userPath, filepath.Join(dir, "trusted-project-configs.json"))
			if got := cfg.IntentTTL(); got != tc.want {
				t.Errorf("IntentTTL = %v, want %v", got, tc.want)
			}
			hasDiag := false
			for _, d := range cfg.Diagnostics {
				if strings.Contains(d, "intent_ttl_minutes") {
					hasDiag = true
				}
			}
			if hasDiag != tc.wantDiag {
				t.Errorf("diagnostic present = %v, want %v (%v)", hasDiag, tc.wantDiag, cfg.Diagnostics)
			}
		})
	}
}
