package config

import (
	"os"
	"path/filepath"
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
}

func TestConfig_LoadConfigFile(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(tempDir, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfig(tempDir)
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
	tempDir, err := os.MkdirTemp("", "jev-config-key-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{
		"typesafe_api_key": "my-secret-jev-key"
	}`
	if err := os.WriteFile(filepath.Join(tempDir, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfig(tempDir)
	if cfg.APIKey != "my-secret-jev-key" {
		t.Errorf("expected APIKey 'my-secret-jev-key', got %s", cfg.APIKey)
	}
}

func TestConfig_LoadConfig_AncestorHierarchy(t *testing.T) {
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

	// Load config from the deep child directory
	cfg := LoadConfig(subChild)
	if cfg.APIKey != "ancestor-key" {
		t.Errorf("expected APIKey 'ancestor-key' from ancestor traversal, got %s", cfg.APIKey)
	}
	if cfg.Mode != "audit" {
		t.Errorf("expected Mode 'audit', got %s", cfg.Mode)
	}
}

func TestConfig_LoadConfig_AlternateFilename(t *testing.T) {
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

	cfg := LoadConfig(tempDir)
	if cfg.APIKey != "alt-filename-key" {
		t.Errorf("expected APIKey 'alt-filename-key', got %s", cfg.APIKey)
	}
}

func TestConfig_LoadConfigForCall_WorkspaceRootsFallback(t *testing.T) {
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

	cfg := LoadConfigForCall(call)
	if cfg.APIKey != "ws-key" {
		t.Errorf("expected APIKey 'ws-key' from WorkspaceRoots fallback, got %s", cfg.APIKey)
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
	if err := os.WriteFile(filepath.Join(tempDir, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfig(tempDir)
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

func TestConfig_FastpathEnabled_FromEnv(t *testing.T) {
	os.Setenv("JEV_GUARD_FASTPATH_ENABLED", "0")
	defer os.Unsetenv("JEV_GUARD_FASTPATH_ENABLED")

	cfg := DefaultConfig()
	loadEnvironment(cfg)
	if cfg.IsFastpathEnabled() {
		t.Errorf("expected FastpathEnabled to be false when JEV_GUARD_FASTPATH_ENABLED=0")
	}
}

func TestConfig_AuditLogPath_AnchoredToConfigDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-config-audit-anchor-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{
		"audit_log_path": ".custom_audit.log"
	}`
	if err := os.WriteFile(filepath.Join(tempDir, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfig(tempDir)
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
	tempDir, err := os.MkdirTemp("", "jev-config-ctx-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configJSON := `{"context_awareness_enabled": false}`
	if err := os.WriteFile(filepath.Join(tempDir, ".jevguard.json"), []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := LoadConfig(tempDir)
	if cfg.IsContextAwarenessEnabled() {
		t.Errorf("expected ContextAwarenessEnabled to be false when set in config file")
	}
}

func TestConfig_ContextAwarenessEnabled_FromEnv(t *testing.T) {
	os.Setenv("JEV_GUARD_CONTEXT_AWARENESS_ENABLED", "0")
	defer os.Unsetenv("JEV_GUARD_CONTEXT_AWARENESS_ENABLED")

	cfg := DefaultConfig()
	loadEnvironment(cfg)
	if cfg.IsContextAwarenessEnabled() {
		t.Errorf("expected ContextAwarenessEnabled to be false when JEV_GUARD_CONTEXT_AWARENESS_ENABLED=0")
	}
}
