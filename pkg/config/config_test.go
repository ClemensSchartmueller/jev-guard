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
