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
	if len(cfg.SensitiveFiles) != 1 || cfg.SensitiveFiles[0] != ".secrets.yaml" {
		t.Errorf("expected sensitive file .secrets.yaml, got %v", cfg.SensitiveFiles)
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
