package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"jev-guard/pkg/harness"
)

// Config encapsulates runtime parameters loaded from environment and configuration files.
type Config struct {
	Mode             string        `json:"mode"`                         // "enforcing" or "audit"
	APIKey           string        `json:"api_key,omitempty"`            // from TYPESAFE_API_KEY or file
	TypesafeAPIKey   string        `json:"typesafe_api_key,omitempty"`   // alias for api_key in config file
	BaseURL          string        `json:"base_url,omitempty"`           // API endpoint
	Model            string        `json:"model,omitempty"`              // e.g. "jev-latest"
	Timeout          time.Duration `json:"-"`
	TimeoutMs        int           `json:"timeout_ms,omitempty"`
	AuditLogPath     string        `json:"audit_log_path,omitempty"`
	SensitiveFiles   []string      `json:"sensitive_files,omitempty"`
	TrustedCommands  []string      `json:"trusted_commands,omitempty"`
}

// DefaultConfig provides fallback defaults for zero-config operation.
func DefaultConfig() *Config {
	return &Config{
		Mode:      "enforcing",
		Timeout:   1500 * time.Millisecond,
		TimeoutMs: 1500,
	}
}

// LoadConfig merges environment variables and optional .jevguard.json into a unified Config.
func LoadConfig(searchDir string) *Config {
	cfg := DefaultConfig()
	loadConfigFile(cfg, searchDir)
	loadEnvironment(cfg)
	return cfg
}

func loadConfigFile(cfg *Config, dir string) {
	if dir == "" {
		return
	}
	filePath := filepath.Join(dir, ".jevguard.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err == nil {
		if fileCfg.Mode != "" {
			cfg.Mode = fileCfg.Mode
		}
		if fileCfg.APIKey != "" {
			cfg.APIKey = fileCfg.APIKey
		} else if fileCfg.TypesafeAPIKey != "" {
			cfg.APIKey = fileCfg.TypesafeAPIKey
		}
		if fileCfg.BaseURL != "" {
			cfg.BaseURL = fileCfg.BaseURL
		}
		if fileCfg.Model != "" {
			cfg.Model = fileCfg.Model
		}
		if fileCfg.TimeoutMs > 0 {
			cfg.TimeoutMs = fileCfg.TimeoutMs
			cfg.Timeout = time.Duration(fileCfg.TimeoutMs) * time.Millisecond
		}
		if fileCfg.AuditLogPath != "" {
			cfg.AuditLogPath = fileCfg.AuditLogPath
		}
		cfg.SensitiveFiles = append(cfg.SensitiveFiles, fileCfg.SensitiveFiles...)
		cfg.TrustedCommands = append(cfg.TrustedCommands, fileCfg.TrustedCommands...)
	}
}

func loadEnvironment(cfg *Config) {
	if key := os.Getenv("TYPESAFE_API_KEY"); key != "" {
		cfg.APIKey = key
	}
	if url := os.Getenv("TYPESAFE_API_URL"); url != "" {
		cfg.BaseURL = url
	}
	if model := os.Getenv("TYPESAFE_MODEL"); model != "" {
		cfg.Model = model
	}
	if mode := os.Getenv("JEV_GUARD_MODE"); mode != "" {
		cfg.Mode = mode
	}
	if timeoutStr := os.Getenv("JEV_GUARD_TIMEOUT_MS"); timeoutStr != "" {
		if ms, err := strconv.Atoi(timeoutStr); err == nil && ms > 0 {
			cfg.TimeoutMs = ms
			cfg.Timeout = time.Duration(ms) * time.Millisecond
		}
	}
}

// AuditEntry records tool evaluations for security auditing and verification.
type AuditEntry struct {
	Timestamp  string                   `json:"timestamp"`
	ToolName   string                   `json:"tool_name"`
	Command    string                   `json:"command,omitempty"`
	TargetPath string                   `json:"target_path,omitempty"`
	Decision   harness.Decision         `json:"decision"`
	Reason     string                   `json:"reason"`
	Source     string                   `json:"source"`
	Confidence float64                  `json:"confidence"`
}

// LogAudit writes evaluation results to the configured audit file when active.
func (c *Config) LogAudit(call *harness.NormalizedToolCall, res *harness.EvaluationResult) error {
	if c.AuditLogPath == "" {
		return nil
	}

	entry := AuditEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ToolName:   call.ToolName,
		Command:    call.Command,
		TargetPath: call.TargetPath,
		Decision:   res.Decision,
		Reason:     res.Reason,
		Source:     res.Source,
		Confidence: res.Confidence,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	f, err := os.OpenFile(c.AuditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log file %s: %w", c.AuditLogPath, err)
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}
