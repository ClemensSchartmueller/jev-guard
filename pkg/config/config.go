package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	FastpathEnabled         *bool         `json:"fastpath_enabled,omitempty"`          // whether local fastpath filter is active
	ContextAwarenessEnabled *bool         `json:"context_awareness_enabled,omitempty"` // whether session intent cache and context awareness are active
	SensitiveFiles          []string      `json:"sensitive_files,omitempty"`
	TrustedCommands         []string      `json:"trusted_commands,omitempty"`
}

// ConfigFileNames specifies the recognized jevguard configuration filenames in order of precedence.
var ConfigFileNames = []string{".jevguard.json", "jevguard.json"}

// DefaultConfig provides fallback defaults for zero-config operation.
func DefaultConfig() *Config {
	enabled := true
	contextAwareness := true
	return &Config{
		Mode:                    "enforcing",
		Timeout:                 1500 * time.Millisecond,
		TimeoutMs:               1500,
		FastpathEnabled:         &enabled,
		ContextAwarenessEnabled: &contextAwareness,
		SensitiveFiles:          DefaultSensitiveFiles(),
		TrustedCommands:         DefaultTrustedCommands(),
	}
}

// IsFastpathEnabled reports whether local fastpath evaluation is enabled (defaults to true).
func (c *Config) IsFastpathEnabled() bool {
	if c.FastpathEnabled == nil {
		return true
	}
	return *c.FastpathEnabled
}

// IsContextAwarenessEnabled reports whether session intent context-awareness is enabled (defaults to true).
func (c *Config) IsContextAwarenessEnabled() bool {
	if c.ContextAwarenessEnabled == nil {
		return true
	}
	return *c.ContextAwarenessEnabled
}

// DefaultSensitiveFiles returns standard sensitive filename fragments protected by default.
func DefaultSensitiveFiles() []string {
	return []string{
		".env",
		"id_rsa",
		"id_ed25519",
		".ssh/",
		".aws/",
		"credentials.json",
		".pem",
		".key",
		"serviceaccount.json",
		".jevguard.json",
		"jevguard.json",
		".jevguard.log",
	}
}

// DefaultTrustedCommands returns baseline read-only inspection commands cached for zero latency.
func DefaultTrustedCommands() []string {
	return []string{
		"git status",
		"git diff",
		"git log",
		"git branch",
		"git show",
		"ls",
		"dir",
		"pwd",
		"echo",
		"whoami",
		"which",
		"where.exe",
		"node -v",
		"go version",
		"python --version",
	}
}

// LoadConfigForCall collects candidate directories from a normalized tool call and loads configuration.
func LoadConfigForCall(call *harness.NormalizedToolCall) *Config {
	candidates := collectCandidates(call)
	return LoadConfig(candidates...)
}

func collectCandidates(call *harness.NormalizedToolCall) []string {
	var candidates []string
	if call != nil {
		if call.Cwd != "" {
			candidates = append(candidates, call.Cwd)
		}
		for _, root := range call.WorkspaceRoots {
			if root != "" {
				candidates = append(candidates, root)
			}
		}
	}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		candidates = append(candidates, cwd)
	}
	return candidates
}

// LoadConfig merges environment variables and optional jevguard configuration into a unified Config.
// It searches candidate directories and their ancestor trees for .jevguard.json or jevguard.json.
func LoadConfig(candidateDirs ...string) *Config {
	cfg := DefaultConfig()
	if filePath := FindConfigFile(candidateDirs...); filePath != "" {
		loadConfigFile(cfg, filePath)
	}
	loadEnvironment(cfg)
	return cfg
}

// FindConfigFile searches candidate directories and their parent hierarchies for a jevguard config file.
func FindConfigFile(candidateDirs ...string) string {
	for _, dir := range candidateDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if filePath := searchDirectoryHierarchy(dir); filePath != "" {
			return filePath
		}
	}
	return ""
}

func searchDirectoryHierarchy(startDir string) string {
	absDir, err := filepath.Abs(startDir)
	if err != nil {
		absDir = filepath.Clean(startDir)
	}

	curr := absDir
	for {
		for _, name := range ConfigFileNames {
			target := filepath.Join(curr, name)
			if info, err := os.Stat(target); err == nil && !info.IsDir() {
				return target
			}
		}

		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}
	return ""
}

func loadConfigFile(cfg *Config, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err == nil {
		applyFileConfig(cfg, &fileCfg, filepath.Dir(filePath))
	}
}

func applyFileConfig(cfg *Config, fileCfg *Config, configDir string) {
	if fileCfg.Mode != "" {
		cfg.Mode = fileCfg.Mode
	}
	applyFileAPIKeys(cfg, fileCfg)
	applyFileNetworkingAndLogging(cfg, fileCfg, configDir)
	applyFilePolicies(cfg, fileCfg)
}

func applyFileAPIKeys(cfg *Config, fileCfg *Config) {
	if fileCfg.APIKey != "" {
		cfg.APIKey = fileCfg.APIKey
	} else if fileCfg.TypesafeAPIKey != "" {
		cfg.APIKey = fileCfg.TypesafeAPIKey
	}
}

func applyFileNetworkingAndLogging(cfg *Config, fileCfg *Config, configDir string) {
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
		cfg.AuditLogPath = anchorRelativePath(fileCfg.AuditLogPath, configDir)
	}
}

func anchorRelativePath(targetPath, baseDir string) string {
	if filepath.IsAbs(targetPath) || baseDir == "" {
		return targetPath
	}
	return filepath.Join(baseDir, targetPath)
}

func applyFilePolicies(cfg *Config, fileCfg *Config) {
	if fileCfg.FastpathEnabled != nil {
		cfg.FastpathEnabled = fileCfg.FastpathEnabled
	}
	if fileCfg.ContextAwarenessEnabled != nil {
		cfg.ContextAwarenessEnabled = fileCfg.ContextAwarenessEnabled
	}
	if len(fileCfg.SensitiveFiles) > 0 {
		cfg.SensitiveFiles = mergeUniqueStrings(cfg.SensitiveFiles, fileCfg.SensitiveFiles)
	}
	if len(fileCfg.TrustedCommands) > 0 {
		cfg.TrustedCommands = mergeUniqueStrings(cfg.TrustedCommands, fileCfg.TrustedCommands)
	}
}

func mergeUniqueStrings(base []string, additional []string) []string {
	seen := make(map[string]bool, len(base)+len(additional))
	res := make([]string, 0, len(base)+len(additional))
	for _, s := range base {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	for _, s := range additional {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
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
	if val := os.Getenv("JEV_GUARD_FASTPATH_ENABLED"); val != "" {
		lower := strings.ToLower(strings.TrimSpace(val))
		enabled := lower != "false" && lower != "0" && lower != "no" && lower != "off"
		cfg.FastpathEnabled = &enabled
	}
	if val := os.Getenv("JEV_GUARD_CONTEXT_AWARENESS_ENABLED"); val != "" {
		lower := strings.ToLower(strings.TrimSpace(val))
		enabled := lower != "false" && lower != "0" && lower != "no" && lower != "off"
		cfg.ContextAwarenessEnabled = &enabled
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
	if c == nil || c.AuditLogPath == "" {
		return nil
	}
	if call == nil && res == nil {
		return nil
	}

	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	if call != nil {
		entry.ToolName = call.ToolName
		entry.Command = call.Command
		entry.TargetPath = call.TargetPath
	}
	if res != nil {
		entry.Decision = res.Decision
		entry.Reason = res.Reason
		entry.Source = res.Source
		entry.Confidence = res.Confidence
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	targetPath := c.resolveAuditLogPath(call)
	dir := filepath.Dir(targetPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create audit log directory %s: %w", dir, err)
		}
	}

	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log file %s: %w", targetPath, err)
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}

func (c *Config) resolveAuditLogPath(call *harness.NormalizedToolCall) string {
	if filepath.IsAbs(c.AuditLogPath) {
		return c.AuditLogPath
	}
	if call != nil {
		if call.Cwd != "" {
			return filepath.Join(call.Cwd, c.AuditLogPath)
		}
		if len(call.WorkspaceRoots) > 0 && call.WorkspaceRoots[0] != "" {
			return filepath.Join(call.WorkspaceRoots[0], c.AuditLogPath)
		}
	}
	return c.AuditLogPath
}
