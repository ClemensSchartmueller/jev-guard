package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"jev-guard/pkg/harness"
)

const MaxConfigFileSize = 1 << 20

// Config encapsulates runtime parameters loaded from environment and configuration files.
type Config struct {
	Mode                    string             `json:"mode"`                       // "enforcing" or "audit"
	APIKey                  string             `json:"api_key,omitempty"`          // from TYPESAFE_API_KEY or file
	TypesafeAPIKey          string             `json:"typesafe_api_key,omitempty"` // alias for api_key in config file
	BaseURL                 string             `json:"base_url,omitempty"`         // API endpoint
	Model                   string             `json:"model,omitempty"`            // e.g. "jev-latest"
	Timeout                 time.Duration      `json:"-"`
	TimeoutMs               int                `json:"timeout_ms,omitempty"`
	AuditLogPath            string             `json:"audit_log_path,omitempty"`
	FastpathEnabled         *bool              `json:"fastpath_enabled,omitempty"`          // whether local fastpath filter is active
	ContextAwarenessEnabled *bool              `json:"context_awareness_enabled,omitempty"` // whether session intent cache and context awareness are active
	SensitiveFiles          []string           `json:"sensitive_files,omitempty"`
	TrustedCommands         []string           `json:"trusted_commands,omitempty"`
	Sources                 map[string]string  `json:"-"`
	Diagnostics             []string           `json:"-"`
	ProjectConfig           *ProjectConfigInfo `json:"-"`
	UserConfigPath          string             `json:"-"`
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
		Sources: map[string]string{
			"mode": "built-in default", "base_url": "built-in default", "api_key": "environment or user config",
			"model": "built-in default", "timeout_ms": "built-in default", "audit_log_path": "built-in default",
			"fastpath_enabled": "built-in default", "context_awareness_enabled": "built-in default",
			"sensitive_files": "built-in defaults", "trusted_commands": "built-in defaults",
		},
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
		"id_ecdsa",
		"id_dsa",
		".ssh/",
		".aws/",
		".kube/",
		"kubeconfig",
		".npmrc",
		".yarnrc",
		".pypirc",
		".git-credentials",
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
	candidates, workspaceRoots := collectCandidates(call)
	if len(candidates) == 0 {
		if cwd, err := os.Getwd(); err == nil && cwd != "" {
			candidates = append(candidates, cwd)
		}
	}
	return LoadConfigWithPathsAndRoots(candidates, workspaceRoots, UserConfigPath(), TrustRegistryPath())
}

func collectCandidates(call *harness.NormalizedToolCall) (candidates, workspaceRoots []string) {
	if call != nil {
		if call.Cwd != "" {
			candidates = append(candidates, call.Cwd)
		}
		for _, root := range call.WorkspaceRoots {
			if root != "" {
				candidates = append(candidates, root)
				workspaceRoots = append(workspaceRoots, root)
			}
		}
	}
	return candidates, workspaceRoots
}

// LoadConfig loads defaults, user-owned policy, explicitly trusted project additions, and credentials.
// Project configuration is never applied unless its exact bytes are present in the user trust registry.
func LoadConfig(candidateDirs ...string) *Config {
	return LoadConfigWithPaths(candidateDirs, UserConfigPath(), TrustRegistryPath())
}

// LoadConfigWithPaths is the path-injectable loader used by tests and embedding applications.
// Production callers should use LoadConfig so paths always come from the operating system user profile.
func LoadConfigWithPaths(candidateDirs []string, userConfigPath, trustRegistryPath string) *Config {
	return LoadConfigWithPathsAndRoots(candidateDirs, nil, userConfigPath, trustRegistryPath)
}

// LoadConfigWithPathsAndRoots loads config using explicit workspace roots as ancestor bounds.
// Without declared roots, candidates use their nearest .git root, or the candidate itself.
func LoadConfigWithPathsAndRoots(candidateDirs, workspaceRoots []string, userConfigPath, trustRegistryPath string) *Config {
	cfg := DefaultConfig()
	cfg.UserConfigPath = userConfigPath
	if cfg.Sources == nil {
		cfg.Sources = make(map[string]string)
	}
	applyUserConfig(cfg, userConfigPath)
	applyTrustedProjectConfig(cfg, candidateDirs, workspaceRoots, trustRegistryPath)
	loadEnvironment(cfg)
	return cfg
}

// UserConfigPath returns the selected user-owned policy file path. It deliberately uses the
// system account profile rather than environment variables that a repository or hook process
// can override. The legacy path is used only when the canonical file is absent.
func UserConfigPath() string {
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.HomeDir) == "" {
		return ""
	}
	return userConfigPathForHome(current.HomeDir)
}

func userConfigPathForHome(home string) string {
	canonical := filepath.Join(home, ".jevguard.json")
	if _, err := os.Lstat(canonical); os.IsNotExist(err) {
		legacy := filepath.Join(home, ".jevguard", "config.json")
		if _, legacyErr := os.Lstat(legacy); !os.IsNotExist(legacyErr) {
			return legacy
		}
	}
	return canonical
}

// TrustRegistryPath returns the user-owned registry that approves exact project config contents.
func TrustRegistryPath() string {
	current, err := user.Current()
	if err != nil || strings.TrimSpace(current.HomeDir) == "" {
		return ""
	}
	return filepath.Join(current.HomeDir, ".jevguard", "trusted-project-configs.json")
}

// FindProjectConfigInDirectory searches a directory up to its bounded project root.
func FindProjectConfigInDirectory(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	for _, searchDir := range projectSearchDirectories([]string{dir}, nil) {
		for _, name := range ConfigFileNames {
			path := filepath.Join(searchDir, name)
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
				return path
			}
		}
	}
	return ""
}

// ProjectConfigTrust is one exact approval record in trusted-project-configs.json.
type ProjectConfigTrust struct {
	ProjectRoot string `json:"project_root"`
	ConfigPath  string `json:"config_path"`
	SHA256      string `json:"sha256"`
}

// ProjectConfigInfo describes the project config without exposing user secrets.
type ProjectConfigInfo struct {
	ProjectRoot    string             `json:"project_root"`
	ConfigPath     string             `json:"config_path"`
	SHA256         string             `json:"sha256"`
	SensitiveFiles []string           `json:"sensitive_files,omitempty"`
	IgnoredKeys    []string           `json:"ignored_keys,omitempty"`
	Trusted        bool               `json:"trusted"`
	TrustIssue     string             `json:"trust_issue,omitempty"`
	TrustRecord    ProjectConfigTrust `json:"trust_record"`
}

type projectTrustRegistry struct {
	Version int                  `json:"version"`
	Entries []ProjectConfigTrust `json:"entries"`
}

// InspectProjectConfig resolves a project config path (or directory), hashes its exact bytes, and
// reports whether the system user has approved that digest. It never changes the trust registry.
func InspectProjectConfig(path string) (*ProjectConfigInfo, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("project config path is required")
	}
	resolved, err := resolveProjectConfigPath(path)
	if err != nil {
		return nil, err
	}
	info, err := inspectProjectConfigFile(resolved)
	if err != nil {
		return nil, err
	}
	info.Trusted, err = trustRecordExists(TrustRegistryPath(), info.TrustRecord)
	if err != nil {
		info.TrustIssue = describeTrustRegistryError(err)
	}
	return info, nil
}

func resolveProjectConfigPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve project config path: %w", err)
	}
	stat, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("read project config path: %w", err)
	}
	if !stat.Mode().IsRegular() && !stat.IsDir() {
		return "", fmt.Errorf("project config must be a regular file: %s", abs)
	}
	if stat.IsDir() {
		for _, name := range ConfigFileNames {
			candidate := filepath.Join(abs, name)
			if candidateInfo, err := os.Lstat(candidate); err == nil && candidateInfo.Mode().IsRegular() {
				abs = candidate
				break
			}
		}
		if stat, err = os.Lstat(abs); err != nil || !stat.Mode().IsRegular() {
			return "", fmt.Errorf("no project config found in %s", path)
		}
	}
	return canonicalProjectConfigPath(abs)
}

func canonicalProjectConfigPath(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("project config must be a regular, non-symlink file: %s", path)
	}
	if info.Size() > MaxConfigFileSize {
		return "", fmt.Errorf("project config exceeds the %d byte limit: %s", MaxConfigFileSize, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func readConfigFile(path string) ([]byte, error) {
	file, err := openRegularConfigFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("configuration file must be a regular file: %s", path)
	}
	if openedInfo.Size() > MaxConfigFileSize {
		return nil, fmt.Errorf("configuration file exceeds the %d byte limit: %s", MaxConfigFileSize, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxConfigFileSize {
		return nil, fmt.Errorf("configuration file exceeds the %d byte limit: %s", MaxConfigFileSize, path)
	}
	return data, nil
}

func inspectProjectConfigFile(path string) (*ProjectConfigInfo, error) {
	canonical, err := canonicalProjectConfigPath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve project config: %w", err)
	}
	data, err := readConfigFile(canonical)
	if err != nil {
		return nil, fmt.Errorf("read project config: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("parse project config: %w", err)
	}
	root, err := filepath.Abs(filepath.Dir(canonical))
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	ignored := make([]string, 0, len(fields))
	for key := range fields {
		if key != "sensitive_files" {
			ignored = append(ignored, key)
		}
	}
	sort.Strings(ignored)
	var sensitiveFiles []string
	if raw, ok := fields["sensitive_files"]; ok {
		if err := json.Unmarshal(raw, &sensitiveFiles); err != nil {
			return nil, fmt.Errorf("project config sensitive_files must be an array of strings: %w", err)
		}
	}
	digest := sha256.Sum256(data)
	record := ProjectConfigTrust{
		ProjectRoot: filepath.Clean(root),
		ConfigPath:  canonical,
		SHA256:      hex.EncodeToString(digest[:]),
	}
	return &ProjectConfigInfo{
		ProjectRoot:    record.ProjectRoot,
		ConfigPath:     record.ConfigPath,
		SHA256:         record.SHA256,
		SensitiveFiles: sensitiveFiles,
		IgnoredKeys:    ignored,
		TrustRecord:    record,
	}, nil
}

func trustRecordExists(registryPath string, expected ProjectConfigTrust) (bool, error) {
	registry, err := readTrustRegistry(registryPath)
	if err != nil {
		return false, err
	}
	for _, entry := range registry.Entries {
		if entry == expected {
			return true, nil
		}
	}
	return false, nil
}

func describeTrustRegistryError(err error) string {
	if os.IsNotExist(err) {
		return "trust registry does not exist"
	}
	return fmt.Sprintf("trust registry unavailable or invalid: %v", err)
}

func readTrustRegistry(path string) (*projectTrustRegistry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("trust registry path unavailable")
	}
	if err := rejectSymlinkFileOrParent(path); err != nil {
		return nil, err
	}
	data, err := readConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust registry: %w", err)
	}
	var registry projectTrustRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("parse trust registry: %w", err)
	}
	if registry.Version != 1 {
		return nil, fmt.Errorf("unsupported trust registry version %d", registry.Version)
	}
	return &registry, nil
}

func rejectSymlinkFileOrParent(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(abs)
	if info, statErr := os.Lstat(parent); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("user configuration directory must not be a symlink: %s", parent)
	}
	if info, statErr := os.Lstat(abs); statErr == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("user configuration file must be a regular file: %s", abs)
	} else if statErr == nil && info.Size() > MaxConfigFileSize {
		return fmt.Errorf("user configuration file exceeds the %d byte limit: %s", MaxConfigFileSize, abs)
	}
	return nil
}

func applyUserConfig(cfg *Config, filePath string) {
	if strings.TrimSpace(filePath) == "" {
		cfg.Diagnostics = append(cfg.Diagnostics, "user config path unavailable; using enforcing built-in defaults")
		return
	}
	if err := rejectSymlinkFileOrParent(filePath); err != nil {
		if !os.IsNotExist(err) {
			cfg.Diagnostics = append(cfg.Diagnostics, "user config ignored: "+err.Error())
		}
		return
	}
	data, err := readConfigFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("user config ignored: %v", err))
		}
		return
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err == nil {
		applyUserFileConfig(cfg, &fileCfg, filepath.Dir(filePath))
	} else {
		cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("user config ignored because it is invalid JSON: %v", err))
	}
}

func applyUserFileConfig(cfg *Config, fileCfg *Config, configDir string) {
	invalid := false
	if fileCfg.Mode != "" {
		mode := strings.ToLower(strings.TrimSpace(fileCfg.Mode))
		if mode == "enforcing" || mode == "audit" {
			cfg.Mode = mode
			cfg.Sources["mode"] = "user config"
		} else {
			cfg.Diagnostics = append(cfg.Diagnostics, "user config mode ignored: expected enforcing or audit")
			invalid = true
		}
	}
	if fileCfg.APIKey != "" {
		cfg.APIKey = fileCfg.APIKey
		cfg.Sources["api_key"] = "user config"
	} else if fileCfg.TypesafeAPIKey != "" {
		cfg.APIKey = fileCfg.TypesafeAPIKey
		cfg.Sources["api_key"] = "user config"
	}
	if fileCfg.BaseURL != "" {
		if ValidateBaseURL(fileCfg.BaseURL) == nil {
			cfg.BaseURL = strings.TrimSpace(fileCfg.BaseURL)
			cfg.Sources["base_url"] = "user config"
		} else {
			cfg.Diagnostics = append(cfg.Diagnostics, "user config base_url ignored: expected an HTTPS URL or loopback HTTP URL without credentials")
			invalid = true
		}
	}
	if fileCfg.Model != "" {
		cfg.Model = fileCfg.Model
		cfg.Sources["model"] = "user config"
	}
	if fileCfg.TimeoutMs > 0 {
		cfg.TimeoutMs = fileCfg.TimeoutMs
		cfg.Timeout = time.Duration(fileCfg.TimeoutMs) * time.Millisecond
		cfg.Sources["timeout_ms"] = "user config"
	}
	if fileCfg.AuditLogPath != "" {
		cfg.AuditLogPath = anchorRelativePath(fileCfg.AuditLogPath, configDir)
		cfg.Sources["audit_log_path"] = "user config"
	}
	if fileCfg.FastpathEnabled != nil {
		cfg.FastpathEnabled = fileCfg.FastpathEnabled
		cfg.Sources["fastpath_enabled"] = "user config"
	}
	if fileCfg.ContextAwarenessEnabled != nil {
		cfg.ContextAwarenessEnabled = fileCfg.ContextAwarenessEnabled
		cfg.Sources["context_awareness_enabled"] = "user config"
	}
	if len(fileCfg.SensitiveFiles) > 0 {
		cfg.SensitiveFiles = mergeUniqueStrings(DefaultSensitiveFiles(), fileCfg.SensitiveFiles)
		cfg.Sources["sensitive_files"] = "user config and built-in defaults"
	}
	if len(fileCfg.TrustedCommands) > 0 {
		cfg.TrustedCommands = mergeUniqueStrings(DefaultTrustedCommands(), fileCfg.TrustedCommands)
		cfg.Sources["trusted_commands"] = "user config and built-in defaults"
	}
	if invalid {
		cfg.Mode = "enforcing"
		cfg.Sources["mode"] = "safe fallback after invalid user config"
	}
}

func anchorRelativePath(targetPath, baseDir string) string {
	if filepath.IsAbs(targetPath) || baseDir == "" {
		return targetPath
	}
	return filepath.Join(baseDir, targetPath)
}

// ValidateBaseURL permits HTTPS endpoints and HTTP endpoints bound to loopback for local servers.
// Credentials, fragments, and queries are rejected because they can leak through logs or redirects.
func ValidateBaseURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed == nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return fmt.Errorf("URL must have a host and cannot contain credentials, a query, or a fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return nil
	}
	if scheme == "http" {
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		ip := net.ParseIP(host)
		if host == "localhost" || ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("URL must use HTTPS, except for loopback HTTP endpoints")
}

func applyTrustedProjectConfig(cfg *Config, candidateDirs, workspaceRoots []string, registryPath string) {
	seen := make(map[string]bool)
	for _, searchDir := range projectSearchDirectories(candidateDirs, workspaceRoots) {
		for _, name := range ConfigFileNames {
			path := filepath.Join(searchDir, name)
			canonical, err := canonicalProjectConfigPath(path)
			if err != nil {
				if !os.IsNotExist(err) {
					cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("project config at %s ignored: %v", path, err))
				}
				continue
			}
			if seen[canonical] {
				continue
			}
			seen[canonical] = true
			info, err := inspectProjectConfigFile(canonical)
			if err != nil {
				cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("project config at %s ignored: %v", path, err))
				continue
			}
			info.Trusted, err = trustRecordExists(registryPath, info.TrustRecord)
			if err != nil {
				info.TrustIssue = describeTrustRegistryError(err)
				cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("project config at %s ignored: %s", canonical, info.TrustIssue))
				continue
			}
			if !info.Trusted {
				cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("project config at %s is not trusted; built-in defaults and any valid user settings remain active", canonical))
				continue
			}
			cfg.ProjectConfig = info
			if len(info.SensitiveFiles) > 0 {
				cfg.SensitiveFiles = mergeUniqueStrings(cfg.SensitiveFiles, info.SensitiveFiles)
				cfg.Sources["sensitive_files"] = "user config, trusted project config, and built-in defaults"
			}
			if len(info.IgnoredKeys) > 0 {
				cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("trusted project config at %s ignored unsupported keys: %s", canonical, strings.Join(info.IgnoredKeys, ", ")))
			}
			return
		}
	}
}

func projectSearchDirectories(candidateDirs, workspaceRoots []string) []string {
	var roots []string
	for _, root := range workspaceRoots {
		if abs, err := filepath.Abs(root); err == nil {
			roots = append(roots, filepath.Clean(abs))
		}
	}

	var directories []string
	seen := make(map[string]bool)
	for _, candidate := range candidateDirs {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		curr := filepath.Clean(abs)
		if info, statErr := os.Stat(curr); statErr == nil && !info.IsDir() {
			curr = filepath.Dir(curr)
		}
		boundary := closestWorkspaceRoot(curr, roots)
		if boundary == "" {
			boundary = nearestGitRoot(curr)
		}
		if boundary == "" {
			boundary = curr
		}
		if _, within := pathWithinRoot(boundary, curr); !within {
			boundary = curr
		}
		for {
			if !seen[curr] {
				directories = append(directories, curr)
				seen[curr] = true
			}
			if curr == boundary {
				break
			}
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}
	return directories
}

func closestWorkspaceRoot(candidate string, roots []string) string {
	closest := ""
	closestDistance := int(^uint(0) >> 1)
	for _, root := range roots {
		relative, within := pathWithinRoot(root, candidate)
		if !within {
			continue
		}
		distance := 0
		if relative != "." {
			distance = strings.Count(relative, string(filepath.Separator)) + 1
		}
		if distance < closestDistance {
			closest = root
			closestDistance = distance
		}
	}
	return closest
}

func pathWithinRoot(root, path string) (string, bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	if relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func nearestGitRoot(startDir string) string {
	curr := filepath.Clean(startDir)
	for {
		if _, err := os.Lstat(filepath.Join(curr, ".git")); err == nil {
			return curr
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			return ""
		}
		curr = parent
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
		cfg.Sources["api_key"] = "TYPESAFE_API_KEY environment variable"
	}
}

// AuditEntry records tool evaluations for security auditing and verification.
type AuditEntry struct {
	Timestamp  string           `json:"timestamp"`
	ToolName   string           `json:"tool_name"`
	Command    string           `json:"command,omitempty"`
	TargetPath string           `json:"target_path,omitempty"`
	Decision   harness.Decision `json:"decision"`
	Reason     string           `json:"reason"`
	Source     string           `json:"source"`
	Confidence float64          `json:"confidence"`
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
