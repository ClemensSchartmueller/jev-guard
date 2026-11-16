package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"jev-guard/internal/accountprofile"
	"jev-guard/pkg/harness"
)

const MaxConfigFileSize = 1 << 20

// Config encapsulates runtime parameters loaded from environment and configuration files.
type Config struct {
	Mode                        string        `json:"mode"`                       // "enforcing" or "audit"
	APIKey                      string        `json:"api_key,omitempty"`          // from TYPESAFE_API_KEY or file
	TypesafeAPIKey              string        `json:"typesafe_api_key,omitempty"` // alias for api_key in config file
	BaseURL                     string        `json:"base_url,omitempty"`         // API endpoint
	Model                       string        `json:"model,omitempty"`            // e.g. "jev-latest"
	Timeout                     time.Duration `json:"-"`
	TimeoutMs                   int           `json:"timeout_ms,omitempty"`
	AuditLogPath                string        `json:"audit_log_path,omitempty"`
	FastpathEnabled             *bool         `json:"fastpath_enabled,omitempty"`          // whether local fastpath filter is active
	ContextAwarenessEnabled     *bool         `json:"context_awareness_enabled,omitempty"` // whether session intent cache and context awareness are active
	IntentTTLMinutes            *int          `json:"intent_ttl_minutes,omitempty"`        // backstop lifetime of a stored prompt intent (1-1440)
	TaintMode                   string        `json:"taint_mode,omitempty"`                // "off", "audit" (default) or "enforce"; user config only
	AntigravityTranscriptIntent *bool         `json:"-"`                                   // read Antigravity prompt intent from the transcript and run the guard that protects it; off by default, user config only
	// AntigravityTranscriptIntentRaw keeps a wrong JSON type from invalidating the whole file, which is what a *bool would do.
	AntigravityTranscriptIntentRaw json.RawMessage    `json:"antigravity_transcript_intent,omitempty"`
	SensitiveFiles                 []string           `json:"sensitive_files,omitempty"`
	TrustedCommands                []string           `json:"trusted_commands,omitempty"`
	Sources                        map[string]string  `json:"-"`
	Diagnostics                    []string           `json:"-"`
	ProjectConfig                  *ProjectConfigInfo `json:"-"`
	UserConfigPath                 string             `json:"-"`
}

// ConfigFileNames specifies the recognized jevguard configuration filenames in order of precedence.
var ConfigFileNames = []string{".jevguard.json", "jevguard.json"}

// DefaultIntentTTLMinutes is the default backstop lifetime of a stored prompt intent.
const DefaultIntentTTLMinutes = 30

// MaxIntentTTLMinutes is the largest accepted intent_ttl_minutes value.
const MaxIntentTTLMinutes = 1440

// Taint modes control what a session tainted by untrusted tool output changes.
const (
	TaintModeOff     = "off"     // PostToolUse records no taint and the gate ignores it
	TaintModeAudit   = "audit"   // record taint and log decisions that enforce would tighten
	TaintModeEnforce = "enforce" // tainted sessions escalate those decisions to ask
)

// DefaultConfig provides fallback defaults for zero-config operation.
func DefaultConfig() *Config {
	enabled := true
	contextAwareness := true
	intentTTL := DefaultIntentTTLMinutes
	transcriptIntent := false
	return &Config{
		Mode:                        "enforcing",
		Timeout:                     1500 * time.Millisecond,
		TimeoutMs:                   1500,
		FastpathEnabled:             &enabled,
		ContextAwarenessEnabled:     &contextAwareness,
		IntentTTLMinutes:            &intentTTL,
		AntigravityTranscriptIntent: &transcriptIntent,
		TaintMode:                   TaintModeAudit,
		SensitiveFiles:              DefaultSensitiveFiles(),
		TrustedCommands:             DefaultTrustedCommands(),
		Sources: map[string]string{
			"mode": "built-in default", "base_url": "built-in default", "api_key": "environment or user config",
			"model": "built-in default", "timeout_ms": "built-in default", "audit_log_path": "built-in default",
			"fastpath_enabled": "built-in default", "context_awareness_enabled": "built-in default",
			"intent_ttl_minutes": "built-in default", "taint_mode": "built-in default", "antigravity_transcript_intent": "built-in default",
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

// IsAntigravityTranscriptIntentEnabled reports whether the user opted in to reading Antigravity
// prompt intent from the conversation transcript. It also turns on the guard that protects the
// transcript from every agent. Off by default.
func (c *Config) IsAntigravityTranscriptIntentEnabled() bool {
	if c.AntigravityTranscriptIntent == nil {
		return false
	}
	return *c.AntigravityTranscriptIntent
}

// IntentTTL returns the configured intent backstop lifetime (defaults to 30 minutes).
func (c *Config) IntentTTL() time.Duration {
	if c.IntentTTLMinutes == nil || *c.IntentTTLMinutes < 1 || *c.IntentTTLMinutes > MaxIntentTTLMinutes {
		return DefaultIntentTTLMinutes * time.Minute
	}
	return time.Duration(*c.IntentTTLMinutes) * time.Minute
}

// EffectiveTaintMode returns the taint mode, treating an empty value as the
// audit default. Without context awareness there is no session to taint, so
// the mode is off.
func (c *Config) EffectiveTaintMode() string {
	if !c.IsContextAwarenessEnabled() {
		return TaintModeOff
	}
	switch c.TaintMode {
	case TaintModeOff, TaintModeEnforce:
		return c.TaintMode
	default:
		return TaintModeAudit
	}
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
		".docker/config.json",
		"kubeconfig",
		".npmrc",
		".yarnrc",
		".pypirc",
		// Repository-local Git config: remote URLs may embed credentials, and writes can set
		// command-executing keys (core.hooksPath, core.fsmonitor, core.sshCommand). See README.
		".git/config",
		".git-credentials",
		".gitconfig",
		".config/git/config",
		".config/git/credentials",
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
	return loadConfigForCallWithPaths(call, UserConfigPath(), TrustRegistryPath())
}

// loadConfigForCallWithPaths is the path-injectable form of LoadConfigForCall. Tests use it to
// exercise call-based discovery without reading the operating system user's configuration.
func loadConfigForCallWithPaths(call *harness.NormalizedToolCall, userConfigPath, trustRegistryPath string) *Config {
	candidates, workspaceRoots := collectCandidates(call)
	if len(candidates) == 0 {
		if cwd, err := os.Getwd(); err == nil && cwd != "" {
			candidates = append(candidates, cwd)
		}
	}
	return LoadConfigWithPathsAndRoots(candidates, workspaceRoots, userConfigPath, trustRegistryPath)
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

// UserConfigPath returns the user-owned policy file path. It deliberately uses the
// system account profile rather than environment variables that a repository or hook process
// can override.
func UserConfigPath() string {
	home := accountprofile.HomeDir()
	if home == "" {
		return ""
	}
	return userConfigPathForHome(home)
}

func userConfigPathForHome(home string) string {
	return filepath.Join(home, ".jevguard", ".jevguard.json")
}

// EnsureUserConfig creates the user-owned configuration on first launch.
// Existing files are checked but never changed, including files created by a
// concurrent launch. An invalid or unsafe path stops startup.
func EnsureUserConfig() error {
	path := UserConfigPath()
	if path == "" {
		return fmt.Errorf("system user home directory is unavailable")
	}
	return ensureUserConfigAt(path)
}

func ensureUserConfigAt(path string) error {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create config directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect config directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config directory must be a directory, not a symlink: %s", dir)
	}
	if _, err := os.Lstat(path); err == nil {
		return validateExistingUserConfig(path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect user config: %w", err)
	}

	defaults := DefaultConfig()
	template := struct {
		Mode                        string   `json:"mode"`
		TimeoutMs                   int      `json:"timeout_ms"`
		FastpathEnabled             bool     `json:"fastpath_enabled"`
		ContextAwarenessEnabled     bool     `json:"context_awareness_enabled"`
		IntentTTLMinutes            int      `json:"intent_ttl_minutes"`
		AntigravityTranscriptIntent bool     `json:"antigravity_transcript_intent"`
		SensitiveFiles              []string `json:"sensitive_files"`
		TrustedCommands             []string `json:"trusted_commands"`
	}{defaults.Mode, defaults.TimeoutMs, defaults.IsFastpathEnabled(), defaults.IsContextAwarenessEnabled(), DefaultIntentTTLMinutes, defaults.IsAntigravityTranscriptIntentEnabled(), defaults.SensitiveFiles, defaults.TrustedCommands}
	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return fmt.Errorf("encode user config: %w", err)
	}
	file, err := os.CreateTemp(dir, ".jevguard-*")
	if err != nil {
		return fmt.Errorf("prepare user config: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write user config: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close user config: %w", err)
	}
	// A hard link publishes the complete file atomically and fails if any path,
	// including a symlink, already occupies the destination.
	if err = os.Link(file.Name(), path); os.IsExist(err) {
		return validateExistingUserConfig(path)
	} else if err != nil {
		return fmt.Errorf("publish user config: %w", err)
	}
	return nil
}

func validateExistingUserConfig(path string) error {
	if err := rejectSymlinkFileOrParent(path); err != nil {
		return err
	}
	data, err := readConfigFile(path)
	if err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return fmt.Errorf("user config must be a JSON object: %s", path)
	}
	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("invalid user config: %w", err)
	}
	return nil
}

// TrustRegistryPath returns the user-owned registry that approves exact project config contents.
func TrustRegistryPath() string {
	home := accountprofile.HomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".jevguard", "trusted-project-configs.json")
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

// ProjectConfigTrust is one approval record in trusted-project-configs.json. It approves the
// config file's exact SHA-256 digest at one location.
//
// A record with Canonical set (what config trust proposes) names the symlink-resolved
// directory and applies only while that path is reached without any symlink or junction,
// checked with pinned, handle-based lookups each time it is used. It then applies to any
// spelling of the same real file and directory. A record without Canonical (written by
// earlier versions, or proposed where pinning is unavailable) applies only to the exact path
// it names, without filesystem checks; see trustRecordsForLookup.
type ProjectConfigTrust struct {
	ProjectRoot string `json:"project_root"`
	ConfigPath  string `json:"config_path"`
	SHA256      string `json:"sha256"`
	Canonical   bool   `json:"canonical,omitempty"`
}

// ProjectConfigInfo describes the project config without exposing user secrets.
type ProjectConfigInfo struct {
	ProjectRoot    string   `json:"project_root"`
	ConfigPath     string   `json:"config_path"`
	SHA256         string   `json:"sha256"`
	SensitiveFiles []string `json:"sensitive_files,omitempty"`
	IgnoredKeys    []string `json:"ignored_keys,omitempty"`
	Trusted        bool     `json:"trusted"`
	TrustIssue     string   `json:"trust_issue,omitempty"`
	// TrustRecord is the exact-spelling record for the inspected path. Computing it needs no
	// filesystem access. config trust prints ProposeTrustRecord's result instead.
	TrustRecord ProjectConfigTrust `json:"trust_record"`
	// TrustMatches lists the registry records, for any digest, that apply to this config
	// file: records without canonical for this exact spelling, and canonical records whose
	// path is reached without a symlink or junction and names this real file and directory.
	// Removing all of them revokes trust.
	TrustMatches []ProjectConfigTrust `json:"trust_matches,omitempty"`
	// TrustAliases lists registry records that name the same config file under another
	// spelling but do not apply to this one: records without canonical, which are bound to
	// their exact spelling, and canonical records whose path goes through a symlink or
	// junction or could not be pinned. It is diagnostic only and never grants trust.
	TrustAliases []ProjectConfigTrust `json:"trust_aliases,omitempty"`
	// TrustAliasCheckSkipped reports that the registry lookups that touch the filesystem
	// (canonical records and the alias scan) did not finish within trustAliasScanTimeout, for
	// example because an entry is on an unreachable network mount. Exact-spelling records
	// without canonical were still honored, but TrustMatches and TrustAliases may be
	// incomplete, and canonical records were treated as not applying (fail closed).
	TrustAliasCheckSkipped bool `json:"trust_alias_check_skipped,omitempty"`

	// file identifies the config file whose bytes were hashed; trust lookups compare
	// registry records against it with os.SameFile.
	file os.FileInfo
	// dir identifies the directory handle that file was opened relative to (see
	// openInspectedConfig), or is nil if that binding could not be established, in which case
	// canonical records never apply. It is not yet known that the inspected spelling still
	// names dir after the read: that check can block on an unreachable path, so every lookup
	// that uses dir repeats it under trustAliasScanTimeout first (verifyInspectedDir).
	dir os.FileInfo
}

type projectTrustRegistry struct {
	Version int                  `json:"version"`
	Entries []ProjectConfigTrust `json:"entries"`
}

// InspectProjectConfig resolves a project config path (or directory), hashes its exact bytes, and
// reports whether the system user has approved that digest. It never changes the trust registry.
func InspectProjectConfig(path string) (*ProjectConfigInfo, error) {
	return inspectProjectConfigWithRegistry(path, TrustRegistryPath())
}

// inspectProjectConfigWithRegistry is the registry-injectable form of InspectProjectConfig.
// Tests use it so trust lookups never read the operating system user's registry.
func inspectProjectConfigWithRegistry(path, trustRegistryPath string) (*ProjectConfigInfo, error) {
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
	registry, err := readTrustRegistry(trustRegistryPath)
	if err != nil {
		info.TrustIssue = describeTrustRegistryError(err)
		return info, nil
	}
	info.TrustMatches, info.TrustAliases, info.TrustAliasCheckSkipped = boundedTrustScan(registry.Entries, info, false, true)
	for _, match := range info.TrustMatches {
		if match.SHA256 == info.SHA256 {
			info.Trusted = true
		}
	}
	return info, nil
}

// trustAliasScanTimeout bounds every registry lookup that touches the filesystem, in both
// the hook and the interactive commands, and the trust proposal in config trust. A lookup on
// a stale network mount can block until the OS gives up, and Go cannot cancel it, so callers
// stop waiting after this deadline.
var trustAliasScanTimeout = 500 * time.Millisecond

// Filesystem seams for trust lookups. Tests replace them to simulate unreachable paths, to
// change the filesystem between the steps of a pinned lookup, or to count calls.
var (
	// trustAliasStat and trustAliasLstat serve the diagnostic alias scan only.
	trustAliasStat  = os.Stat
	trustAliasLstat = os.Lstat
	// trustInspectedDirStat checks, after the read, that the inspected directory spelling
	// still names the directory handle the config was read from (verifyInspectedDir).
	trustInspectedDirStat = os.Stat
	// trustPinRecorded is the pinned lookup of a canonical record's path.
	trustPinRecorded pinFunc = pinRecordedConfig
	// trustPinStep, when set, runs before each open of a pinned lookup and of the bound
	// open of the inspected config, and before the inspected spelling is checked again.
	trustPinStep func(path string)
	// trustEvalSymlinks resolves the directory that config trust proposes, in the exact
	// spelling the pinned lookup requires (resolveTrustProposalRoot). Only
	// ProposeTrustRecord calls it; the hook path never proposes a record.
	trustEvalSymlinks = resolveTrustProposalRoot
)

// trustLookup holds the filesystem lookups used on registry entry paths, captured once per
// bounded scan so a goroutine that outlives its deadline never reads the package variables.
type trustLookup struct {
	stat, lstat func(string) (os.FileInfo, error)
	dirStat     func(string) (os.FileInfo, error)
	pinRecorded pinFunc
	step        func(string)
}

func currentTrustStep() func(string) {
	if step := trustPinStep; step != nil {
		return step
	}
	return func(string) {}
}

func currentTrustLookup() trustLookup {
	return trustLookup{
		stat:        trustAliasStat,
		lstat:       trustAliasLstat,
		dirStat:     trustInspectedDirStat,
		pinRecorded: trustPinRecorded,
		step:        currentTrustStep(),
	}
}

// trustTarget is the immutable part of a ProjectConfigInfo that trust lookups read. A
// bounded scan works on a copy so it never reads fields the caller may still be writing.
type trustTarget struct {
	projectRoot, configPath string
	file, dir               os.FileInfo
}

func newTrustTarget(info *ProjectConfigInfo) trustTarget {
	return trustTarget{projectRoot: info.ProjectRoot, configPath: info.ConfigPath, file: info.file, dir: info.dir}
}

// verifyInspectedDir returns target with dir cleared unless the inspected directory
// spelling still names the directory handle the config was read from. Inspection reads the
// config through that handle first; checking the spelling afterwards closes the window in
// which a link in the spelling pointed at the directory only while it was opened. The stat
// can block on an unreachable path, so it runs only inside a bounded lookup, and only when
// a lookup actually needs dir (exact records never do).
func verifyInspectedDir(target trustTarget, lookup trustLookup) trustTarget {
	if target.dir == nil {
		return target
	}
	lookup.step(target.projectRoot)
	if now, err := lookup.dirStat(target.projectRoot); err != nil || !os.SameFile(now, target.dir) {
		target.dir = nil
	}
	return target
}

// boundedTrustScan finds the registry entries that apply to info (matches) and, with
// wantAliases, the entries for another spelling of the same file that do not apply
// (aliases). Exact-spelling records without canonical need no filesystem access and are
// always returned. Canonical records and the alias scan run in one goroutine under
// trustAliasScanTimeout; on timeout they are dropped, so only the exact records count (fail
// closed), aliases are empty, and skipped is true. The goroutine works on copies of its
// inputs and reports through a buffered channel, so a blocked scan writes no shared state
// after the caller has returned.
func boundedTrustScan(entries []ProjectConfigTrust, info *ProjectConfigInfo, currentDigestOnly, wantAliases bool) (matches, aliases []ProjectConfigTrust, skipped bool) {
	exact, canonical, others := trustRecordsForLookup(entries, info, currentDigestOnly)
	if currentDigestOnly && len(exact) > 0 {
		// The hook already has its answer without touching the filesystem.
		return exact, nil, false
	}
	if len(canonical) == 0 && (!wantAliases || !others) {
		return exact, nil, false
	}
	target := newTrustTarget(info)
	lookup := currentTrustLookup()
	entries = append([]ProjectConfigTrust(nil), entries...)
	type scanResult struct{ matches, aliases []ProjectConfigTrust }
	result := make(chan scanResult, 1)
	go func() {
		var r scanResult
		if len(canonical) > 0 {
			r.matches = canonicalTrustRecords(canonical, verifyInspectedDir(target, lookup), lookup)
		}
		if wantAliases {
			r.aliases = trustAliasRecords(entries, target, lookup)
		}
		result <- r
	}()
	timer := time.NewTimer(trustAliasScanTimeout)
	defer timer.Stop()
	select {
	case r := <-result:
		matches = append(exact, r.matches...)
		for _, alias := range r.aliases {
			if !containsTrustRecord(matches, alias) {
				aliases = append(aliases, alias)
			}
		}
		return matches, aliases, false
	case <-timer.C:
		return exact, nil, true
	}
}

func containsTrustRecord(records []ProjectConfigTrust, record ProjectConfigTrust) bool {
	for _, candidate := range records {
		if candidate == record {
			return true
		}
	}
	return false
}

// trustRecordsForLookup partitions the registry entries that may approve info's config file.
// With currentDigestOnly, only entries for info's exact digest are considered.
//
// exact holds records without canonical that name the inspected spelling exactly. They apply
// with no filesystem access, as they always have, so records written by earlier versions keep
// working. This is a compatibility exception: such a record is bound to a path string, not to
// a directory, so if a directory on that path is later replaced by a symlink or junction to
// another directory with byte-identical config, the record still applies there. config trust
// proposes canonical records, which do not have this weakness.
//
// canonical holds every canonical record, including one that names the inspected spelling
// exactly; canonicalTrustRecords checks them with pinned lookups. others reports whether any
// other entry exists, which only the diagnostic alias scan looks at.
func trustRecordsForLookup(entries []ProjectConfigTrust, info *ProjectConfigInfo, currentDigestOnly bool) (exact, canonical []ProjectConfigTrust, others bool) {
	for _, entry := range entries {
		if currentDigestOnly && entry.SHA256 != info.SHA256 {
			continue
		}
		switch {
		case entry.Canonical:
			canonical = append(canonical, entry)
		case entry.ProjectRoot == info.ProjectRoot && entry.ConfigPath == info.ConfigPath:
			exact = append(exact, entry)
		default:
			others = true
		}
	}
	return exact, canonical, others
}

// trustRecordShapeValid reports whether a record names an absolute, clean config path
// directly inside its project root, under the same file name (ignoring case) as target.
func trustRecordShapeValid(record ProjectConfigTrust, target trustTarget) bool {
	return filepath.IsAbs(record.ConfigPath) && filepath.Clean(record.ConfigPath) == record.ConfigPath &&
		record.ProjectRoot == filepath.Dir(record.ConfigPath) &&
		strings.EqualFold(filepath.Base(record.ConfigPath), filepath.Base(target.configPath))
}

// canonicalTrustRecords returns the canonical records that apply to target. A canonical
// record applies when a pinned lookup of its path (trustPinRecorded) reaches, without any
// symlink or junction, a directory and a regular config file whose handle identities are the
// file that was hashed and the directory handle that file was opened from during inspection
// (openInspectedConfig). Comparing directories too excludes hard links from other
// directories. Every identity comes from an open handle, so swapping a path component for a
// link between steps cannot move trust to another directory; see the platform files for
// what each operating system pins. The lookups can block on unreachable paths, so callers
// run this through a bounded goroutine.
func canonicalTrustRecords(entries []ProjectConfigTrust, target trustTarget, lookup trustLookup) []ProjectConfigTrust {
	if len(entries) == 0 || target.file == nil || target.dir == nil {
		return nil
	}
	var matches []ProjectConfigTrust
	for _, entry := range entries {
		if !entry.Canonical || !trustRecordShapeValid(entry, target) {
			continue
		}
		pinned, err := lookup.pinRecorded(entry.ProjectRoot, filepath.Base(entry.ConfigPath), lookup.step)
		if err == nil && os.SameFile(pinned.file, target.file) && os.SameFile(pinned.dir, target.dir) {
			matches = append(matches, entry)
		}
	}
	return matches
}

// trustAliasRecords returns registry records that name the same file in the same directory as
// target under another spelling, or that are canonical, judged by plain stat calls. It is
// diagnostic only: boundedTrustScan drops the records that apply, and the rest are reported
// so a user can see why an approval appears to have no effect. Records whose paths no longer
// resolve, and records that could never be approved as written, are skipped.
func trustAliasRecords(entries []ProjectConfigTrust, target trustTarget, lookup trustLookup) []ProjectConfigTrust {
	if target.file == nil {
		return nil
	}
	wantDir, err := lookup.stat(target.projectRoot)
	if err != nil {
		return nil
	}
	var aliases []ProjectConfigTrust
	for _, entry := range entries {
		if (!entry.Canonical && entry.ConfigPath == target.configPath) || !trustRecordShapeValid(entry, target) {
			continue
		}
		// The approved path must name a regular file, as config trust requires; comparing
		// both the file and its directory excludes hard links from other directories.
		if linkInfo, err := lookup.lstat(entry.ConfigPath); err != nil || !linkInfo.Mode().IsRegular() {
			continue
		}
		file, err := lookup.stat(entry.ConfigPath)
		if err != nil || !os.SameFile(file, target.file) {
			continue
		}
		dir, err := lookup.stat(entry.ProjectRoot)
		if err != nil || !os.SameFile(dir, wantDir) {
			continue
		}
		aliases = append(aliases, entry)
	}
	return aliases
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
	data, _, err := readConfigFileWithInfo(path)
	return data, err
}

// readConfigFileWithInfo reads a regular config file and returns the identity of the opened
// file, so callers can bind decisions to the file whose bytes they read.
func readConfigFileWithInfo(path string) ([]byte, os.FileInfo, error) {
	file, err := openRegularConfigFile(path)
	if err != nil {
		return nil, nil, err
	}
	return readOpenConfigFile(file, path)
}

// readOpenConfigFile reads a regular config file from an open handle, closes it, and returns
// the handle's identity.
func readOpenConfigFile(file *os.File, path string) ([]byte, os.FileInfo, error) {
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("configuration file must be a regular file: %s", path)
	}
	if openedInfo.Size() > MaxConfigFileSize {
		return nil, nil, fmt.Errorf("configuration file exceeds the %d byte limit: %s", MaxConfigFileSize, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigFileSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxConfigFileSize {
		return nil, nil, fmt.Errorf("configuration file exceeds the %d byte limit: %s", MaxConfigFileSize, path)
	}
	return data, openedInfo, nil
}

func inspectProjectConfigFile(path string) (*ProjectConfigInfo, error) {
	canonical, err := canonicalProjectConfigPath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve project config: %w", err)
	}
	data, file, dir, err := readInspectedConfig(canonical)
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
	info := &ProjectConfigInfo{
		ProjectRoot:    filepath.Clean(root),
		ConfigPath:     canonical,
		SHA256:         hex.EncodeToString(digest[:]),
		SensitiveFiles: sensitiveFiles,
		IgnoredKeys:    ignored,
		file:           file,
		dir:            dir,
	}
	info.TrustRecord = ProjectConfigTrust{ProjectRoot: info.ProjectRoot, ConfigPath: info.ConfigPath, SHA256: info.SHA256}
	return info, nil
}

// readInspectedConfig reads the config at path, a clean absolute path, through
// openInspectedConfig, so the bytes that are hashed come from a file opened relative to the
// directory handle whose identity is returned as dir. That the inspected directory spelling
// still names dir after the read is checked later, under the lookup deadline, by every
// lookup that uses dir (verifyInspectedDir). If the bound open is not possible
// (an unsupported platform, or a directory that cannot be opened), the file is read by its
// path as before and dir is nil. Without dir, canonical records do not apply (fail closed),
// while records for the exact spelling still do.
func readInspectedConfig(path string) (data []byte, file, dir os.FileInfo, err error) {
	root, name := filepath.Dir(path), filepath.Base(path)
	step := currentTrustStep()
	if opened, dirInfo, openErr := openInspectedConfig(root, name, step); openErr == nil {
		data, file, err = readOpenConfigFile(opened, path)
		if err != nil {
			return nil, nil, nil, err
		}
		return data, file, dirInfo, nil
	}
	data, file, err = readConfigFileWithInfo(path)
	return data, file, nil, err
}

// ProposeTrustRecord returns the record config trust prints for info. It proposes a
// canonical record for the symlink-resolved directory, but only after verifying it with the
// same pinned lookup that the hook uses, so the proposal applies when added. If that is not
// possible (no pinning on this platform, a path that cannot be resolved or pinned, or a
// lookup that does not finish within trustAliasScanTimeout), it falls back to a record for
// the exact inspected spelling without canonical, and note says why.
//
// Only config trust calls this. The hook path never proposes a record.
func ProposeTrustRecord(info *ProjectConfigInfo) (record ProjectConfigTrust, note string) {
	exact := ProjectConfigTrust{ProjectRoot: info.ProjectRoot, ConfigPath: info.ConfigPath, SHA256: info.SHA256}
	if !trustPinningSupported {
		return exact, "this platform cannot check trust records without following links, so the record is bound to this exact path"
	}
	target := newTrustTarget(info)
	digest := info.SHA256
	lookup := currentTrustLookup()
	evalSymlinks := trustEvalSymlinks
	type proposal struct {
		record ProjectConfigTrust
		err    error
	}
	result := make(chan proposal, 1)
	go func() {
		record, err := canonicalTrustProposal(verifyInspectedDir(target, lookup), digest, lookup, evalSymlinks)
		result <- proposal{record, err}
	}()
	timer := time.NewTimer(trustAliasScanTimeout)
	defer timer.Stop()
	select {
	case p := <-result:
		if p.err != nil {
			return exact, p.err.Error() + ", so the record is bound to this exact path"
		}
		return p.record, ""
	case <-timer.C:
		return exact, "resolving the real directory did not finish in time, so the record is bound to this exact path"
	}
}

func canonicalTrustProposal(target trustTarget, digest string, lookup trustLookup, evalSymlinks func(string) (string, error)) (ProjectConfigTrust, error) {
	resolved, err := evalSymlinks(target.projectRoot)
	if err != nil || !filepath.IsAbs(resolved) {
		return ProjectConfigTrust{}, fmt.Errorf("the real directory of %s could not be resolved", target.projectRoot)
	}
	resolved = filepath.Clean(resolved)
	record := ProjectConfigTrust{
		ProjectRoot: resolved,
		ConfigPath:  filepath.Join(resolved, filepath.Base(target.configPath)),
		SHA256:      digest,
		Canonical:   true,
	}
	if len(canonicalTrustRecords([]ProjectConfigTrust{record}, target, lookup)) != 1 {
		return ProjectConfigTrust{}, fmt.Errorf("the real directory %s could not be verified without following a link", resolved)
	}
	return record, nil
}

func describeTrustRegistryError(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
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
	if fileCfg.IntentTTLMinutes != nil {
		if minutes := *fileCfg.IntentTTLMinutes; minutes >= 1 && minutes <= MaxIntentTTLMinutes {
			cfg.IntentTTLMinutes = &minutes
			cfg.Sources["intent_ttl_minutes"] = "user config"
		} else {
			cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("user config intent_ttl_minutes ignored: expected an integer from 1 to %d, using default %d", MaxIntentTTLMinutes, DefaultIntentTTLMinutes))
		}
	}
	if fileCfg.TaintMode != "" {
		switch mode := strings.ToLower(strings.TrimSpace(fileCfg.TaintMode)); mode {
		case TaintModeOff, TaintModeAudit, TaintModeEnforce:
			cfg.TaintMode = mode
			cfg.Sources["taint_mode"] = "user config"
		default:
			// An unrecognized value fails toward the stricter mode.
			cfg.TaintMode = TaintModeEnforce
			cfg.Sources["taint_mode"] = "safe fallback after invalid user config"
			cfg.Diagnostics = append(cfg.Diagnostics, "user config taint_mode ignored: expected off, audit or enforce, using enforce")
		}
	}
	if raw := bytes.TrimSpace(fileCfg.AntigravityTranscriptIntentRaw); len(raw) > 0 && string(raw) != "null" {
		var enabled bool
		if err := json.Unmarshal(raw, &enabled); err == nil {
			cfg.AntigravityTranscriptIntent = &enabled
			cfg.Sources["antigravity_transcript_intent"] = "user config"
		} else {
			enabled = false
			cfg.AntigravityTranscriptIntent = &enabled
			cfg.Sources["antigravity_transcript_intent"] = "safe fallback after invalid user config"
			cfg.Diagnostics = append(cfg.Diagnostics, "user config antigravity_transcript_intent ignored: expected true or false, leaving it off")
		}
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
			registry, err := readTrustRegistry(registryPath)
			if err != nil {
				info.TrustIssue = describeTrustRegistryError(err)
				cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("project config at %s ignored: %s", canonical, info.TrustIssue))
				continue
			}
			matches, _, skipped := boundedTrustScan(registry.Entries, info, true, false)
			info.Trusted = len(matches) > 0
			info.TrustAliasCheckSkipped = skipped
			if !info.Trusted {
				reason := ""
				if skipped {
					reason = " (the registry lookup for other spellings of this path did not finish in time; an entry may point to an unreachable location)"
				}
				cfg.Diagnostics = append(cfg.Diagnostics, fmt.Sprintf("project config at %s is not trusted%s; built-in defaults and any valid user settings remain active", canonical, reason))
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
	Taint      string           `json:"taint,omitempty"`
	// Model is the semantic model that answered, as reported by the provider.
	// Empty when no semantic evaluation produced a response.
	Model string `json:"model,omitempty"`
}

// LogAudit writes evaluation results to the configured audit file when active.
func (c *Config) LogAudit(call *harness.NormalizedToolCall, res *harness.EvaluationResult) error {
	return c.LogAuditWithModel(call, res, "")
}

// LogAuditWithModel is LogAudit that also records the semantic model that
// answered; an empty model is omitted from the entry.
func (c *Config) LogAuditWithModel(call *harness.NormalizedToolCall, res *harness.EvaluationResult, model string) error {
	if c == nil || c.AuditLogPath == "" {
		return nil
	}
	if call == nil && res == nil {
		return nil
	}

	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Model:     model,
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
		entry.Taint = res.TaintNote
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
