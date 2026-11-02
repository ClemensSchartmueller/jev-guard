package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jev-guard/pkg/harness"
)

func TestTaintMode_DefaultIsAudit(t *testing.T) {
	cfg := DefaultConfig()
	if got := cfg.EffectiveTaintMode(); got != TaintModeAudit {
		t.Fatalf("default taint mode = %q, want %q", got, TaintModeAudit)
	}
	off := false
	cfg.ContextAwarenessEnabled = &off
	if got := cfg.EffectiveTaintMode(); got != TaintModeOff {
		t.Fatalf("taint mode without context awareness = %q, want off", got)
	}
}

func TestTaintMode_UserConfig(t *testing.T) {
	clearConfigEnvironment(t)
	for _, tc := range []struct {
		value, want string
		wantDiag    bool
	}{
		{"off", TaintModeOff, false},
		{"audit", TaintModeAudit, false},
		{" Enforce ", TaintModeEnforce, false},
		{"strict", TaintModeEnforce, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			root := t.TempDir()
			userConfigPath := filepath.Join(root, "user", "config.json")
			writeConfig(t, userConfigPath, `{"taint_mode":"`+tc.value+`"}`)
			cfg := LoadConfigWithPaths([]string{root}, userConfigPath, filepath.Join(root, "registry.json"))
			if got := cfg.EffectiveTaintMode(); got != tc.want {
				t.Errorf("taint mode = %q, want %q", got, tc.want)
			}
			hasDiag := strings.Contains(strings.Join(cfg.Diagnostics, "\n"), "taint_mode")
			if hasDiag != tc.wantDiag {
				t.Errorf("taint_mode diagnostic = %t, want %t (%v)", hasDiag, tc.wantDiag, cfg.Diagnostics)
			}
		})
	}
}

// A project config, even a trusted one, must not be able to weaken taint handling.
func TestTaintMode_TrustedProjectConfigCannotChangeIt(t *testing.T) {
	clearConfigEnvironment(t)
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	projectConfigPath := filepath.Join(repo, ".jevguard.json")
	writeConfig(t, projectConfigPath, `{"taint_mode":"off","sensitive_files":[".project-secret"]}`)
	userConfigPath := filepath.Join(root, "user", "config.json")
	trustRegistryPath := filepath.Join(root, "user", "trusted-project-configs.json")
	writeConfig(t, userConfigPath, `{"taint_mode":"enforce"}`)

	info, err := inspectProjectConfigIsolated(t, projectConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(makeTrustRegistryFixture(t, info))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRegistryPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfigWithPaths([]string{repo}, userConfigPath, trustRegistryPath)
	if cfg.ProjectConfig == nil || !cfg.ProjectConfig.Trusted {
		t.Fatal("expected the project config to be trusted")
	}
	if got := cfg.EffectiveTaintMode(); got != TaintModeEnforce {
		t.Fatalf("trusted project config changed taint mode to %q", got)
	}
	if !containsConfigValue(info.IgnoredKeys, "taint_mode") {
		t.Errorf("taint_mode should be reported as an ignored project key, got %v", info.IgnoredKeys)
	}
}

func TestLogAudit_RecordsTaintNote(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	cfg := &Config{AuditLogPath: logPath}
	res := &harness.EvaluationResult{Decision: harness.DecisionAllow, Source: "fastpath_trusted", TaintNote: "audit: enforce would ask"}
	if err := cfg.LogAudit(&harness.NormalizedToolCall{ToolName: "Bash"}, res); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Taint != res.TaintNote {
		t.Fatalf("audit taint = %q, want %q", entry.Taint, res.TaintNote)
	}
}
