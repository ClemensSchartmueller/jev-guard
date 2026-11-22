package fastpath

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"jev-guard/pkg/harness"
)

// searchWorkspace returns a temp workspace holding a source file and a dummy .env.
func searchWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{"main.go": "package main", ".env": "DUMMY=1"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func claudeSearchCall(t *testing.T, root, tool string, args map[string]interface{}) *harness.NormalizedToolCall {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{"tool_name": tool, "cwd": root, "tool_input": args})
	if err != nil {
		t.Fatal(err)
	}
	call, err := harness.ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return call
}

func antigravitySearchCall(t *testing.T, root, tool string, args map[string]interface{}) *harness.NormalizedToolCall {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{
		"toolCall":       map[string]interface{}{"name": tool, "args": args},
		"workspacePaths": []string{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	call, err := harness.ParsePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return call
}

func isTrustedAllow(result *harness.EvaluationResult) bool {
	return result != nil && result.Decision == harness.DecisionAllow
}

// Invariant 1: a file filter that could select a sensitive file never gets a local ALLOW.
func TestSearchFilterThatCanSelectSensitiveFileIsNotAllowed(t *testing.T) {
	root := searchWorkspace(t)
	cases := map[string]*harness.NormalizedToolCall{
		"Grep glob .env*":           claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": ".env*"}),
		"Grep glob .en?":            claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": ".en?"}),
		"Grep glob bracket":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": ".[e]nv"}),
		"Grep glob star":            claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "*"}),
		"Grep glob any pem":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "**/*.pem"}),
		"Grep glob brace":           claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "*.{env,key}"}),
		"Grep glob json":            claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "*.json"}),
		"Grep glob dir wildcard":    claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": ".ss?/*.go"}),
		"Grep glob upper case":      claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": ".ENV*"}),
		"Grep type json":            claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "type": "json"}),
		"Grep type sh":              claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "type": "sh"}),
		"Grep type unknown":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "type": "secrets"}),
		"Grep glob list space":      claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "*.go .en?"}),
		"Grep glob list comma":      claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "*.go,*"}),
		"Grep no filter":            claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root}),
		"Grep exclude only":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "!*.md"}),
		"Grep missing path":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": filepath.Join(root, "nope")}),
		"grep_search no Includes":   antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "KEY"}),
		"grep_search Excludes only": antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "KEY", "Excludes": []interface{}{"*.md"}}),
		"Grep glob non-string":      claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": []interface{}{"*.go", 7}}),
		"Glob pattern .env*":        claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": ".env*", "path": root}),
		"Glob pattern everything":   claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "**/*", "path": root}),
		"Glob pattern id_rsa":       claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "**/id_*", "path": root}),
		"grep_search Includes env":  antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "KEY", "Includes": []interface{}{"*.go", ".env*"}}),
		"grep_search Includes star": antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "KEY", "Includes": []interface{}{"*"}}),
		"find_by_name Pattern":      antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Pattern": "*.pem"}),
		"find_by_name Extensions":   antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Pattern": "*", "Extensions": []interface{}{"env"}}),
		"find_by_name ext only":     antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Extensions": []interface{}{"key"}}),
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if result := NewDefaultFilter().Evaluate(call); isTrustedAllow(result) {
				t.Fatalf("filter that can select a sensitive file must not be allowed, got %+v", result)
			}
		})
	}
}

// A filter that names a sensitive file is treated like a sensitive target: ASK without intent,
// and also reported to the taint gate.
func TestSearchFilterNamingSensitiveFileAsks(t *testing.T) {
	root := searchWorkspace(t)
	for name, call := range map[string]*harness.NormalizedToolCall{
		"Grep glob .env*":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": ".env*"}),
		"Glob pattern pem":        claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "**/*.pem", "path": root}),
		"grep_search Includes":    antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "KEY", "Includes": []interface{}{"*.{env,go}"}}),
		"find_by_name Extensions": antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Extensions": []interface{}{"key"}}),
	} {
		t.Run(name, func(t *testing.T) {
			result := NewDefaultFilter().Evaluate(call)
			if result == nil || result.Decision != harness.DecisionAsk || result.Source != "fastpath_sensitive" {
				t.Fatalf("expected fastpath_sensitive ASK, got %+v", result)
			}
			if NewDefaultFilter().SensitiveReason(call) == "" {
				t.Fatal("SensitiveReason must report the filter")
			}
		})
	}
}

// Invariant 2: a pattern that leaves the searched directory is boundary-checked.
func TestSearchPatternOutsideWorkspaceIsNotAllowed(t *testing.T) {
	root := searchWorkspace(t)
	outside := filepath.ToSlash(filepath.Join(t.TempDir(), "*.go"))
	cases := map[string]*harness.NormalizedToolCall{
		"Glob absolute outside":     claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": outside, "path": root}),
		"Glob root":                 claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "/*.go", "path": root}),
		"Glob parent":               claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "../*.go", "path": root}),
		"Glob nested parent":        claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "src/../../*.go", "path": root}),
		"Glob home":                 claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "~/*.go", "path": root}),
		"Grep glob parent":          claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "KEY", "path": root, "glob": "../**/*.go"}),
		"grep_search Includes abs":  antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "KEY", "Includes": []interface{}{outside}}),
		"find_by_name Pattern home": antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Pattern": "~/*.go"}),
	}
	if runtime.GOOS == "windows" {
		cases["Glob drive"] = claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": `C:\*.go`, "path": root})
		cases["Glob backslash parent"] = claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": `..\*.go`, "path": root})
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if result := NewDefaultFilter().Evaluate(call); isTrustedAllow(result) {
				t.Fatalf("pattern outside the workspace must not be allowed, got %+v", result)
			}
		})
	}
}

// Invariants 3 and 4: narrow filters, contained absolute patterns and Grep's content pattern
// keep the fast-path ALLOW.
func TestNarrowSearchFiltersStayAllowed(t *testing.T) {
	root := searchWorkspace(t)
	inside := filepath.ToSlash(filepath.Join(root, "src")) + "/**/*.go"
	cases := map[string]*harness.NormalizedToolCall{
		"Grep glob go":              claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": root, "glob": "*.go"}),
		"Grep glob ts tree":         claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": root, "glob": "src/**/*.ts"}),
		"Grep glob brace":           claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": root, "glob": "*.{ts,tsx}"}),
		"Grep glob list":            claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": root, "glob": "*.go *.md,*.ts"}),
		"Grep glob and exclusion":   claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": root, "glob": "*.go,!*_test.go"}),
		"Grep type go":              claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": root, "type": "go"}),
		"Grep content regex .env":   claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": ".env", "path": root, "glob": "*.go"}),
		"Grep single file":          claudeSearchCall(t, root, "Grep", map[string]interface{}{"pattern": "func", "path": filepath.Join(root, "main.go")}),
		"grep_search single file":   antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": filepath.Join(root, "main.go"), "Query": "func"}),
		"Glob md":                   claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": "**/*.md", "path": root}),
		"Glob absolute inside":      claudeSearchCall(t, root, "Glob", map[string]interface{}{"pattern": inside, "path": root}),
		"grep_search Includes go":   antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "func", "Includes": []interface{}{"*.go", "*.md"}}),
		"grep_search Excludes env":  antigravitySearchCall(t, root, "grep_search", map[string]interface{}{"SearchPath": root, "Query": "func", "Includes": []interface{}{"*.go"}, "Excludes": []interface{}{".env*"}}),
		"find_by_name Pattern go":   antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Pattern": "*_test.go"}),
		"find_by_name Extensions":   antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Pattern": "*", "Extensions": []interface{}{"go", "ts"}}),
		"find_by_name Type is kind": antigravitySearchCall(t, root, "find_by_name", map[string]interface{}{"SearchDirectory": root, "Pattern": "*.go", "Type": "file"}),
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			result := NewDefaultFilter().Evaluate(call)
			if result == nil || result.Decision != harness.DecisionAllow || result.Source != "fastpath_trusted" {
				t.Fatalf("expected trusted ALLOW, got %+v", result)
			}
		})
	}
}
