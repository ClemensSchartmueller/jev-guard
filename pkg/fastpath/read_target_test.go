package fastpath

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"jev-guard/pkg/harness"
)

func TestTrustedReadRequiresUnambiguousCanonicalTarget(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "README.md")
	if err := os.WriteFile(inside, []byte("read me"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "private.txt")

	for _, tc := range []struct {
		name  string
		tool  string
		args  map[string]interface{}
		allow bool
	}{
		{"Read canonical", "Read", map[string]interface{}{"file_path": inside}, true},
		{"View canonical", "View", map[string]interface{}{"file_path": inside}, true},
		{"view_file canonical", "view_file", map[string]interface{}{"AbsolutePath": inside}, true},
		{"read_file path", "read_file", map[string]interface{}{"path": inside}, true},
		{"Read decoy and outside canonical", "Read", map[string]interface{}{"TargetFile": inside, "file_path": outside}, false},
		{"Read decoy and sensitive canonical", "Read", map[string]interface{}{"TargetFile": inside, "file_path": "/etc/shadow"}, false},
		{"Read conflicting contained paths", "Read", map[string]interface{}{"TargetFile": inside, "file_path": filepath.Join(root, "other.txt")}, false},
		{"Read missing canonical", "Read", map[string]interface{}{"TargetFile": inside}, false},
		{"Read duplicate alias", "Read", map[string]interface{}{"TargetFile": inside, "file_path": inside}, false},
		{"read_file conflicting aliases", "read_file", map[string]interface{}{"TargetFile": inside, "path": outside}, false},
		{"view_file decoy", "view_file", map[string]interface{}{"TargetFile": inside, "AbsolutePath": outside}, false},
		{"list_dir conflicting targets", "list_dir", map[string]interface{}{"DirectoryPath": inside, "path": outside}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]interface{}{"tool_name": tc.tool, "cwd": root, "tool_input": tc.args})
			if err != nil {
				t.Fatal(err)
			}
			call, err := harness.ParsePayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			result := NewDefaultFilter().Evaluate(call)
			if tc.allow {
				if result == nil || result.Decision != harness.DecisionAllow || result.Source != "fastpath_trusted" {
					t.Fatalf("expected trusted ALLOW, got %+v", result)
				}
			} else if result == nil || result.Decision == harness.DecisionAllow {
				t.Fatalf("ambiguous or noncanonical read must not be allowed, got %+v", result)
			}
		})
	}
}

func TestTrustedAntigravityReadResourceRequiresSingleURI(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "README.md")
	if err := os.WriteFile(inside, []byte("read me"), 0o600); err != nil {
		t.Fatal(err)
	}
	uri := "file://" + inside
	for _, tc := range []struct {
		name  string
		args  map[string]interface{}
		allow bool
	}{
		{"canonical Uri", map[string]interface{}{"Uri": uri}, true},
		{"ambiguous URI and path", map[string]interface{}{"TargetFile": inside, "Uri": "file:///etc/shadow"}, false},
		{"missing URI", map[string]interface{}{"TargetFile": inside}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]interface{}{
				"toolCall":       map[string]interface{}{"name": "read_resource", "args": tc.args},
				"workspacePaths": []string{root},
			})
			if err != nil {
				t.Fatal(err)
			}
			call, err := harness.ParsePayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			result := NewDefaultFilter().Evaluate(call)
			if tc.allow {
				if result == nil || result.Decision != harness.DecisionAllow || result.Source != "fastpath_trusted" {
					t.Fatalf("expected trusted ALLOW, got %+v", result)
				}
			} else if result == nil || result.Decision == harness.DecisionAllow {
				t.Fatalf("ambiguous or noncanonical read must not be allowed, got %+v", result)
			}
		})
	}
}
