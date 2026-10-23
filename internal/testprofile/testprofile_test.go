package testprofile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiffDetectsProfileChanges(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, ".jevguard.json")
	missing := filepath.Join(dir, "trusted-project-configs.json")
	if err := os.WriteFile(existing, []byte(`{"mode":"enforcing"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	watched := []string{existing, missing}
	before := snapshot(watched)
	if changed := diff(before, snapshot(watched)); len(changed) != 0 {
		t.Fatalf("unchanged files reported as changed: %v", changed)
	}

	if err := os.WriteFile(missing, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed := diff(before, snapshot(watched)); len(changed) != 1 {
		t.Fatalf("expected a created registry to be reported, got %v", changed)
	}

	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(existing, later, later); err != nil {
		t.Fatal(err)
	}
	if changed := diff(before, snapshot(watched)); len(changed) != 1 {
		t.Fatalf("expected a rewritten user config to be reported, got %v", changed)
	}
}
