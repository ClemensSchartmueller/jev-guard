package boundary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPathContained_InsideWorkspace(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-boundary-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	resolver, err := NewResolver([]string{tempDir}, tempDir)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	subFile := filepath.Join(tempDir, "src", "index.ts")
	contained, err := resolver.IsPathContained(subFile, tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contained {
		t.Errorf("expected %s to be contained in %s", subFile, tempDir)
	}
}

func TestIsPathContained_OutsideWorkspace(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-boundary-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	resolver, err := NewResolver([]string{tempDir}, tempDir)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	outsidePath := filepath.Join(tempDir, "..", "outside-file.txt")
	contained, err := resolver.IsPathContained(outsidePath, tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contained {
		t.Errorf("expected %s to be recognized as outside workspace", outsidePath)
	}
}

func TestIsPathContained_RelativeEscapes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "jev-boundary-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	resolver, err := NewResolver([]string{tempDir}, tempDir)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	escapeRelative := filepath.Join("..", "..", "system.ini")
	contained, err := resolver.IsPathContained(escapeRelative, tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contained {
		t.Errorf("expected relative escape %s to be outside workspace", escapeRelative)
	}
}

func TestIsPathContained_SymlinkOutsideWorkspace(t *testing.T) {
	tempWorkspace, err := os.MkdirTemp("", "jev-ws-*")
	if err != nil {
		t.Fatalf("failed to create temp ws: %v", err)
	}
	defer os.RemoveAll(tempWorkspace)

	tempOutside, err := os.MkdirTemp("", "jev-outside-*")
	if err != nil {
		t.Fatalf("failed to create temp outside: %v", err)
	}
	defer os.RemoveAll(tempOutside)

	symlinkPath := filepath.Join(tempWorkspace, "symlink_dir")
	if err := os.Symlink(tempOutside, symlinkPath); err != nil {
		t.Skipf("skipping symlink test on current environment: %v", err)
	}

	resolver, err := NewResolver([]string{tempWorkspace}, tempWorkspace)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	targetViaSymlink := filepath.Join(symlinkPath, "secret.txt")
	contained, err := resolver.IsPathContained(targetViaSymlink, tempWorkspace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contained {
		t.Errorf("expected symlink target %s pointing to %s to be recognized as outside workspace", targetViaSymlink, tempOutside)
	}
}

func TestIsSubPathForOS(t *testing.T) {
	// Linux: case sensitivity preserved
	if isSubPathForOS("/workspace/Project", "/workspace/project/main.go", "linux") {
		t.Errorf("expected Linux path comparison to be case-sensitive")
	}
	if !isSubPathForOS("/workspace/Project", "/workspace/Project/main.go", "linux") {
		t.Errorf("expected matching case path to be subpath on Linux")
	}

	// Windows: case-insensitive
	if !isSubPathForOS("C:\\Workspace\\Project", "c:\\workspace\\project\\main.go", "windows") {
		t.Errorf("expected Windows path comparison to be case-insensitive")
	}

	// Sibling prefix evasion check
	if isSubPathForOS("/workspace/app", "/workspace/app-secrets/key.pem", "linux") {
		t.Errorf("sibling directory app-secrets should not be considered inside app")
	}
}

