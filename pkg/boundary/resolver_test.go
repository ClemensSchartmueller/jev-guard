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

