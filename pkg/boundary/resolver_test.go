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
