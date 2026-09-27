package config

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularConfigFileReadsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".jevguard.json")
	const content = `{"mode":"enforcing"}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	file, err := openRegularConfigFile(path)
	if err != nil {
		t.Fatalf("open regular config: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read regular config: %v", err)
	}
	if string(data) != content {
		t.Fatalf("read unexpected config contents %q", data)
	}
}

func TestOpenRegularConfigFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, ".jevguard.json")
	if err := os.WriteFile(target, []byte(`{"mode":"audit"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable on this host: %v", err)
	}

	file, err := openRegularConfigFile(link)
	if file != nil {
		_ = file.Close()
	}
	if err == nil {
		t.Fatal("safe config open accepted a symlink")
	}
}
