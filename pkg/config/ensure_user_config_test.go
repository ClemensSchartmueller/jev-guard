package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

func TestEnsureUserConfigCreatesDefaultsAndPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".jevguard", ".jevguard.json")
	if err := ensureUserConfigAt(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := DefaultConfig()
	if got.Mode != want.Mode || got.TimeoutMs != want.TimeoutMs || got.IsFastpathEnabled() != want.IsFastpathEnabled() || got.IsContextAwarenessEnabled() != want.IsContextAwarenessEnabled() {
		t.Fatalf("created config does not match built-in defaults: %+v", got)
	}
	if got.APIKey != "" || got.TypesafeAPIKey != "" {
		t.Fatal("default config must not contain an API key")
	}
	if !reflect.DeepEqual(got.SensitiveFiles, want.SensitiveFiles) || !reflect.DeepEqual(got.TrustedCommands, want.TrustedCommands) {
		t.Fatal("created config omitted built-in policy entries")
	}
	if err := ensureUserConfigAt(path); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("existing config changed: %v", err)
	}
	if info, err := os.Stat(path); runtime.GOOS != "windows" && (err != nil || info.Mode().Perm()&0077 != 0) {
		t.Fatalf("user config permissions are too broad: %v %v", info, err)
	}
}

func TestEnsureUserConfigConcurrentFirstLaunch(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".jevguard", ".jevguard.json")
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- ensureUserConfigAt(path)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent launch failed: %v", err)
		}
	}
	if err := validateExistingUserConfig(path); err != nil {
		t.Fatalf("concurrent launch left invalid config: %v", err)
	}
}

func TestEnsureUserConfigRejectsInvalidAndNonregularExistingPaths(t *testing.T) {
	for _, kind := range []string{"invalid JSON", "invalid field type", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, ".jevguard")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".jevguard.json")
			switch kind {
			case "invalid JSON":
				if err := os.WriteFile(path, []byte("{invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid field type":
				if err := os.WriteFile(path, []byte(`{"mode":123}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(root, "target")
				if err := os.WriteFile(target, []byte(`{"mode":"audit"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			if err := ensureUserConfigAt(path); err == nil {
				t.Fatal("expected startup error for unsafe existing config")
			}
			if kind == "invalid JSON" {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "{invalid" {
					t.Fatalf("invalid existing config was changed: %q %v", data, err)
				}
			}
		})
	}
}
