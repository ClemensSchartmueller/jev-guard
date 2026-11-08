package config

import (
	"fmt"
	"strings"
	"testing"

	"jev-guard/pkg/harness"
)

// TestAccountProfileLoadersFailFastInTests proves the TestMain guard: every loader
// that resolves the real account profile panics before it can read or write it.
func TestAccountProfileLoadersFailFastInTests(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		call   func()
		caller string
	}{
		"UserConfigPath":       {func() { UserConfigPath() }, "config.TestAccountProfileLoadersFailFastInTests"},
		"TrustRegistryPath":    {func() { TrustRegistryPath() }, "config.TestAccountProfileLoadersFailFastInTests"},
		"LoadConfig":           {func() { LoadConfig(dir) }, "config.LoadConfig"},
		"LoadConfigForCall":    {func() { LoadConfigForCall(&harness.NormalizedToolCall{Cwd: dir}) }, "config.LoadConfigForCall"},
		"InspectProjectConfig": {func() { _, _ = InspectProjectConfig(dir) }, "config.InspectProjectConfig"},
		"EnsureUserConfig":     {func() { _ = EnsureUserConfig() }, "config.EnsureUserConfig"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				message := fmt.Sprint(recover())
				if !strings.Contains(message, "resolved the real account profile in a test") || !strings.Contains(message, tc.caller) {
					t.Fatalf("expected the account profile guard to name %s, got %q", tc.caller, message)
				}
			}()
			tc.call()
		})
	}
}
