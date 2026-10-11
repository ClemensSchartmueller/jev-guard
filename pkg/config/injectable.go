package config

import "jev-guard/pkg/harness"

// LoadConfigForCallWithPaths is LoadConfigForCall with explicit user config and trust registry
// paths. It exists for tests and embedding applications outside this package (for example the
// eval command tests), which must never read the operating system user's configuration.
// Production callers should use LoadConfigForCall.
func LoadConfigForCallWithPaths(call *harness.NormalizedToolCall, userConfigPath, trustRegistryPath string) *Config {
	return loadConfigForCallWithPaths(call, userConfigPath, trustRegistryPath)
}

// InspectProjectConfigWithRegistry is InspectProjectConfig with an explicit trust registry path,
// for tests and embedding applications outside this package. Production callers should use
// InspectProjectConfig.
func InspectProjectConfigWithRegistry(path, trustRegistryPath string) (*ProjectConfigInfo, error) {
	return inspectProjectConfigWithRegistry(path, trustRegistryPath)
}
