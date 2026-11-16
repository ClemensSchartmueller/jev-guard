//go:build !linux && !freebsd && !darwin && !windows

package config

import "errors"

// trustPinningSupported reports whether this platform can pin a trust record's path without
// a separate, raceable path resolution. Here it cannot, so canonical records never apply
// (fail closed) and config trust proposes exact-spelling records.
const trustPinningSupported = false

var errTrustPinningUnsupported = errors.New("pinned trust lookups are not supported on this platform")

func pinRecordedConfig(string, string, func(string)) (pinnedConfig, error) {
	return pinnedConfig{}, errTrustPinningUnsupported
}

func pinInspectedConfig(string, string, func(string)) (pinnedConfig, error) {
	return pinnedConfig{}, errTrustPinningUnsupported
}
