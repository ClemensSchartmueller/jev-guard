//go:build !windows

package config

import "path/filepath"

// resolveTrustProposalRoot returns the directory config trust proposes for a canonical
// record: dir with every symlink resolved. The pinned lookup of the proposed record then
// verifies that it is reached without a link.
func resolveTrustProposalRoot(dir string) (string, error) {
	return filepath.EvalSymlinks(dir)
}
