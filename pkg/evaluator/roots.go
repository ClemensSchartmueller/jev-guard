package evaluator

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// trustedSystemRoots deliberately avoids SystemCertPool: on Unix it honors
// SSL_CERT_FILE and SSL_CERT_DIR supplied by the invoking process.
var trustedSystemRoots = sync.OnceValue(readTrustedSystemRoots)

func readTrustedSystemRoots() *x509.CertPool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" || runtime.GOOS == "windows" {
		return nil // Use the native platform verifier.
	}
	var files, dirs []string
	switch runtime.GOOS {
	case "linux", "android":
		files = []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"}
		dirs = []string{"/etc/ssl/certs", "/etc/pki/tls/certs"}
		if runtime.GOOS == "android" {
			dirs = append(dirs, "/system/etc/security/cacerts")
		}
	case "dragonfly", "freebsd", "netbsd", "openbsd":
		files = []string{"/usr/local/etc/ssl/cert.pem", "/etc/ssl/cert.pem", "/usr/local/share/certs/ca-root-nss.crt", "/etc/openssl/certs/ca-certificates.crt"}
		dirs = []string{"/etc/ssl/certs", "/usr/local/share/certs", "/etc/openssl/certs"}
	}
	return loadSystemRoots(files, dirs)
}

// Paths mirror Go's crypto/x509 Linux and BSD defaults. An empty pool fails
// closed when no system certificates are available, rather than falling back
// to environment-selected roots.
func loadSystemRoots(files, dirs []string) *x509.CertPool {
	roots := x509.NewCertPool()
	for _, path := range files {
		if pem, err := os.ReadFile(path); err == nil {
			roots.AppendCertsFromPEM(pem)
			break
		}
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			// Hashed aliases pointing within this directory duplicate certificates.
			if entry.Type()&os.ModeSymlink != 0 {
				if target, err := os.Readlink(path); err == nil && !strings.Contains(target, "/") {
					continue
				}
			}
			if pem, err := os.ReadFile(path); err == nil {
				roots.AppendCertsFromPEM(pem)
			}
		}
	}
	return roots
}
