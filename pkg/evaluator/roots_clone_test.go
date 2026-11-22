package evaluator

import (
	"crypto/x509"
	"testing"
)

// Each transport gets its own root pool, so adding a certificate to one
// cannot widen trust for other clients in the same process.
func TestNewTransportRootPoolsAreIndependent(t *testing.T) {
	a, b := NewTransport().TLSClientConfig.RootCAs, NewTransport().TLSClientConfig.RootCAs
	if a == nil || b == nil {
		if a != b {
			t.Fatalf("expected both pools nil (platform verifier), got %v and %v", a, b)
		}
		t.Skip("platform verifier in use; no shared pool to mutate")
	}
	if a == b {
		t.Fatal("transports share one *x509.CertPool")
	}
	before := len(b.Subjects()) //nolint:staticcheck // Subjects is fine for a count.
	a.AddCert(&x509.Certificate{Raw: []byte{1}, RawSubject: []byte{0x30, 0}})
	if after := len(b.Subjects()); after != before { //nolint:staticcheck
		t.Fatalf("mutating one transport's pool changed another: %d -> %d", before, after)
	}
}
