// Package binding computes RFC 8705 certificate thumbprints (x5t#S256).
package binding

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
)

// Thumbprint returns base64url (no padding) of SHA-256 over the cert's DER bytes.
func Thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Match reports whether cnf is the thumbprint of cert.
// Constant-time compare so response timing does not leak how many leading characters matched.
func Match(cnf string, cert *x509.Certificate) bool {
	if cnf == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cnf), []byte(Thumbprint(cert))) == 1
}
