package binding

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestThumbprintKnownVector(t *testing.T) {
	cert := selfSigned(t, "client-a")
	sum := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	got := Thumbprint(cert)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(got) != 43 || strings.Contains(got, "=") {
		t.Fatalf("bad format: %q", got)
	}
}

func TestMatch(t *testing.T) {
	a, b := selfSigned(t, "client-a"), selfSigned(t, "client-b")
	if !Match(Thumbprint(a), a) {
		t.Error("own thumbprint should match")
	}
	if Match(Thumbprint(b), a) {
		t.Error("other cert's thumbprint should not match")
	}
	if Match("", a) {
		t.Error("empty cnf should not match")
	}
}
