package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"testing"
	"time"

	"mtlsdemo/internal/binding"
	"mtlsdemo/internal/jwt"
	"mtlsdemo/internal/pki"
)

func leaf(t *testing.T, ca *pki.CA, cn string, now time.Time) *x509.Certificate {
	t.Helper()
	certPEM, _, err := ca.Issue(cn, nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parsePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestResource(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	a, b := leaf(t, ca, "client-a", now), leaf(t, ca, "client-b", now)
	h := NewHandler(&key.PublicKey, "api.demo", func() time.Time { return now })

	tok := func(signer *ecdsa.PrivateKey, aud string, exp int64, cnf *jwt.Cnf) string {
		s, err := jwt.Sign(jwt.Claims{Iss: "https://auth.demo", Sub: "client-a", Aud: aud, Exp: exp, Cnf: cnf}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	boundA := &jwt.Cnf{X5tS256: binding.Thumbprint(a)}
	good := tok(key, "api.demo", now.Unix()+300, boundA)
	peer := []*x509.Certificate{a}

	tests := []struct {
		name   string
		auth   string
		tls    *tls.ConnectionState
		status int
		reason string // JSON error; "" means success
	}{
		{"ok", "Bearer " + good, &tls.ConnectionState{PeerCertificates: peer}, 200, ""},
		{"thumbprint mismatch", "Bearer " + good, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{b}}, 401, "thumbprint_mismatch"},
		{"cnf nil", "Bearer " + tok(key, "api.demo", now.Unix()+300, nil), &tls.ConnectionState{PeerCertificates: peer}, 401, "no_cnf"},
		{"cnf empty", "Bearer " + tok(key, "api.demo", now.Unix()+300, &jwt.Cnf{}), &tls.ConnectionState{PeerCertificates: peer}, 401, "no_cnf"},
		{"bad signature", "Bearer " + tok(other, "api.demo", now.Unix()+300, boundA), &tls.ConnectionState{PeerCertificates: peer}, 401, "bad_signature"},
		{"expired", "Bearer " + tok(key, "api.demo", now.Unix()-1, boundA), &tls.ConnectionState{PeerCertificates: peer}, 401, "expired"},
		{"bad audience", "Bearer " + tok(key, "other.demo", now.Unix()+300, boundA), &tls.ConnectionState{PeerCertificates: peer}, 401, "bad_audience"},
		{"nil TLS", "Bearer " + good, nil, 401, "no_client_cert"},
		{"empty peer certs", "Bearer " + good, &tls.ConnectionState{}, 401, "no_client_cert"},
		{"missing header", "", &tls.ConnectionState{PeerCertificates: peer}, 401, "malformed"},
		{"basic scheme", "Basic xxx", &tls.ConnectionState{PeerCertificates: peer}, 401, "malformed"},
		{"empty bearer", "Bearer ", &tls.ConnectionState{PeerCertificates: peer}, 401, "malformed"},
		{"garbage bearer", "Bearer garbage", &tls.ConnectionState{PeerCertificates: peer}, 401, "malformed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/data", nil)
			req.TLS = tc.tls
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if body["data"] != "hello client-a" {
					t.Fatalf("body %v", body)
				}
			} else if body["error"] != tc.reason {
				t.Fatalf("error %q, want %q", body["error"], tc.reason)
			}
		})
	}
}

func parsePEM(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	return x509.ParseCertificate(blk.Bytes)
}
