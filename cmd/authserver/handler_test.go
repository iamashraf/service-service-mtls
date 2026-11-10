package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mtlsdemo/internal/binding"
	"mtlsdemo/internal/jwt"
	"mtlsdemo/internal/pki"
)

func TestTokenBoundToClientCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1_700_000_000, 0)
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Issue("client-a", nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])

	srv := httptest.NewUnstartedServer(NewHandler(key, func() time.Time { return now }))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true, // test server uses httptest's own cert
	}}}

	resp, err := client.Post(srv.URL+"/token", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.TokenType != "Bearer" || body.ExpiresIn != 300 {
		t.Fatalf("body %+v", body)
	}
	c, err := jwt.Verify(body.AccessToken, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Cnf == nil || c.Cnf.X5tS256 != binding.Thumbprint(leaf) {
		t.Fatalf("cnf %+v", c.Cnf)
	}
	if c.Sub != "client-a" || c.Aud != "api.demo" || c.Iss != "https://auth.demo" || c.Exp != now.Unix()+300 {
		t.Fatalf("claims %+v", c)
	}
}

func TestTokenNoPeerCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := NewHandler(key, time.Now)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/token", nil))
	if rec.Code != 401 || rec.Body.String() != `{"error":"no_client_cert"}`+"\n" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestTokenWrongMethod(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rec := httptest.NewRecorder()
	NewHandler(key, time.Now).ServeHTTP(rec, httptest.NewRequest("GET", "/token", nil))
	if rec.Code != 405 {
		t.Fatalf("got %d", rec.Code)
	}
}
