package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mtlsdemo/internal/pki"
)

func setup(t *testing.T) (http.Handler, *pki.CA) {
	t.Helper()
	demo, err := pki.NewCA("demo-ca")
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := pki.NewCA("rogue-ca")
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(demo, rogue, time.Now), demo
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func mustEnroll(t *testing.T, h http.Handler, body string) enrollResp {
	t.Helper()
	w := post(h, body)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var e enrollResp
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func leaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func roots(caPEM string) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM([]byte(caPEM))
	return p
}

func TestEnrollClient(t *testing.T) {
	h, _ := setup(t)
	e := mustEnroll(t, h, `{"name":"java-writer","kind":"client"}`)
	c := leaf(t, e.CertPEM)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots(e.CAPEM), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "java-writer" {
		t.Fatalf("CN %q", c.Subject.CommonName)
	}
	b, _ := pem.Decode([]byte(e.KeyPEM))
	if b == nil || b.Type != "PRIVATE KEY" {
		t.Fatalf("key block %v", b)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ec, ok := k.(*ecdsa.PrivateKey); !ok || ec.Curve != elliptic.P256() {
		t.Fatalf("key is not EC P-256: %T", k)
	}
}

func TestEnrollServer(t *testing.T) {
	h, _ := setup(t)
	e := mustEnroll(t, h, `{"name":"api","kind":"server","dns":["api.demo"]}`)
	c := leaf(t, e.CertPEM)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots(e.CAPEM), DNSName: "api.demo", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
}

func TestRogueIssuerFailsAgainstDemoCA(t *testing.T) {
	h, demo := setup(t)
	e := mustEnroll(t, h, `{"name":"evil","kind":"client","issuer":"rogue"}`)
	if e.CAPEM != string(demo.PEM()) {
		t.Fatal("ca_pem is not the demo CA")
	}
	c := leaf(t, e.CertPEM)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots(e.CAPEM), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("rogue cert verified against demo CA")
	}
}

func TestEnrollRejects(t *testing.T) {
	h, _ := setup(t)
	cases := map[string]string{
		"empty name":       `{"name":"","kind":"client"}`,
		"long name":        `{"name":"` + strings.Repeat("a", 64) + `","kind":"client"}`,
		"upper":            `{"name":"UPPER","kind":"client"}`,
		"space":            `{"name":"a b","kind":"client"}`,
		"unknown kind":     `{"name":"a","kind":"admin"}`,
		"unknown issuer":   `{"name":"a","kind":"client","issuer":"other"}`,
		"server no dns":    `{"name":"a","kind":"server"}`,
		"server empty dns": `{"name":"a","kind":"server","dns":[]}`,
		"unknown field":    `{"name":"a","kind":"client","x":1}`,
		"bad json":         `nope`,
		"oversize body":    `{"name":"` + strings.Repeat("a", 5000) + `","kind":"client"}`,
		"wildcard dns":     `{"name":"a","kind":"server","dns":["*.demo"]}`,
		"empty dns entry":  `{"name":"a","kind":"server","dns":[""]}`,
		"bad char dns":     `{"name":"a","kind":"server","dns":["a_b.demo"]}`,
		"11 dns":           `{"name":"a","kind":"server","dns":["` + strings.Repeat(`a.demo","`, 10) + `a.demo"]}`,
	}
	wantErr := map[string]string{
		"oversize body":   "body too large",
		"wildcard dns":    "invalid dns",
		"empty dns entry": "invalid dns",
		"bad char dns":    "invalid dns",
		"11 dns":          "too many dns names",
	}
	for n, body := range cases {
		t.Run(n, func(t *testing.T) {
			w := post(h, body)
			var m map[string]string
			if w.Code != 400 || json.Unmarshal(w.Body.Bytes(), &m) != nil || m["error"] == "" || m["cert_pem"] != "" {
				t.Fatalf("status %d body %s", w.Code, w.Body)
			}
			if want, ok := wantErr[n]; ok && m["error"] != want {
				t.Fatalf("error %q, want %q", m["error"], want)
			}
		})
	}
}

func TestWrongMethod(t *testing.T) {
	h, _ := setup(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll", nil))
	if w.Code != 405 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHealthz(t *testing.T) {
	h, _ := setup(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("status %d body %q", w.Code, w.Body)
	}
}
