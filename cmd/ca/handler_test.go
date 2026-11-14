package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mtlsdemo/internal/pki"
)

// testSecret is random per run, so no secret is written in the tests. wrongSecret is never accepted.
var testSecret, wrongSecret = randHex(), randHex()

func randHex() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

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
	secrets := map[string]string{"java-writer": testSecret, "api": testSecret, "evil": testSecret, "a": testSecret}
	return NewHandler(demo, rogue, secrets, time.Now), demo
}

// csrFor returns a CSR PEM signed by key. Its subject is deliberately wrong: the CA must ignore it.
func csrFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// postRaw sends body as is, with the given enroll secret header (omitted when empty).
func postRaw(h http.Handler, body, secret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
	if secret != "" {
		r.Header.Set("X-Enroll-Secret", secret)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// withCSR adds a fresh valid csr_pem to a JSON object body.
func withCSR(t *testing.T, body string) string {
	t.Helper()
	if !strings.HasSuffix(body, "}") {
		return body
	}
	c, _ := json.Marshal(csrFor(t, newKey(t)))
	return body[:len(body)-1] + `,"csr_pem":` + string(c) + "}"
}

// post sends body with a valid CSR and the valid secret.
func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postRaw(h, withCSR(t, body), testSecret)
}

func mustEnroll(t *testing.T, h http.Handler, body string) enrollResp {
	t.Helper()
	w := post(t, h, body)
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
}

func TestCertIsForCSRKeyAndCNComesFromRequest(t *testing.T) {
	h, _ := setup(t)
	key := newKey(t)
	body := `{"name":"java-writer","kind":"client","csr_pem":` + mustJSON(csrFor(t, key)) + `}`
	w := postRaw(h, body, testSecret)
	if w.Code != 200 || strings.Contains(w.Body.String(), "key_pem") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	var e enrollResp
	json.Unmarshal(w.Body.Bytes(), &e)
	c := leaf(t, e.CertPEM)
	if !c.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("cert is not for the CSR key")
	}
	if c.Subject.CommonName != "java-writer" {
		t.Fatalf("CN %q came from the CSR", c.Subject.CommonName)
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestBadCSRRejected(t *testing.T) {
	h, _ := setup(t)
	good := csrFor(t, newKey(t))
	// a CSR whose signature does not match its key: flip a byte in the signature
	b, _ := pem.Decode([]byte(good))
	b.Bytes[len(b.Bytes)-1] ^= 0xff
	tampered := string(pem.EncodeToMemory(b))
	rsaCSR := func() string {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}()
	p384 := func() string {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}()
	for n, csr := range map[string]string{"missing": "", "garbage": "nope", "tampered signature": tampered, "rsa key": rsaCSR, "p384 key": p384} {
		t.Run(n, func(t *testing.T) {
			w := postRaw(h, `{"name":"java-writer","kind":"client","csr_pem":`+mustJSON(csr)+`}`, testSecret)
			if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid csr") {
				t.Fatalf("status %d body %s", w.Code, w.Body)
			}
		})
	}
}

func TestEnrollSecret(t *testing.T) {
	h, _ := setup(t)
	body := withCSR(t, `{"name":"java-writer","kind":"client"}`)
	cases := map[string]struct{ name, secret string }{
		"missing secret": {"java-writer", ""},
		"wrong secret":   {"java-writer", wrongSecret},
		"unknown name":   {"nobody", testSecret},
	}
	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			b := strings.Replace(body, "java-writer", c.name, 1)
			w := postRaw(h, b, c.secret)
			if w.Code != 403 || strings.Contains(w.Body.String(), "cert_pem") {
				t.Fatalf("status %d body %s", w.Code, w.Body)
			}
		})
	}
	if w := postRaw(h, body, testSecret); w.Code != 200 {
		t.Fatalf("right secret: status %d", w.Code)
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
			w := post(t, h, body)
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
