package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func issue(t *testing.T, ca *CA, dns []string, eku x509.ExtKeyUsage, nb, na time.Time) *x509.Certificate {
	t.Helper()
	c, _, err := ca.Issue("x", dns, eku, nb, na)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, c)
}

func pool(ca *CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

func newCA(t *testing.T, cn string) *CA {
	t.Helper()
	ca, err := NewCA(cn)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestIssueVerifiesAgainstCA(t *testing.T) {
	ca := newCA(t, "ca")
	now := time.Now()
	leaf := issue(t, ca, nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute), now.Add(time.Hour))
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	// wrong key usage must fail
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err == nil {
		t.Fatal("client cert verified for server auth")
	}
}

func TestRogueDoesNotVerify(t *testing.T) {
	ca, rogue := newCA(t, "ca"), newCA(t, "rogue")
	now := time.Now()
	leaf := issue(t, rogue, nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute), now.Add(time.Hour))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("rogue cert verified")
	}
}

func TestExpiredCert(t *testing.T) {
	ca := newCA(t, "ca")
	now := time.Now()
	leaf := issue(t, ca, nil, x509.ExtKeyUsageClientAuth, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool(ca), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if ie, ok := err.(x509.CertificateInvalidError); !ok || ie.Reason != x509.Expired {
		t.Fatalf("want Expired, got %v", err)
	}
}

func TestServerSAN(t *testing.T) {
	ca := newCA(t, "ca")
	now := time.Now()
	leaf := issue(t, ca, []string{"api.demo"}, x509.ExtKeyUsageServerAuth, now.Add(-time.Minute), now.Add(time.Hour))
	opts := x509.VerifyOptions{Roots: pool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSName: "api.demo"}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatal(err)
	}
	opts.DNSName = "other.demo"
	if _, err := leaf.Verify(opts); err == nil {
		t.Fatal("wrong hostname verified")
	}
}

func TestLoadTLSAndSigningKeys(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, "ca")
	now := time.Now()
	c, k, err := ca.Issue("api.demo", []string{"api.demo"}, x509.ExtKeyUsageServerAuth, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cc, ck, _ := ca.Issue("client-a", nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute), now.Add(time.Hour))
	for n, d := range map[string][]byte{"ca.pem": ca.PEM(), "api.demo.pem": c, "api.demo.key": k, "client-a.pem": cc, "client-a.key": ck} {
		if err := WriteFile(dir, n, d); err != nil {
			t.Fatal(err)
		}
	}
	s, err := LoadServerTLS(dir, "api.demo")
	if err != nil {
		t.Fatal(err)
	}
	if s.ClientAuth != tls.RequireAndVerifyClientCert || s.MinVersion != tls.VersionTLS13 || s.ClientCAs == nil {
		t.Fatalf("bad server config: %+v", s)
	}
	cl, err := LoadClientTLS(dir, "client-a", "api.demo")
	if err != nil {
		t.Fatal(err)
	}
	if cl.ServerName != "api.demo" || cl.RootCAs == nil || len(cl.Certificates) != 1 {
		t.Fatalf("bad client config: %+v", cl)
	}
	sk, pub, err := NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	WriteFile(dir, "signing.key", sk)
	WriteFile(dir, "signing.pub", pub)
	priv, err := LoadSigningKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := LoadSigningPub(dir)
	if err != nil || !priv.PublicKey.Equal(pk) {
		t.Fatalf("signing pair mismatch: %v", err)
	}
}
